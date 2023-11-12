mod error;
mod extract;
mod middleware;
#[cfg(feature = "preauth")]
pub mod preauth;
mod puid;
#[cfg(feature = "template")]
mod route;
mod signal;
mod turnstile;

use anyhow::anyhow;
use axum::body::{Body, StreamBody};
use axum::headers::authorization::Bearer;
use axum::headers::Authorization;
use axum::http::Response;
use axum::response::IntoResponse;
use axum::routing::{any, get, post};
use axum::{Json, TypedHeader};
use axum_server::{AddrIncomingConfig, Handle};

use self::extract::SendRequestExt;
use crate::auth::model::{AccessToken, AuthAccount, RefreshToken, SessionAccessToken};
use crate::auth::provide::AuthProvider;
use crate::auth::API_AUTH_SESSION_COOKIE_KEY;
use crate::context::{self, ContextArgs};
use crate::serve::error::ResponseError;
use crate::serve::middleware::tokenbucket::{Strategy, TokenBucketLimitContext};
use crate::{debug, info, warn};
use crate::{URL_CHATGPT_API, URL_PLATFORM_API};
use axum::http::header;
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::{cookie, CookieJar};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::HttpConfig;
use reqwest::header::HeaderMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower_http::trace;
use tracing::Level;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const EMPTY: &str = "";

pub struct Launcher {
    inner: ContextArgs,
}

impl Launcher {
    pub fn new(inner: ContextArgs) -> Self {
        Self { inner }
    }

    pub fn run(self) -> anyhow::Result<()> {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "RUST_LOG=warn".into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();

        info!(
            "Starting HTTP(S) server at http(s)://{:?}",
            self.inner.bind.expect("bind address required")
        );
        info!("Starting {} workers", self.inner.workers);
        info!("Concurrent limit {}", self.inner.concurrent_limit);
        info!("Enabled cookie store: {}", self.inner.cookie_store);

        if let Some((ref ipv6, len)) = self.inner.ipv6_subnet {
            info!("Ipv6 subnet: {ipv6}/{len}");
        } else {
            info!("Keepalive {} seconds", self.inner.tcp_keepalive);
            info!("Timeout {} seconds", self.inner.timeout);
            info!("Connect timeout {} seconds", self.inner.connect_timeout);
            if self.inner.disable_direct {
                info!("Disable direct connection");
            }
        }

        self.inner.arkose_solver.as_ref().map(|solver| {
            info!("ArkoseLabs solver: {:?}", solver.solver);
        });

        self.inner
            .interface
            .as_ref()
            .map(|i| info!("Bind address: {i} for outgoing connection"));

        // init context
        context::init(self.inner.clone());

        let global_layer = tower::ServiceBuilder::new()
            .layer(
                tower_http::trace::TraceLayer::new_for_http()
                    .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                    .on_response(trace::DefaultOnResponse::new().level(Level::INFO))
                    .on_request(trace::DefaultOnRequest::new().level(Level::INFO))
                    .on_failure(trace::DefaultOnFailure::new().level(Level::WARN)),
            )
            .layer(tower::limit::ConcurrencyLimitLayer::new(
                self.inner.concurrent_limit,
            ))
            .layer(
                tower_http::cors::CorsLayer::new()
                    .allow_credentials(true)
                    .allow_headers(tower_http::cors::AllowHeaders::mirror_request())
                    .allow_methods(tower_http::cors::AllowMethods::mirror_request())
                    .allow_origin(tower_http::cors::AllowOrigin::mirror_request()),
            )
            .layer(axum::error_handling::HandleErrorLayer::new(
                |_: axum::BoxError| async { axum::http::StatusCode::REQUEST_TIMEOUT },
            ))
            .layer(tower::timeout::TimeoutLayer::new(Duration::from_secs(
                self.inner.timeout as u64,
            )))
            .layer(axum::extract::DefaultBodyLimit::max(200 * 1024 * 1024));

        let app_layer = {
            let limit_context = TokenBucketLimitContext::from((
                Strategy::from_str(self.inner.tb_store_strategy.as_str())?,
                self.inner.tb_enable,
                self.inner.tb_capacity,
                self.inner.tb_fill_rate,
                self.inner.tb_expired,
                self.inner.tb_redis_url.clone(),
            ));

            tower::ServiceBuilder::new()
                .layer(axum::middleware::from_fn(
                    middleware::token_authorization_middleware,
                ))
                .layer(axum::middleware::from_fn_with_state(
                    Arc::new(limit_context),
                    middleware::token_bucket_limit_middleware,
                ))
        };

        let router = axum::Router::new()
            // official dashboard api endpoint
            .route("/dashboard/*path", any(official_proxy))
            // official v1 api endpoint
            .route("/v1/*path", any(official_proxy))
            // unofficial backend api endpoint
            .route("/backend-api/*path", any(unofficial_proxy))
            .route_layer(app_layer)
            // unofficial public api endpoint
            .route("/public-api/*path", any(unofficial_proxy))
            .route("/auth/token", post(post_access_token))
            .route("/auth/refresh_token", post(post_refresh_token))
            .route("/auth/revoke_token", post(post_revoke_token))
            .route("/api/auth/session", get(get_session));

        let router = route::config(router, &self.inner).layer(global_layer);

        let http_config = HttpConfig::new()
            .http1_keep_alive(true)
            .http1_header_read_timeout(Duration::from_secs(self.inner.tcp_keepalive as u64))
            .http2_keep_alive_timeout(Duration::from_secs(self.inner.tcp_keepalive as u64))
            .http2_keep_alive_interval(Some(Duration::from_secs(self.inner.tcp_keepalive as u64)))
            .build();

        let incoming_config = AddrIncomingConfig::new()
            .tcp_sleep_on_accept_errors(true)
            .tcp_keepalive_interval(Some(Duration::from_secs(self.inner.tcp_keepalive as u64)))
            .tcp_keepalive(Some(Duration::from_secs(self.inner.tcp_keepalive as u64)))
            .build();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_io()
            .enable_time()
            .worker_threads(self.inner.workers)
            .build()?;

        runtime.block_on(async move {
            let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);
            // PreAuth mitm proxy
            #[cfg(feature = "preauth")]
            if let Some(pbind) = self.inner.pbind.clone() {
                if let Some(err) = preauth::mitm_proxy(
                    pbind,
                    self.inner.pupstream.clone(),
                    self.inner.pcert.clone(),
                    self.inner.pkey.clone(),
                    rx,
                )
                .await
                .err()
                {
                    crate::error!("PreAuth proxy error: {}", err);
                }
            }

            // Signal the server to shutdown using Handle.
            let handle = Handle::new();

            // Spawn a task to gracefully shutdown server.
            tokio::spawn(signal::graceful_shutdown(handle.clone()));

            // Spawn a task to check wan address.
            tokio::spawn(check_wan_address());

            let result = match (self.inner.tls_cert, self.inner.tls_key) {
                (Some(cert), Some(key)) => {
                    let tls_config = RustlsConfig::from_pem_file(cert, key)
                        .await
                        .expect("Failed to load TLS keypair");

                    axum_server::bind_rustls(self.inner.bind.unwrap(), tls_config)
                        .handle(handle)
                        .addr_incoming_config(incoming_config)
                        .http_config(http_config)
                        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                        .await
                }
                _ => {
                    axum_server::bind(self.inner.bind.unwrap())
                        .handle(handle)
                        .addr_incoming_config(incoming_config)
                        .http_config(http_config)
                        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                        .await
                }
            };

            if let Some(err) = result.err() {
                warn!("Http Server error: {}", err);
            }

            if let Some(err) = tx.send(()).await.err() {
                warn!("Send shutdown signal error: {}", err);
            }

            tokio::time::sleep(Duration::from_secs(3)).await;
        });

        Ok(())
    }
}

/// GET /api/auth/session
async fn get_session(jar: CookieJar) -> Result<impl IntoResponse, ResponseError> {
    match jar.get(API_AUTH_SESSION_COOKIE_KEY) {
        Some(session) => {
            let session_token = context::get_instance()
                .auth_client()
                .do_session(session.value())
                .await
                .map_err(ResponseError::BadRequest)?;

            let resp: Response<Body> = session_token.try_into()?;
            Ok(resp.into_response())
        }
        None => Err(ResponseError::Unauthorized(anyhow!(
            "Session: {API_AUTH_SESSION_COOKIE_KEY} required!"
        ))),
    }
}

/// POST /auth/token
async fn post_access_token(
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    mut account: axum::Form<AuthAccount>,
) -> Result<impl IntoResponse, ResponseError> {
    if let Some(key) = context::get_instance().auth_key() {
        let bearer = bearer.ok_or(ResponseError::Unauthorized(anyhow!(
            "Login Authentication Key required!"
        )))?;
        if bearer.token().ne(key) {
            return Err(ResponseError::Unauthorized(anyhow!(
                "Authentication Key error!"
            )));
        }
    }

    match try_login(&mut account).await? {
        AccessToken::Session(session_token) => {
            let resp: Response<Body> = session_token.try_into()?;
            Ok(resp.into_response())
        }
        AccessToken::OAuth(c) => Ok(Json(AccessToken::OAuth(c)).into_response()),
    }
}

/// POST /auth/refresh_token
async fn post_refresh_token(
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<RefreshToken>, ResponseError> {
    let ctx = context::get_instance();
    match ctx.auth_client().do_refresh_token(bearer.token()).await {
        Ok(refresh_token) => Ok(Json(refresh_token)),
        Err(err) => Err(ResponseError::BadRequest(err)),
    }
}

/// POST /auth/revoke_token
async fn post_revoke_token(
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
) -> Result<axum::http::StatusCode, ResponseError> {
    let ctx = context::get_instance();
    match ctx.auth_client().do_revoke_token(bearer.token()).await {
        Ok(_) => Ok(axum::http::StatusCode::OK),
        Err(err) => Err(ResponseError::BadRequest(err)),
    }
}

/// match path /dashboard/{tail.*}
/// POST https://api.openai.com/dashboard/onboarding/login"
/// POST https://api.openai.com/dashboard/user/api_keys
/// GET https://api.openai.com/dashboard/user/api_keys
/// POST https://api.openai.com/dashboard/billing/usage
/// POST https://api.openai.com/dashboard/billing/credit_grants
///
/// platform API match path /v1/{tail.*}
/// reference: https://platform.openai.com/docs/api-reference
async fn official_proxy(
    req: extract::RequestExtractor,
) -> Result<impl IntoResponse, ResponseError> {
    let resp = context::get_instance()
        .client()
        .send_request(URL_PLATFORM_API, req)
        .await?;
    response_convert(resp)
}

/// reference: doc/http.rest
async fn unofficial_proxy(
    req: extract::RequestExtractor,
) -> Result<impl IntoResponse, ResponseError> {
    let resp = context::get_instance()
        .client()
        .send_request(URL_CHATGPT_API, req)
        .await?;
    response_convert(resp)
}

/// Request headers convert
fn header_convert(
    h: &HeaderMap,
    jar: &CookieJar,
    origin: &'static str,
) -> Result<HeaderMap, ResponseError> {
    let authorization = match h.get(header::AUTHORIZATION) {
        Some(v) => Some(v),
        // support Pandora WebUI passing X-Authorization header
        None => h.get("X-Authorization"),
    };

    let mut headers = HeaderMap::new();
    if let Some(h) = authorization {
        headers.insert(header::AUTHORIZATION, h.clone());
    }
    if let Some(content_type) = h.get(header::CONTENT_TYPE) {
        headers.insert(header::CONTENT_TYPE, content_type.clone());
    }
    headers.insert(header::REFERER, header::HeaderValue::from_static(origin));
    headers.insert(header::REFERER, header::HeaderValue::from_static(origin));

    let mut cookies = Vec::new();

    jar.iter()
        .filter(|c| {
            let name = c.name().to_lowercase();
            name.eq("_puid") || name.eq("cf_clearance")
        })
        .for_each(|c| {
            let c = format!("{}={}", c.name(), cookie_encoded(c.value()));
            debug!("cookie: {}", c);
            cookies.push(c);
        });

    // setting cookie
    if !cookies.is_empty() {
        headers.insert(
            header::COOKIE,
            header::HeaderValue::from_str(&cookies.join(";")).expect("setting cookie error"),
        );
    }
    Ok(headers)
}

/// Response convert
fn response_convert(resp: reqwest::Response) -> Result<impl IntoResponse, ResponseError> {
    let mut builder = Response::builder().status(resp.status());
    for kv in resp
        .headers()
        .into_iter()
        .filter(|(k, _)| k.as_str().to_lowercase().ne("set-cookie"))
    {
        builder = builder.header(kv.0, kv.1);
    }

    for c in resp
        .cookies()
        .filter(|c| {
            let name = c.name().to_lowercase();
            name.eq("_puid") || name.eq("cf_clearance")
        })
        .into_iter()
    {
        if let Some(expires) = c.expires() {
            let timestamp_secs = expires
                .duration_since(UNIX_EPOCH)
                .expect("Failed to get timestamp")
                .as_secs_f64();
            let cookie = Cookie::build(c.name(), c.value())
                .path("/")
                .max_age(time::Duration::seconds_f64(timestamp_secs))
                .same_site(cookie::SameSite::Lax)
                .secure(false)
                .http_only(false)
                .finish();
            builder = builder.header(axum::http::header::SET_COOKIE, cookie.to_string());
        }
    }
    Ok(builder
        .body(StreamBody::new(resp.bytes_stream()))
        .map_err(ResponseError::InternalServerError)?)
}

pub(crate) async fn try_login(account: &axum::Form<AuthAccount>) -> anyhow::Result<AccessToken> {
    let ctx = context::get_instance();
    ctx.auth_client().do_access_token(&account).await
}

fn cookie_encoded(input: &str) -> String {
    let separator = ':';
    if let Some((name, value)) = input.split_once(separator) {
        let encoded_value = value
            .chars()
            .map(|ch| match ch {
                '!' | '#' | '$' | '%' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | '/' | ':'
                | ';' | '=' | '?' | '@' | '[' | ']' | '~' => {
                    format!("%{:02X}", ch as u8)
                }
                _ => ch.to_string(),
            })
            .collect::<String>();

        format!("{name}:{encoded_value}")
    } else {
        input.to_string()
    }
}

impl TryInto<Response<Body>> for SessionAccessToken {
    type Error = ResponseError;

    fn try_into(self) -> Result<Response<Body>, Self::Error> {
        let s = self
            .session
            .clone()
            .ok_or(ResponseError::InternalServerError(anyhow!(
                "Session error!"
            )))?;

        let timestamp_secs = s
            .expires
            .unwrap_or_else(|| SystemTime::now())
            .duration_since(UNIX_EPOCH)
            .expect("Failed to get timestamp")
            .as_secs_f64();

        let cookie = cookie::Cookie::build(API_AUTH_SESSION_COOKIE_KEY, s.value)
            .path("/")
            .expires(time::OffsetDateTime::from_unix_timestamp(
                timestamp_secs as i64,
            )?)
            .same_site(cookie::SameSite::Lax)
            .secure(true)
            .http_only(false)
            .finish();

        Ok(Response::builder()
            .status(axum::http::StatusCode::OK)
            .header(header::SET_COOKIE, cookie.to_string())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_string(&self)?))
            .map_err(ResponseError::InternalServerError)?)
    }
}

async fn check_wan_address() {
    match context::get_instance()
        .client()
        .get("https://ifconfig.me")
        .timeout(Duration::from_secs(70))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
    {
        Ok(resp) => match resp.text().await {
            Ok(res) => {
                info!("What is my IP address: {}", res.trim())
            }
            Err(err) => {
                warn!("Check IP address error: {}", err.to_string())
            }
        },
        Err(err) => {
            warn!("Check IP request error: {}", err)
        }
    }
}
