pub mod err;
pub mod middleware;
pub mod turnstile;

#[cfg(feature = "template")]
pub mod router;
pub mod signal;

use anyhow::anyhow;
use axum::body::{Body, StreamBody};
use axum::headers::authorization::Bearer;
use axum::headers::Authorization;
use axum::http::Response;
use axum::response::IntoResponse;
use axum::routing::{any, get, post};
use axum::{Json, TypedHeader};
use axum_server::{AddrIncomingConfig, Handle};

use axum::http::header;
use axum::http::method::Method;
use axum::http::uri::Uri;
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::{cookie, CookieJar};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::HttpConfig;
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use std::net::SocketAddr;

use crate::arkose::Type;
use crate::auth::model::{AccessToken, AuthAccount, RefreshToken, SessionAccessToken};
use crate::auth::provide::AuthProvider;
use crate::auth::API_AUTH_SESSION_COOKIE_KEY;
use crate::context::{self, ContextArgs};
use crate::serve::middleware::tokenbucket::TokenBucketLimitContext;
use crate::serve::router::toapi::chat_to_api;
use crate::{arkose, debug, info, warn, HOST_CHATGPT, ORIGIN_CHATGPT};

use crate::serve::err::ResponseError;
use crate::{HEADER_UA, URL_CHATGPT_API, URL_PLATFORM_API};

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

        context::init(self.inner.clone());

        let global_layer = tower::ServiceBuilder::new()
            .layer(tower_http::trace::TraceLayer::new_for_http())
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
            )));

        let app_layer = {
            let limit_context = TokenBucketLimitContext::from((
                self.inner.tb_store_strategy.clone(),
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
            .enable_all()
            .worker_threads(self.inner.workers)
            .build()?;

        runtime.block_on(async {
            tokio::spawn(check_wan_address());

            let router = axum::Router::new()
                // official dashboard api endpoint
                .route("/dashboard/*path", any(official_proxy))
                // official v1 api endpoint
                .route("/v1/*path", any(official_proxy))
                // unofficial backend api endpoint
                .route("/backend-api/*path", any(unofficial_proxy))
                // unofficial api to official api
                .route("/to/v1/chat/completions", post(chat_to_api))
                .route_layer(app_layer)
                // unofficial public api endpoint
                .route("/public-api/*path", any(unofficial_proxy))
                .route("/auth/token", post(post_access_token))
                .route("/auth/refresh_token", post(post_refresh_token))
                .route("/auth/revoke_token", post(post_revoke_token))
                .route("/api/auth/session", get(get_session));

            let router = router::config(router, &self.inner).layer(global_layer);

            let handle = Handle::new();

            // Spawn a task to gracefully shutdown server.
            tokio::spawn(signal::graceful_shutdown(handle.clone()));

            match (self.inner.tls_cert, self.inner.tls_key) {
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
                        .expect("openai server failed")
                }
                _ => axum_server::bind(self.inner.bind.unwrap())
                    .handle(handle)
                    .addr_incoming_config(incoming_config)
                    .http_config(http_config)
                    .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                    .await
                    .expect("openai server failed"),
            }
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
/// GET https://api.openai.com/v1/models
/// GET https://api.openai.com/v1/models/{model}
/// POST https://api.openai.com/v1/chat/completions
/// POST https://api.openai.com/v1/completions
/// POST https://api.openai.com/v1/edits
/// POST https://api.openai.com/v1/images/generations
/// POST https://api.openai.com/v1/images/edits
/// POST https://api.openai.com/v1/images/variations
/// POST https://api.openai.com/v1/embeddings
/// POST https://api.openai.com/v1/audio/transcriptions
/// POST https://api.openai.com/v1/audio/translations
/// GET https://api.openai.com/v1/files
/// POST https://api.openai.com/v1/files
/// DELETE https://api.openai.com/v1/files/{file_id}
/// GET https://api.openai.com/v1/files/{file_id}
/// GET https://api.openai.com/v1/files/{file_id}/content
/// POST https://api.openai.com/v1/fine-tunes
/// GET https://api.openai.com/v1/fine-tunes
/// GET https://api.openai.com/v1/fine-tunes/{fine_tune_id}
/// POST https://api.openai.com/v1/fine-tunes/{fine_tune_id}/cancel
/// GET https://api.openai.com/v1/fine-tunes/{fine_tune_id}/events
/// DELETE https://api.openai.com/v1/models/{model}
/// POST https://api.openai.com/v1/moderations
/// Deprecated GET https://api.openai.com/v1/engines
/// Deprecated GET https://api.openai.com/v1/engines/{engine_id}
async fn official_proxy(
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    jar: CookieJar,
    mut body: Option<Json<Value>>,
) -> Result<impl IntoResponse, ResponseError> {
    let path_and_query = uri
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or(uri.path());
    let url = format!("{URL_CHATGPT_API}{path_and_query}");

    handle_dashboard_body(&url, &method, &mut body).await?;

    let builder = context::get_instance()
        .client()
        .request(method, &url)
        .headers(header_convert(&headers, &jar).await?);
    let resp = match body {
        Some(body) => builder.json(&body.0).send().await,
        None => builder.send().await,
    };
    response_convert(resp)
}

/// reference: doc/http.rest
/// GET http://{{host}}/backend-api/models?history_and_training_disabled=false
/// GET http://{{host}}/backend-api/accounts/check
/// GET http://{{host}}/backend-api/accounts/check/v4-2023-04-27
/// GET http://{{host}}/backend-api/settings/beta_features
/// GET http://{{host}}/backend-api/conversation/{conversation_id}
/// GET http://{{host}}/backend-api/conversations?offset=0&limit=3&order=updated
/// GET http://{{host}}/public-api/conversation_limit
/// POST http://{{host}}/backend-api/conversation
/// PATCH http://{{host}}/backend-api/conversation/{conversation_id}
/// POST http://{{host}}/backend-api/conversation/gen_title/{conversation_id}
/// PATCH http://{{host}}/backend-api/conversation/{conversation_id}
/// PATCH http://{{host}}/backend-api/conversations
/// POST http://{{host}}/backend-api/conversation/message_feedback
async fn unofficial_proxy(
    uri: Uri,
    method: Method,
    mut headers: HeaderMap,
    jar: CookieJar,
    mut body: Option<Json<Value>>,
) -> Result<impl IntoResponse, ResponseError> {
    let path_and_query = uri
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or(uri.path());
    let url = format!("{URL_PLATFORM_API}{path_and_query}");

    handle_body(&url, &method, &mut headers, &mut body).await?;

    let builder = context::get_instance()
        .client()
        .request(method, url)
        .headers(header_convert(&headers, &jar).await?);
    let resp = match body {
        Some(body) => builder.json(&body.0).send().await,
        None => builder.send().await,
    };
    response_convert(resp)
}
pub(super) async fn header_convert(
    headers: &HeaderMap,
    jar: &CookieJar,
) -> Result<HeaderMap, ResponseError> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .ok_or(ResponseError::Unauthorized(anyhow!(
            "AccessToken required!"
        )))?;

    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, authorization.clone());
    headers.insert(header::HOST, HeaderValue::from_static(HOST_CHATGPT));
    headers.insert(header::ORIGIN, HeaderValue::from_static(ORIGIN_CHATGPT));
    headers.insert(header::USER_AGENT, HeaderValue::from_static(HEADER_UA));
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(
        "sec-ch-ua",
        HeaderValue::from_static(
            r#""Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"#,
        ),
    );
    headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    headers.insert("sec-ch-ua-platform", HeaderValue::from_static("Linux"));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("empty"));
    headers.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
    headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
    headers.insert("sec-gpc", HeaderValue::from_static("1"));
    headers.insert("Pragma", HeaderValue::from_static("no-cache"));
    headers.remove(header::CONNECTION);

    let mut cookie = String::new();

    if let Some(puid) = headers.get("PUID") {
        let puid = puid.to_str()?;
        cookie.push_str(&format!("_puid={puid};"))
    }

    if let Some(cookier) = jar.get("_puid") {
        let c = &format!("_puid={};", puid_cookie_encoded(cookier.value()));
        cookie.push_str(c);
        debug!("request cookie `puid`: {}", c);
    }

    // setting cookie
    if !cookie.is_empty() {
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(cookie.as_str()).expect("setting cookie error"),
        );
    }
    Ok(headers)
}

fn response_convert(
    res: Result<reqwest::Response, reqwest::Error>,
) -> Result<impl IntoResponse, ResponseError> {
    let resp = res.map_err(ResponseError::InternalServerError)?;
    let mut builder = Response::builder().status(resp.status());
    for kv in resp.headers().into_iter().filter(|(k, _v)| {
        let name = k.as_str().to_lowercase();
        name.ne("__cf_bm") || name.ne("__cfduid") || name.ne("_cfuvid") || name.ne("set-cookie")
    }) {
        builder = builder.header(kv.0, kv.1);
    }

    for c in resp.cookies().into_iter().filter(|c| {
        let key = c.name();
        key.eq("_puid") || key.eq("_account")
    }) {
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

async fn handle_dashboard_body(
    url: &str,
    method: &Method,
    body: &mut Option<Json<Value>>,
) -> Result<(), ResponseError> {
    if !url.contains("/dashboard/user/api_keys") || !method.eq("POST") {
        return Ok(());
    }

    let body = match body.as_mut().and_then(|b| b.as_object_mut()) {
        Some(body) => body,
        None => return Ok(()),
    };

    if body.get("arkose_token").is_none() {
        let arkose_token = arkose::ArkoseToken::new_from_context(Type::Platform).await?;
        body.insert("arkose_token".to_owned(), json!(arkose_token));
    }

    Ok(())
}

async fn handle_body(
    url: &str,
    method: &Method,
    headers: &mut HeaderMap,
    body: &mut Option<Json<Value>>,
) -> Result<(), ResponseError> {
    if !url.contains("/backend-api/conversation") || !method.eq("POST") {
        return Ok(());
    }

    let body = match body.as_mut().and_then(|b| b.as_object_mut()) {
        Some(body) => body,
        None => return Ok(()),
    };

    let model = match body.get("model").and_then(|m| m.as_str()) {
        Some(model) => model,
        None => return Ok(()),
    };

    match arkose::GPTModel::from_str(model) {
        Ok(model) => {
            let condition = match body.get("arkose_token") {
                Some(s) => {
                    let s = s.as_str().unwrap_or(EMPTY);
                    s.is_empty() || s.eq("null")
                }
                None => true,
            };

            if condition {
                let arkose_token = arkose::ArkoseToken::new_from_context(model.into()).await?;
                body.insert("arkose_token".to_owned(), json!(arkose_token));
            }
        }
        Err(err) => {
            return Err(ResponseError::BadRequest(anyhow!(
                "GPTModel parse error: {}",
                err
            )))
        }
    }

    let authorization = headers
        .get(header::AUTHORIZATION)
        .ok_or(ResponseError::Unauthorized(anyhow!(
            "AccessToken required!"
        )))?;

    if !has_puid(headers)? {
        let resp = context::get_instance()
            .client()
            .get(format!("{URL_CHATGPT_API}/backend-api/models"))
            .header(header::AUTHORIZATION, authorization)
            .send()
            .await
            .map_err(ResponseError::InternalServerError)?;
        match resp.error_for_status() {
            Ok(resp) => {
                if let Some(puid_cookie) = resp.cookies().into_iter().find(|s| s.name().eq("_puid"))
                {
                    headers.insert(
                        header::COOKIE,
                        HeaderValue::from_str(&format!("_puid={};", puid_cookie.value()))
                            .map_err(ResponseError::BadRequest)?,
                    );
                }
            }
            Err(err) => return Err(ResponseError::InternalServerError(err)),
        }
    }

    Ok(())
}

fn puid_cookie_encoded(input: &str) -> String {
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

pub(super) fn has_puid(headers: &HeaderMap) -> Result<bool, ResponseError> {
    let res = match headers.get(header::COOKIE) {
        Some(hv) => hv
            .to_str()
            .map_err(ResponseError::BadRequest)?
            .contains("_puid"),
        None => false,
    };
    Ok(res)
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
