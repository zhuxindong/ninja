pub mod middleware;
#[cfg(feature = "sign")]
pub mod sign;
#[cfg(feature = "limit")]
pub mod tokenbucket;

#[cfg(feature = "template")]
pub mod ui;

pub mod err;

pub mod load_balancer;

use axum::body::StreamBody;
use axum::http::Response;
use axum::routing::{any, get, post};
use axum::Json;

use axum::http::header;
use axum::http::method::Method;
use axum::http::uri::Uri;
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::{cookie, CookieJar};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::HttpConfig;
use derive_builder::Builder;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::{Arc, Once};
use std::time::{Duration, UNIX_EPOCH};
use tokio::runtime::Builder;
use tower_http::cors;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use crate::arkose::ArkoseToken;
use crate::auth::model::{AccessToken, AuthAccount, RefreshToken};
use crate::auth::{AuthClient, AuthHandle};
use crate::serve::tokenbucket::TokenBucketLimitContext;
use crate::serve::ui::TemplateData;
use crate::{debug, info, warn, HOST_CHATGPT, ORIGIN_CHATGPT};

use crate::serve::err::ResponseError;
use crate::{HEADER_UA, URL_CHATGPT_API, URL_PLATFORM_API};

const EMPTY: &str = "";
static INIT: Once = Once::new();

static mut API_CLIENT: Option<load_balancer::ClientLoadBalancer<Client>> = None;
static mut AUTH_CLIENT: Option<load_balancer::ClientLoadBalancer<AuthClient>> = None;

pub(super) fn api_client() -> Client {
    if let Some(lb) = unsafe { &API_CLIENT } {
        return lb.next().clone();
    }
    panic!("The requesting client must be initialized")
}

pub(super) fn auth_client() -> AuthClient {
    if let Some(lb) = unsafe { &AUTH_CLIENT } {
        return lb.next().clone();
    }
    panic!("The requesting oauth client must be initialized")
}

#[derive(Builder, Clone)]
pub struct Launcher {
    /// Listen addres
    host: IpAddr,
    /// Listen port
    port: u16,
    /// Machine worker pool
    workers: usize,
    /// Concurrent limit (Enforces a limit on the concurrent number of requests the underlying)
    concurrent_limit: usize,
    /// Server proxies
    proxies: Vec<String>,
    /// TCP keepalive (second)
    tcp_keepalive: usize,
    /// Client timeout
    timeout: usize,
    /// Client connect timeout
    connect_timeout: usize,
    /// TLS keypair
    tls_keypair: Option<(PathBuf, PathBuf)>,
    /// Web UI api prefix
    api_prefix: Option<String>,
    /// Enable url signature (signature secret key)
    #[cfg(feature = "sign")]
    sign_secret_key: Option<String>,
    /// Enable Tokenbucket
    #[cfg(feature = "limit")]
    tb_enable: bool,
    /// Tokenbucket store strategy
    #[cfg(feature = "limit")]
    tb_store_strategy: tokenbucket::Strategy,
    /// Tokenbucket redis url
    tb_redis_url: Vec<String>,
    /// Tokenbucket capacity
    #[cfg(feature = "limit")]
    tb_capacity: u32,
    /// Tokenbucket fill rate
    #[cfg(feature = "limit")]
    tb_fill_rate: u32,
    /// Tokenbucket expired (second)
    #[cfg(feature = "limit")]
    tb_expired: u32,
    /// Cloudflare turnstile captcha site key
    cf_site_key: Option<String>,
    /// Cloudflare turnstile captcha secret key
    cf_secret_key: Option<String>,
    /// Disable web ui
    disable_ui: bool,
}

impl Launcher {
    pub fn run(self) -> anyhow::Result<()> {
        INIT.call_once(|| unsafe {
            API_CLIENT = Some(
                load_balancer::ClientLoadBalancer::<Client>::new_api_client(&self)
                    .expect("Failed to initialize the requesting client"),
            );
            AUTH_CLIENT = Some(
                load_balancer::ClientLoadBalancer::<AuthClient>::new_auth_client(&self)
                    .expect("Failed to initialize the requesting oauth client"),
            );

            ui::DISABLE_UI = self.disable_ui;
            ui::TEMPLATE_DATA = Some(TemplateData::from(self.clone()));
        });

        let global_layer = tower::ServiceBuilder::new()
            .layer(tower_http::trace::TraceLayer::new_for_http())
            .layer(tower::limit::ConcurrencyLimitLayer::new(
                self.concurrent_limit,
            ))
            .layer(
                tower_http::cors::CorsLayer::new()
                    .max_age(Duration::from_secs(3600))
                    .allow_origin(cors::AllowOrigin::any())
                    .allow_headers(cors::AllowHeaders::any())
                    .allow_methods(cors::AllowMethods::any()),
            )
            .layer(axum::error_handling::HandleErrorLayer::new(
                |_: axum::BoxError| async { axum::http::StatusCode::REQUEST_TIMEOUT },
            ))
            .layer(tower::timeout::TimeoutLayer::new(Duration::from_secs(
                self.timeout as u64,
            )));

        let http_config = HttpConfig::new()
            .http1_keep_alive(true)
            .http1_header_read_timeout(Duration::from_secs(self.tcp_keepalive as u64))
            .http2_keep_alive_timeout(Duration::from_secs(self.tcp_keepalive as u64))
            .http1_only(false)
            .http2_only(false)
            .build();

        let tokio_runtime = Builder::new_multi_thread()
            .worker_threads(self.workers)
            .enable_all()
            .build()?;

        tokio_runtime.block_on(async {
            info!(
                "Starting HTTP(S) server at http(s)://{}:{}",
                self.host, self.port
            );

            info!("Starting {} workers", self.workers);

            info!("Concurrent limit {}", self.concurrent_limit);

            check_self_ip(&api_client()).await;

            #[cfg(all(feature = "sign", feature = "limit"))]
            let app_layer = {
                let limit_context = TokenBucketLimitContext::from((
                    self.tb_store_strategy.clone(),
                    self.tb_enable,
                    self.tb_capacity,
                    self.tb_fill_rate,
                    self.tb_expired,
                    self.tb_redis_url.clone(),
                ));

                tower::ServiceBuilder::new()
                    .layer(axum::middleware::from_fn_with_state(
                        Arc::new(limit_context),
                        middleware::token_bucket_limit_middleware,
                    ))
                    .layer(axum::middleware::from_fn_with_state(
                        Arc::new(self.sign_secret_key),
                        middleware::sign_middleware,
                    ))
                    .layer(axum::middleware::from_fn(
                        middleware::token_authorization_middleware,
                    ))
            };

            #[cfg(all(not(feature = "limit"), feature = "sign"))]
            let app_layer = {
                tower::ServiceBuilder::new()
                    .layer(axum::middleware::from_fn_with_state(
                        Arc::new(self.sign_secret_key),
                        middleware::sign_middleware,
                    ))
                    .layer(axum::middleware::from_fn(
                        middleware::token_authorization_middleware,
                    ))
            };

            #[cfg(all(not(feature = "limit"), not(feature = "sign")))]
            let app_layer = {
                tower::ServiceBuilder::new().layer(axum::middleware::from_fn(
                    middleware::token_authorization_middleware,
                ))
            };

            let router = axum::Router::new()
                // official dashboard api endpoint
                .route("/dashboard/*path", any(official_proxy))
                // official v1 api endpoint
                .route("/v1/*path", any(official_proxy))
                // unofficial backend api endpoint
                .route("/backend-api/*path", any(unofficial_proxy))
                // unofficial public api endpoint
                .route("/public-api/*path", any(unofficial_proxy))
                .route_layer(app_layer)
                // ab pressure test
                .route("/ab", get(|| async {}))
                .route("/auth/token", post(post_access_token))
                .route("/auth/refresh_token", post(post_refresh_token))
                .route("/auth/revoke_token", post(post_revoke_token))
                .route("/auth/arkose_token", get(get_arkose_token));

            let router = ui::config(router).layer(global_layer);

            match self.tls_keypair {
                Some(keypair) => {
                    let tls_config = Self::load_rustls_config(keypair.0, keypair.1)
                        .await
                        .unwrap();
                    let socket = std::net::SocketAddr::new(self.host, self.port);
                    axum_server::bind_rustls(socket, tls_config)
                        .http_config(http_config)
                        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                        .await
                        .expect("openai server failed")
                }
                None => {
                    let socket = std::net::SocketAddr::new(self.host, self.port);
                    axum_server::bind(socket)
                        .http_config(http_config)
                        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                        .await
                        .expect("openai server failed")
                }
            }
        });

        Ok(())
    }

    async fn load_rustls_config(
        tls_cert: PathBuf,
        tls_key: PathBuf,
    ) -> anyhow::Result<axum_server::tls_rustls::RustlsConfig> {
        let config = RustlsConfig::from_pem_file(tls_cert, tls_key)
            .await
            .unwrap();
        Ok(config)
    }
}

async fn post_access_token(
    account: axum::Form<AuthAccount>,
) -> Result<Json<AccessToken>, ResponseError> {
    match auth_client().do_access_token(&account.0).await {
        Ok(access_token) => Ok(Json(access_token)),
        Err(err) => Err(ResponseError::BadRequest(err)),
    }
}

async fn post_refresh_token(headers: HeaderMap) -> Result<Json<RefreshToken>, ResponseError> {
    let refresh_token = headers
        .get(header::AUTHORIZATION)
        .map_or(EMPTY, |e| e.to_str().unwrap_or_default());
    match auth_client().do_refresh_token(refresh_token).await {
        Ok(refresh_token) => Ok(Json(refresh_token)),
        Err(err) => Err(ResponseError::BadRequest(err)),
    }
}

async fn post_revoke_token(headers: HeaderMap) -> Result<axum::http::StatusCode, ResponseError> {
    let refresh_token = headers
        .get(header::AUTHORIZATION)
        .map_or(EMPTY, |e| e.to_str().unwrap_or_default());
    match auth_client().do_revoke_token(refresh_token).await {
        Ok(_) => Ok(axum::http::StatusCode::OK),
        Err(err) => Err(ResponseError::BadRequest(err)),
    }
}

async fn get_arkose_token() -> Result<Json<ArkoseToken>, ResponseError> {
    match ArkoseToken::new("gpt4").await {
        Ok(arkose_token) => Ok(Json(arkose_token)),
        Err(err) => Err(ResponseError::InternalServerError(err)),
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
    body: Option<Json<Value>>,
) -> Result<
    Response<StreamBody<impl futures_core::Stream<Item = Result<bytes::Bytes, reqwest::Error>>>>,
    ResponseError,
> {
    let url = match uri.query() {
        None => {
            format!("{URL_PLATFORM_API}{}", uri.path())
        }
        Some(query) => {
            format!("{URL_PLATFORM_API}{}?{}", uri.path(), query)
        }
    };

    let builder = api_client()
        .request(method, &url)
        .headers(header_convert(headers, jar));
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
    headers: HeaderMap,
    jar: CookieJar,
    mut body: Option<Json<Value>>,
) -> Result<
    Response<StreamBody<impl futures_core::Stream<Item = Result<bytes::Bytes, reqwest::Error>>>>,
    ResponseError,
> {
    let url = if let Some(query) = uri.query() {
        format!("{URL_CHATGPT_API}{}?{}", uri.path(), query)
    } else {
        format!("{URL_CHATGPT_API}{}", uri.path())
    };

    gpt4_body_handle(&url, &method, &mut body).await;

    let builder = api_client()
        .request(method, url)
        .headers(header_convert(headers, jar));
    let resp = match body {
        Some(body) => builder.json(&body.0).send().await,
        None => builder.send().await,
    };
    response_convert(resp)
}

fn response_convert(
    resp: Result<reqwest::Response, reqwest::Error>,
) -> Result<
    Response<StreamBody<impl futures_core::Stream<Item = Result<bytes::Bytes, reqwest::Error>>>>,
    ResponseError,
> {
    match resp {
        Ok(resp) => {
            let mut builder = Response::builder().status(resp.status());
            for kv in resp.headers().into_iter().filter(|(k, _v)| {
                let name = k.as_str().to_lowercase();
                name.ne("__cf_bm")
                    || name.ne("__cfduid")
                    || name.ne("_cfuvid")
                    || name.ne("set-cookie")
            }) {
                builder = builder.header(kv.0, kv.1);
            }

            for c in resp.cookies().into_iter().filter(|c| {
                let key = c.name();
                key.eq("_puid") || key.eq("_account")
            }) {
                if let Some(expires) = c.expires() {
                    let timestamp_nanos = expires
                        .duration_since(UNIX_EPOCH)
                        .expect("Failed to get timestamp")
                        .as_nanos() as i128;
                    let cookie = Cookie::build(c.name(), c.value())
                        .path("/")
                        .expires(
                            time::OffsetDateTime::from_unix_timestamp_nanos(timestamp_nanos)
                                .expect("get cookie expires exception"),
                        )
                        .same_site(cookie::SameSite::Lax)
                        .secure(false)
                        .http_only(false)
                        .finish();
                    builder = builder.header(axum::http::header::SET_COOKIE, cookie.to_string());
                }
            }
            Ok(builder
                .body(StreamBody::new(resp.bytes_stream()))
                .map_err(|err| ResponseError::InternalServerError(err))?)
        }
        Err(err) => Err(ResponseError::InternalServerError(err)),
    }
}

fn header_convert(headers: axum::http::HeaderMap, jar: CookieJar) -> HeaderMap {
    let authorization = match headers.get(header::AUTHORIZATION) {
        Some(v) => Some(v),
        // pandora will pass X-Authorization header
        None => headers.get("X-Authorization"),
    };

    let mut res = HeaderMap::new();
    if let Some(h) = authorization {
        res.insert(header::AUTHORIZATION, h.clone());
    }
    res.insert(header::HOST, HeaderValue::from_static(HOST_CHATGPT));
    res.insert(header::ORIGIN, HeaderValue::from_static(ORIGIN_CHATGPT));
    res.insert(header::USER_AGENT, HeaderValue::from_static(HEADER_UA));
    res.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    res.insert(
        "sec-ch-ua",
        HeaderValue::from_static(
            r#""Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"#,
        ),
    );
    res.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    res.insert("sec-ch-ua-platform", HeaderValue::from_static("Linux"));
    res.insert("sec-fetch-dest", HeaderValue::from_static("empty"));
    res.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
    res.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
    res.insert("sec-gpc", HeaderValue::from_static("1"));
    res.insert("Pragma", HeaderValue::from_static("no-cache"));

    let mut cookie = String::new();

    if let Some(puid) = headers.get("PUID") {
        let puid = puid.to_str().unwrap();
        cookie.push_str(&format!("_puid={puid};"))
    }

    if let Some(cookier) = jar.get("_puid") {
        let c = &format!("_puid={};", puid_cookie_encoded(cookier.value()));
        cookie.push_str(c);
        debug!("request cookie `puid`: {}", c);
    }

    // setting cookie
    if !cookie.is_empty() {
        res.insert(
            header::COOKIE,
            HeaderValue::from_str(cookie.as_str()).expect("setting cookie error"),
        );
    }
    res
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

        format!("{}:{}", name, encoded_value)
    } else {
        input.to_string()
    }
}

async fn gpt4_body_handle(url: &str, method: &Method, body: &mut Option<Json<Value>>) {
    if url.contains("/backend-api/conversation") && method.eq("POST") {
        if let Some(body) = body.as_mut().and_then(|b| b.as_object_mut()) {
            if let Some(v) = body.get("model").and_then(|m| m.as_str()) {
                if body.get("arkose_token").is_none() {
                    if let Ok(arkose) = ArkoseToken::new_from_endpoint(v).await {
                        let _ = body.insert("arkose_token".to_owned(), json!(arkose));
                    }
                }
            }
        }
    }
}

async fn check_self_ip(client: &Client) {
    match client
        .get("https://ifconfig.me")
        .timeout(Duration::from_secs(10))
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
