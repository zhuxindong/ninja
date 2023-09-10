pub mod middleware;
#[cfg(feature = "sign")]
pub mod sign;
#[cfg(feature = "limit")]
pub mod tokenbucket;

pub mod err;

#[cfg(feature = "template")]
pub mod router;
pub mod signal;

use anyhow::anyhow;
use axum::body::StreamBody;
use axum::headers::authorization::Bearer;
use axum::headers::Authorization;
use axum::http::Response;
use axum::response::IntoResponse;
use axum::routing::{any, post};
use axum::{Json, TypedHeader};
use axum_server::{AddrIncomingConfig, Handle};

use axum::http::header;
use axum::http::method::Method;
use axum::http::uri::Uri;
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::{cookie, CookieJar};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::HttpConfig;
use derive_builder::Builder;
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use crate::arkose::funcaptcha::{ArkoseSolver, Solver};
use crate::auth::model::{AccessToken, AuthAccount, AuthStrategy, RefreshToken};
use crate::auth::AuthHandle;
use crate::context::{Context, ContextArgsBuilder};
use crate::serve::router::toapi::chat_to_api;
use crate::serve::tokenbucket::TokenBucketLimitContext;
use crate::{arkose, debug, info, warn, HOST_CHATGPT, ORIGIN_CHATGPT};

use crate::serve::err::ResponseError;
use crate::{HEADER_UA, URL_CHATGPT_API, URL_PLATFORM_API};

const EMPTY: &str = "";

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
    /// Disable direct connection
    disable_direct: bool,
    /// TCP keepalive (second)
    tcp_keepalive: usize,
    /// Client timeout
    timeout: usize,
    /// Client connect timeout
    connect_timeout: usize,
    /// TLS keypair
    tls_keypair: Option<(PathBuf, PathBuf)>,
    /// Account Plus puid cookie value
    puid: Option<String>,
    /// Get the user password of the PUID
    puid_password: Option<String>,
    /// Get the user mailbox of the PUID
    puid_email: Option<String>,
    /// Get the mfa code of the PUID
    puid_mfa: Option<String>,
    /// Web UI api prefix
    api_prefix: Option<String>,
    /// Arkose endpoint
    arkose_endpoint: Option<String>,
    /// Get arkose token endpoint
    arkose_token_endpoint: Option<String>,
    /// Arkoselabs HAR record file path
    arkose_har_file: Option<PathBuf>,
    /// HAR file upload authenticate key
    arkose_har_upload_key: Option<String>,
    /// arkoselabs solver
    arkose_solver: Solver,
    /// arkoselabs solver client key
    arkose_solver_key: Option<String>,
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
    tb_redis_url: String,
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
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "RUST_LOG=warn".into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();

        info!(
            "Starting HTTP(S) server at http(s)://{}:{}",
            self.host, self.port
        );
        info!("Starting {} workers", self.workers);
        info!("Concurrent limit {}", self.concurrent_limit);
        info!("Keepalive {} seconds", self.tcp_keepalive);
        info!("Timeout {} seconds", self.timeout);
        info!("Connect timeout {} seconds", self.connect_timeout);
        if self.disable_direct {
            info!("Disable direct connection");
        }

        let arkose_sovler = match self.arkose_solver_key.as_ref() {
            Some(key) => {
                info!("ArkoseLabs solver: {:?}", self.arkose_solver);
                Some(ArkoseSolver::new(self.arkose_solver.clone(), key.clone()))
            }
            None => None,
        };
        let args = ContextArgsBuilder::default()
            .api_prefix(self.api_prefix.clone())
            .arkose_endpoint(self.arkose_endpoint.clone())
            .arkose_har_file(self.arkose_har_file.clone())
            .arkose_har_upload_key(self.arkose_har_upload_key.clone())
            .arkose_token_endpoint(self.arkose_token_endpoint.clone())
            .arkose_solver(arkose_sovler)
            .puid(self.puid.clone())
            .proxies(self.proxies.clone())
            .disable_direct(self.disable_direct)
            .timeout(self.timeout.clone())
            .connect_timeout(self.connect_timeout)
            .tcp_keepalive(self.tcp_keepalive)
            .build()?;

        Context::init(args);

        let global_layer = tower::ServiceBuilder::new()
            .layer(tower_http::trace::TraceLayer::new_for_http())
            .layer(tower::limit::ConcurrencyLimitLayer::new(
                self.concurrent_limit,
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
                self.timeout as u64,
            )));

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
                .layer(axum::middleware::from_fn(
                    middleware::token_authorization_middleware,
                ))
                .layer(axum::middleware::from_fn_with_state(
                    Arc::new(self.sign_secret_key.clone()),
                    middleware::sign_middleware,
                ))
                .layer(axum::middleware::from_fn_with_state(
                    Arc::new(limit_context),
                    middleware::token_bucket_limit_middleware,
                ))
        };

        #[cfg(all(not(feature = "limit"), feature = "sign"))]
        let app_layer = {
            tower::ServiceBuilder::new()
                .layer(axum::middleware::from_fn(
                    middleware::token_authorization_middleware,
                ))
                .layer(axum::middleware::from_fn_with_state(
                    Arc::new(self.sign_secret_key),
                    middleware::sign_middleware,
                ))
        };

        #[cfg(all(not(feature = "limit"), not(feature = "sign")))]
        let app_layer = {
            tower::ServiceBuilder::new().layer(axum::middleware::from_fn(
                middleware::token_authorization_middleware,
            ))
        };

        let http_config = HttpConfig::new()
            .http1_keep_alive(true)
            .http1_header_read_timeout(Duration::from_secs(self.tcp_keepalive as u64))
            .http2_keep_alive_timeout(Duration::from_secs(self.tcp_keepalive as u64))
            .http2_keep_alive_interval(Some(Duration::from_secs(self.tcp_keepalive as u64)))
            .build();

        let incoming_config = AddrIncomingConfig::new()
            .tcp_sleep_on_accept_errors(true)
            .tcp_keepalive_interval(Some(Duration::from_secs(self.tcp_keepalive as u64)))
            .tcp_keepalive(Some(Duration::from_secs(self.tcp_keepalive as u64)))
            .build();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(self.workers)
            .build()?;

        runtime.block_on(async {
            tokio::spawn(check_wan_address());
            tokio::spawn(initialize_puid(
                self.puid_email.clone(),
                self.puid_password.clone(),
                self.puid_mfa.clone(),
            ));

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
                .route("/auth/revoke_token", post(post_revoke_token));

            let router = router::config(router, &self).layer(global_layer);

            let handle = Handle::new();

            // Spawn a task to gracefully shutdown server.
            tokio::spawn(signal::graceful_shutdown(handle.clone()));

            match self.tls_keypair {
                Some(keypair) => {
                    let tls_config = RustlsConfig::from_pem_file(keypair.0, keypair.1)
                        .await
                        .expect("Failed to load TLS keypair");
                    let socket = std::net::SocketAddr::new(self.host, self.port);
                    axum_server::bind_rustls(socket, tls_config)
                        .handle(handle)
                        .addr_incoming_config(incoming_config)
                        .http_config(http_config)
                        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                        .await
                        .expect("openai server failed")
                }
                None => {
                    let socket = std::net::SocketAddr::new(self.host, self.port);
                    axum_server::bind(socket)
                        .handle(handle)
                        .addr_incoming_config(incoming_config)
                        .http_config(http_config)
                        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                        .await
                        .expect("openai server failed")
                }
            }
        });

        Ok(())
    }
}

async fn post_access_token(
    mut account: axum::Form<AuthAccount>,
) -> Result<Json<AccessToken>, ResponseError> {
    let ctx = Context::get_instance().await;
    let mut result: Result<Json<AccessToken>, ResponseError> = Err(
        ResponseError::InternalServerError(anyhow!("There was an error logging in to the Body")),
    );

    for _ in 0..2 {
        match ctx.load_auth_client().do_access_token(&account.0).await {
            Ok(access_token) => {
                result = Ok(Json(access_token));
                break;
            }
            Err(err) => {
                debug!("Error: {err}");
                account.0.option = match account.0.option {
                    AuthStrategy::Web => AuthStrategy::Apple,
                    AuthStrategy::Apple => AuthStrategy::Web,
                    _ => break,
                };
                result = Err(ResponseError::BadRequest(err));
            }
        }
    }

    result
}

async fn post_refresh_token(
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<RefreshToken>, ResponseError> {
    let ctx = Context::get_instance().await;
    match ctx
        .load_auth_client()
        .do_refresh_token(bearer.token())
        .await
    {
        Ok(refresh_token) => Ok(Json(refresh_token)),
        Err(err) => Err(ResponseError::BadRequest(err)),
    }
}

async fn post_revoke_token(
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
) -> Result<axum::http::StatusCode, ResponseError> {
    let ctx = Context::get_instance().await;
    match ctx.load_auth_client().do_revoke_token(bearer.token()).await {
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
    body: Option<Json<Value>>,
) -> Result<impl IntoResponse, ResponseError> {
    let url = match uri.query() {
        None => {
            format!("{URL_PLATFORM_API}{}", uri.path())
        }
        Some(query) => {
            format!("{URL_PLATFORM_API}{}?{}", uri.path(), query)
        }
    };
    let ctx = Context::get_instance().await;
    let builder = ctx
        .load_client()
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
    let url = if let Some(query) = uri.query() {
        format!("{URL_CHATGPT_API}{}?{}", uri.path(), query)
    } else {
        format!("{URL_CHATGPT_API}{}", uri.path())
    };

    handle_body(&url, &method, &mut headers, &mut body).await?;

    let ctx = Context::get_instance().await;
    let builder = ctx
        .load_client()
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
        let puid = puid.to_str().unwrap();
        cookie.push_str(&format!("_puid={puid};"))
    }

    match jar.get("_puid") {
        Some(cookier) => {
            let c = &format!("_puid={};", puid_cookie_encoded(cookier.value()));
            cookie.push_str(c);
            debug!("request cookie `puid`: {}", c);
        }
        None => {
            if !has_puid(&headers)? {
                let ctx = Context::get_instance().await;
                let puid = ctx.get_share_puid().await;
                if !puid.is_empty() {
                    let c = &format!("_puid={};", puid);
                    cookie.push_str(c);
                    debug!("Local `puid`: {}", c);
                }
            }
        }
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
        .map_err(ResponseError::InternalServerError)?)
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

    if arkose::GPT4Model::try_from(model).is_err() {
        return Ok(());
    }

    if body.get("arkose_token").is_some() {
        return Ok(());
    }

    let authorization = headers
        .get(header::AUTHORIZATION)
        .ok_or(ResponseError::Unauthorized(anyhow!(
            "AccessToken required!"
        )))?;

    if !has_puid(headers)? {
        let resp = Context::get_instance()
            .await
            .load_client()
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
                        HeaderValue::from_str(&format!("_puid={};", puid_cookie.value())).unwrap(),
                    );
                }
            }
            Err(err) => return Err(ResponseError::InternalServerError(err)),
        }
    }

    if let Ok(arkose_token) = arkose::ArkoseToken::new_from_context().await {
        let _ = body.insert("arkose_token".to_owned(), json!(arkose_token));
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

async fn check_wan_address() {
    match Context::get_instance()
        .await
        .load_client()
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

async fn initialize_puid(username: Option<String>, password: Option<String>, mfa: Option<String>) {
    if username.is_none() || password.is_none() {
        return;
    }
    let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60)); // 24 hours
    let mut account = AuthAccount {
        username: username.unwrap(),
        password: password.unwrap(),
        mfa,
        option: AuthStrategy::Apple,
        cf_turnstile_response: None,
    };
    let ctx = Context::get_instance().await;
    loop {
        interval.tick().await;
        for _ in 0..2 {
            match ctx.load_auth_client().do_access_token(&account).await {
                Ok(v) => {
                    let access_token = match v {
                        AccessToken::Session(access_token) => access_token.access_token,
                        AccessToken::OAuth(access_token) => access_token.access_token,
                    };
                    match ctx
                        .load_client()
                        .get(format!("{URL_CHATGPT_API}/backend-api/models"))
                        .bearer_auth(access_token)
                        .send()
                        .await
                    {
                        Ok(resp) => match resp.error_for_status() {
                            Ok(v) => match v.cookies().into_iter().find(|v| v.name().eq("_puid")) {
                                Some(cookie) => {
                                    let puid = cookie.value();
                                    info!("Update PUID: {puid}");
                                    ctx.set_share_puid(puid).await;
                                    break;
                                }
                                None => {
                                    warn!("Your account may not be Plus")
                                }
                            },
                            Err(err) => {
                                warn!("failed to get puid error: {}", err)
                            }
                        },
                        Err(err) => {
                            warn!("[{}] Error: {err}", account.option);
                        }
                    }
                }
                Err(err) => {
                    warn!("login error: {}", err);
                    account.option = AuthStrategy::Web
                }
            }
        }
    }
}
