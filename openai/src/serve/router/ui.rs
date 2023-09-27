use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::OnceLock;

use anyhow::anyhow;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::extract::Path;
use axum::extract::Query;
use axum::headers::authorization::Bearer;
use axum::headers::Authorization;
use axum::http::header;
use axum::http::HeaderMap;
use axum::http::Response;
use axum::response::IntoResponse;
use axum::routing::any;
use axum::routing::{get, post};
use axum::Router;
use axum::TypedHeader;
use axum_extra::extract::cookie;
use axum_extra::extract::CookieJar;

use base64::Engine;

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;

use crate::context;
use crate::info;
use crate::serve::err::ResponseError;
use crate::serve::header_convert;
use crate::serve::response_convert;
use crate::serve::Launcher;
use crate::serve::EMPTY;
use crate::{
    auth::{model::AuthAccount, AuthHandle},
    model::AuthenticateToken,
    URL_CHATGPT_API,
};

use super::get_static_resource;

const DEFAULT_INDEX: &str = "/";
const LOGIN_INDEX: &str = "/auth/login";
const SESSION_ID: &str = "ninja_session";
const BUILD_ID: &str = "oDTsXIohP85MnLZj7TlaB";
const TEMP_404: &str = "404.htm";
const TEMP_AUTH: &str = "auth.htm";
const TEMP_CHAT: &str = "chat.htm";
const TEMP_DETAIL: &str = "detail.htm";
const TEMP_LOGIN: &str = "login.htm";
const TEMP_SHARE: &str = "share.htm";

static TEMPLATE: OnceLock<tera::Tera> = OnceLock::new();
static TEMPLATE_DATA: OnceLock<TemplateData> = OnceLock::new();

#[derive(Serialize, Deserialize)]
struct Session {
    refresh_token: Option<String>,
    access_token: String,
    user_id: String,
    email: String,
    picture: Option<String>,
    expires_in: i64,
    expires: i64,
}

impl ToString for Session {
    fn to_string(&self) -> String {
        let json = serde_json::to_string(self)
            .expect("An error occurred during the internal serialization session");
        base64::engine::general_purpose::URL_SAFE.encode(json.as_bytes())
    }
}

impl TryFrom<&str> for Session {
    type Error = ResponseError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let data = base64::engine::general_purpose::URL_SAFE
            .decode(value)
            .map_err(ResponseError::Unauthorized)?;
        serde_json::from_slice(&data).map_err(ResponseError::Unauthorized)
    }
}

impl From<AuthenticateToken> for Session {
    fn from(value: AuthenticateToken) -> Self {
        let refresh_token = if let Some(refresh_token) = value.refresh_token() {
            Some(refresh_token.to_owned())
        } else {
            None
        };
        Session {
            user_id: value.user_id().to_owned(),
            email: value.email().to_owned(),
            picture: Some(value.picture().to_owned()),
            access_token: value.access_token().to_owned(),
            expires_in: value.expires_in(),
            expires: value.expires(),
            refresh_token,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone)]
pub(super) struct TemplateData {
    /// WebSite api prefix
    api_prefix: Option<String>,
    /// GPT-4 model arkose token endpoint
    arkose_endpoint: Option<String>,
    /// Cloudflare captcha site key
    cf_site_key: Option<String>,
    /// Cloudflare captcha secret key
    cf_secret_key: Option<String>,
}

impl From<Launcher> for TemplateData {
    fn from(value: Launcher) -> Self {
        Self {
            api_prefix: value.api_prefix,
            cf_site_key: value.cf_site_key,
            cf_secret_key: value.cf_secret_key,
            arkose_endpoint: value.arkose_endpoint,
        }
    }
}

// this function could be located in a different module
pub(super) fn config(router: Router, args: &Launcher) -> Router {
    if !args.disable_ui {
        let data = TEMPLATE_DATA.get_or_init(|| TemplateData::from(args.clone()));
        if let Some(url) = data.api_prefix.as_ref() {
            info!("WebUI site use API: {url}")
        }

        if let Some(endpoint) = data.arkose_endpoint.as_ref() {
            info!("WebUI site use Arkose endpoint: {endpoint}")
        }

        let mut tera = tera::Tera::default();
        tera.add_raw_templates(vec![
            (TEMP_404, include_str!("../../../ui/404.htm")),
            (TEMP_AUTH, include_str!("../../../ui/auth.htm")),
            (TEMP_LOGIN, include_str!("../../../ui/login.htm")),
            (TEMP_CHAT, include_str!("../../../ui/chat.htm")),
            (TEMP_DETAIL, include_str!("../../../ui/detail.htm")),
            (TEMP_SHARE, include_str!("../../../ui/share.htm")),
        ])
        .expect("The static template failed to load");

        let _ = TEMPLATE.set(tera);

        router
            .route("/auth", get(get_auth))
            .route("/auth/login", get(get_login))
            .route("/auth/login", post(post_login))
            .route("/auth/login/token", post(post_login_token))
            .route("/auth/logout", get(get_logout))
            .route("/auth/session", get(get_session))
            .route("/", get(get_chat))
            .route("/c", get(get_chat))
            .route("/c/:conversation_id", get(get_chat))
            .route(
                "/chat",
                any(|| async {
                    Response::builder()
                        .status(StatusCode::FOUND)
                        .header(header::LOCATION, "/")
                        .body(Body::empty())
                        .expect("An error occurred while redirecting")
                }),
            )
            .route(
                "/chat/:conversation_id",
                any(|| async {
                    Response::builder()
                        .status(StatusCode::FOUND)
                        .header(header::LOCATION, "/")
                        .body(Body::empty())
                        .expect("An error occurred while redirecting")
                }),
            )
            .route("/share/:share_id", get(get_share_chat))
            .route("/share/:share_id/continue", get(get_share_chat_continue))
            .route(
                &format!("/_next/data/{BUILD_ID}/index.json"),
                get(get_chat_info),
            )
            .route(
                // {conversation_id}.json
                &format!("/_next/data/{BUILD_ID}/c/:conversation_id"),
                get(get_chat_info),
            )
            .route(
                // {share_id}.json
                &format!("/_next/data/{BUILD_ID}/share/:share_id"),
                get(get_share_chat_info),
            )
            .route(
                &format!("/_next/data/{BUILD_ID}/share/:share_id/continue.json"),
                get(get_share_chat_continue_info),
            )
            // user picture
            .route("/_next/image", get(get_image))
            // static resource endpoints
            .route("/resources/*path", get(get_static_resource))
            .route("/_next/static/*path", get(get_static_resource))
            .route("/fonts/*path", get(get_static_resource))
            .route("/ulp/*path", get(get_static_resource))
            .route("/sweetalert2/*path", get(get_static_resource))
            // 404 endpoint
            .fallback(error_404)
    } else {
        router
    }
}

async fn get_auth() -> Result<Response<Body>, ResponseError> {
    let mut ctx = tera::Context::new();
    settings_template_data(&mut ctx);
    render_template(TEMP_AUTH, &ctx)
}

async fn get_login() -> Result<Response<Body>, ResponseError> {
    let mut ctx = tera::Context::new();
    ctx.insert("error", "");
    ctx.insert("username", "");
    settings_template_data(&mut ctx);
    render_template(TEMP_LOGIN, &ctx)
}

async fn post_login(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    account: axum::Form<AuthAccount>,
) -> Result<Response<Body>, ResponseError> {
    let account = account.0;
    if let Some(err) = cf_captcha_check(addr.ip(), account.cf_turnstile_response.as_deref())
        .await
        .err()
    {
        let mut ctx = tera::Context::new();
        ctx.insert("username", &account.username);
        ctx.insert("error", &err.msg());
        return render_template(TEMP_LOGIN, &ctx);
    }

    match context::Context::get_instance()
        .await
        .load_auth_client()
        .do_access_token(&account)
        .await
    {
        Ok(access_token) => {
            let authentication_token = AuthenticateToken::try_from(access_token)
                .map_err(ResponseError::InternalServerError)?;
            let session = Session::from(authentication_token);

            let cookie = cookie::Cookie::build(SESSION_ID, session.to_string())
                .path(DEFAULT_INDEX)
                .same_site(cookie::SameSite::Lax)
                .max_age(time::Duration::seconds(session.expires_in))
                .secure(false)
                .http_only(false)
                .finish();

            Ok(Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header(header::LOCATION, DEFAULT_INDEX)
                .header(header::SET_COOKIE, cookie.to_string())
                .body(Body::empty())
                .map_err(ResponseError::InternalServerError)?)
        }
        Err(e) => {
            let mut ctx = tera::Context::new();
            ctx.insert("username", &account.username);
            ctx.insert("error", &e.to_string());
            render_template(TEMP_LOGIN, &ctx)
        }
    }
}

async fn post_login_token(
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
) -> Result<Response<Body>, ResponseError> {
    let access_token = bearer.token();

    if access_token.is_empty() {
        return redirect_login();
    }

    let profile = crate::token::check(bearer.token())
        .map_err(ResponseError::Unauthorized)?
        .ok_or(ResponseError::InternalServerError(anyhow!(
            "Get Profile Erorr"
        )))?;

    let session = match context::Context::get_instance()
        .await
        .load_auth_client()
        .do_get_user_picture(access_token)
        .await
    {
        Ok(picture) => Session {
            refresh_token: None,
            access_token: access_token.to_owned(),
            user_id: profile.user_id().to_owned(),
            email: profile.email().to_owned(),
            picture: picture,
            expires_in: profile.expires_in(),
            expires: profile.expires(),
        },
        Err(_) => Session {
            user_id: profile.user_id().to_owned(),
            email: profile.email().to_owned(),
            picture: None,
            access_token: access_token.to_owned(),
            expires_in: profile.expires_in(),
            expires: profile.expires(),
            refresh_token: None,
        },
    };

    let cookie = cookie::Cookie::build(SESSION_ID, session.to_string())
        .path(DEFAULT_INDEX)
        .same_site(cookie::SameSite::Lax)
        .max_age(time::Duration::seconds(session.expires_in))
        .secure(false)
        .http_only(false)
        .finish();

    return Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::LOCATION, DEFAULT_INDEX)
        .header(header::SET_COOKIE, cookie.to_string())
        .body(Body::empty())
        .map_err(ResponseError::InternalServerError)?);
}

async fn get_logout(jar: CookieJar) -> Result<Response<Body>, ResponseError> {
    if let Some(c) = jar.get(SESSION_ID) {
        match extract_session(c.value()) {
            Ok(session) => {
                if let Some(refresh_token) = session.refresh_token {
                    let ctx = context::Context::get_instance().await;
                    let _a = ctx.load_auth_client().do_revoke_token(&refresh_token).await;
                }
            }
            Err(_) => {}
        }
    }
    let cookie = cookie::Cookie::build(SESSION_ID, EMPTY)
        .path(DEFAULT_INDEX)
        .same_site(cookie::SameSite::Lax)
        .max_age(time::Duration::seconds(0))
        .secure(false)
        .http_only(false)
        .finish();

    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, LOGIN_INDEX)
        .header(header::SET_COOKIE, cookie.to_string())
        .body(Body::empty())
        .map_err(ResponseError::InternalServerError)?)
}

async fn get_session(jar: CookieJar) -> Result<Response<Body>, ResponseError> {
    if let Some(cookie) = jar.get(SESSION_ID) {
        let session = extract_session(cookie.value())?;

        let time = time::OffsetDateTime::from_unix_timestamp(session.expires)
            .map_err(ResponseError::InternalServerError)?;
        let expires = time
            .format(&Rfc3339)
            .map_err(ResponseError::InternalServerError)?;

        let props = serde_json::json!({
            "user": {
                "id": session.user_id,
                "name": session.email,
                "email": session.email,
                "image": session.picture,
                "picture": session.picture,
                "groups": [],
            },
            "expires" : expires,
            "accessToken": session.access_token,
            "authProvider": "auth0"
        });

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::LOCATION, LOGIN_INDEX)
            .header(header::SET_COOKIE, cookie.to_string())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(props.to_string()))
            .map_err(ResponseError::InternalServerError)?);
    }
    redirect_login()
}

async fn get_chat(
    jar: CookieJar,
    conversation_id: Option<Path<String>>,
    mut query: Query<HashMap<String, String>>,
) -> Result<Response<Body>, ResponseError> {
    if let Some(cookie) = jar.get(SESSION_ID) {
        return match extract_session(cookie.value()) {
            Ok(session) => {
                let template_name = match conversation_id {
                    Some(conversation_id) => {
                        query.insert("default".to_string(), format!("[c, {}]", conversation_id.0));
                        TEMP_DETAIL
                    }
                    None => TEMP_CHAT,
                };
                let props = serde_json::json!({
                    "props": {
                        "pageProps": {
                            "user": {
                                "id": session.user_id,
                                "name": session.email,
                                "email": session.email,
                                "image": session.picture,
                                "picture": session.picture,
                                "groups": [],
                            },
                            "serviceStatus": {},
                            "userCountry": "US",
                            "geoOk": true,
                            "serviceAnnouncement": {
                                "paid": {},
                                "public": {}
                            },
                            "isUserInCanPayGroup": true
                        },
                        "__N_SSP": true
                    },
                    "page": "/[[...default]]",
                    "query": query.0,
                    "buildId": BUILD_ID,
                    "isFallback": false,
                    "gssp": true,
                    "scriptLoader": []
                });
                let mut ctx = tera::Context::new();
                ctx.insert(
                    "props",
                    &serde_json::to_string(&props).map_err(ResponseError::InternalServerError)?,
                );
                settings_template_data(&mut ctx);
                return render_template(template_name, &ctx);
            }
            Err(_) => redirect_login(),
        };
    }
    redirect_login()
}

async fn get_chat_info(jar: CookieJar) -> Result<Response<Body>, ResponseError> {
    if let Some(cookie) = jar.get(SESSION_ID) {
        return match extract_session(cookie.value()) {
            Ok(session) => {
                let body = serde_json::json!({
                    "pageProps": {
                        "user": {
                            "id": session.user_id,
                            "name": session.email,
                            "email": session.email,
                            "image": session.picture,
                            "picture": session.picture,
                            "groups": [],
                        },
                        "serviceStatus": {},
                        "userCountry": "US",
                        "geoOk": true,
                        "serviceAnnouncement": {
                            "paid": {},
                            "public": {}
                        },
                        "isUserInCanPayGroup": true
                    },
                    "__N_SSP": true
                });

                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .map_err(ResponseError::InternalServerError)?)
            }
            Err(_) => {
                let body = serde_json::json!(
                    {"pageProps": {"__N_REDIRECT": "/auth/login?", "__N_REDIRECT_STATUS": 307}, "__N_SSP": true}
                );
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .map_err(ResponseError::InternalServerError)?)
            }
        };
    }
    redirect_login()
}

async fn get_share_chat(
    headers: HeaderMap,
    jar: CookieJar,
    share_id: Path<String>,
) -> Result<Response<Body>, ResponseError> {
    let share_id = share_id.0;
    if let Some(cookie) = jar.get(SESSION_ID) {
        return match extract_session(cookie.value()) {
            Ok(session) => {
                let ctx = context::Context::get_instance().await;
                let url = get_url();
                let resp = ctx
                    .load_client()
                    .get(format!("{url}/backend-api/share/{share_id}"))
                    .headers(header_convert(&headers, &jar).await?)
                    .bearer_auth(session.access_token)
                    .send()
                    .await
                    .map_err(ResponseError::InternalServerError)?;

                match resp.json::<Value>().await {
                    Ok(mut share_data) => {
                        if let Some(replace) = share_data
                            .get_mut("continue_conversation_url")
                            .and_then(|v| v.as_str())
                        {
                            let new_value = replace.replace("https://chat.openai.com", "");
                            share_data.as_object_mut().and_then(|data| {
                                data.insert(
                                    "continue_conversation_url".to_owned(),
                                    json!(new_value),
                                )
                            });
                        }

                        let props = serde_json::json!({
                                    "props": {
                                        "pageProps": {
                                            "sharedConversationId": share_id,
                                            "serverResponse": {
                                                "type": "data",
                                                "data": share_data
                                            },
                                            "continueMode": false,
                                            "moderationMode": false,
                                            "chatPageProps": {},
                                        },
                                        "__N_SSP": true
                                    },
                                    "page": "/share/[[...shareParams]]",
                                    "query": {
                                        "shareParams": vec![share_id]
                                    },
                                    "buildId": BUILD_ID,
                                    "isFallback": false,
                                    "gssp": true,
                                    "scriptLoader": []
                                }
                        );
                        let mut ctx = tera::Context::new();
                        ctx.insert(
                            "props",
                            &serde_json::to_string(&props)
                                .map_err(ResponseError::InternalServerError)?,
                        );
                        settings_template_data(&mut ctx);
                        render_template(TEMP_SHARE, &ctx)
                    }
                    Err(_) => {
                        let props = serde_json::json!({
                            "props": {
                                "pageProps": {"statusCode": 404}
                            },
                            "page": "/_error",
                            "query": {},
                            "buildId": BUILD_ID,
                            "nextExport": true,
                            "isFallback": false,
                            "gip": true,
                            "scriptLoader": []
                        });

                        let mut ctx = tera::Context::new();
                        ctx.insert(
                            "props",
                            &serde_json::to_string(&props)
                                .map_err(ResponseError::InternalServerError)?,
                        );
                        settings_template_data(&mut ctx);
                        render_template(TEMP_404, &ctx)
                    }
                }
            }
            Err(_) => Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header(
                    header::LOCATION,
                    format!("/auth/login?next=%2Fshare%2F{share_id}"),
                )
                .body(Body::empty())
                .map_err(ResponseError::InternalServerError)?),
        };
    }

    redirect_login()
}

async fn get_share_chat_info(
    headers: HeaderMap,
    jar: CookieJar,
    share_id: Path<String>,
) -> Result<Response<Body>, ResponseError> {
    let share_id = share_id.0.replace(".json", "");
    if let Some(cookie) = jar.get(SESSION_ID) {
        if let Ok(session) = extract_session(cookie.value()) {
            let ctx = context::Context::get_instance().await;
            let url = get_url();
            let resp = ctx
                .load_client()
                .get(format!("{url}/backend-api/share/{share_id}"))
                .headers(header_convert(&headers, &jar).await?)
                .bearer_auth(session.access_token)
                .send()
                .await
                .map_err(ResponseError::InternalServerError)?;

            return match resp.json::<Value>().await {
                Ok(mut share_data) => {
                    if let Some(replace) = share_data
                        .get_mut("continue_conversation_url")
                        .and_then(|v| v.as_str())
                    {
                        let new_value = replace.replace("https://chat.openai.com", "");
                        share_data.as_object_mut().and_then(|data| {
                            data.insert("continue_conversation_url".to_owned(), json!(new_value))
                        });
                    }

                    let props = serde_json::json!({
                        "pageProps": {
                            "sharedConversationId": share_id,
                            "serverResponse": {
                                "type": "data",
                                "data": share_data,
                            },
                            "continueMode": false,
                            "moderationMode": false,
                            "chatPageProps": {},
                        },
                        "__N_SSP": true
                    }
                    );
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::to_string(&props)
                                .map_err(ResponseError::InternalServerError)?,
                        ))
                        .map_err(ResponseError::InternalServerError)?)
                }
                Err(_) => Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_string(&serde_json::json!({"notFound": true}))
                            .map_err(ResponseError::InternalServerError)?,
                    ))
                    .map_err(ResponseError::InternalServerError)?),
            };
        }

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(
                header::LOCATION,
                format!("/auth/login?next=%2Fshare%2F{share_id}"),
            )
            .body(Body::empty())
            .map_err(ResponseError::InternalServerError)?);
    }
    redirect_login()
}

async fn get_share_chat_continue(share_id: Path<String>) -> Result<Response<Body>, ResponseError> {
    Ok(Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(header::LOCATION, format!("/share/{}", share_id.0))
        .body(Body::empty())
        .map_err(ResponseError::InternalServerError)?)
}

async fn get_share_chat_continue_info(
    headers: HeaderMap,
    jar: CookieJar,
    share_id: Path<String>,
) -> Result<Response<Body>, ResponseError> {
    if let Some(cookie) = jar.get(SESSION_ID) {
        return match extract_session(cookie.value()) {
            Ok(session) => {
                let ctx = context::Context::get_instance().await;
                let url = get_url();
                let resp = ctx
                    .load_client()
                    .get(format!("{url}/backend-api/share/{}", share_id.0))
                    .headers(header_convert(&headers, &jar).await?)
                    .bearer_auth(session.access_token)
                    .send()
                    .await
                    .map_err(ResponseError::InternalServerError)?;
                match resp.json::<Value>().await {
                    Ok(mut share_data) => {
                        if let Some(replace) = share_data
                            .get_mut("continue_conversation_url")
                            .and_then(|v| v.as_str())
                        {
                            let new_value = replace.replace("https://chat.openai.com", "");
                            share_data.as_object_mut().and_then(|data| {
                                data.insert(
                                    "continue_conversation_url".to_owned(),
                                    json!(new_value),
                                )
                            });
                        }
                        let props = serde_json::json!({
                            "pageProps": {
                                "user": {
                                    "id": session.user_id,
                                    "name": session.email,
                                    "email": session.email,
                                    "image": session.picture,
                                    "picture": session.picture,
                                    "groups": [],
                                },
                                "serviceStatus": {},
                                "userCountry": "US",
                                "geoOk": true,
                                "serviceAnnouncement": {
                                    "paid": {},
                                    "public": {}
                                },
                                "isUserInCanPayGroup": true,
                                "sharedConversationId": share_id.0,
                                "serverResponse": {
                                    "type": "data",
                                    "data": share_data,
                                },
                                "continueMode": true,
                                "moderationMode": false,
                                "chatPageProps": {
                                    "user": {
                                        "id": session.user_id,
                                        "name": session.email,
                                        "email": session.email,
                                        "image": session.picture,
                                        "picture": session.picture,
                                        "groups": [],
                                    },
                                    "serviceStatus": {},
                                    "userCountry": "US",
                                    "geoOk": true,
                                    "serviceAnnouncement": {
                                        "paid": {},
                                        "public": {}
                                    },
                                    "isUserInCanPayGroup": true,
                                },
                            },
                            "__N_SSP": true
                        });
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(Body::from(
                                serde_json::to_string(&props)
                                    .map_err(ResponseError::InternalServerError)?,
                            ))
                            .map_err(ResponseError::InternalServerError)?)
                    }
                    Err(_) => Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "same-origin")
                        .body(Body::from(
                            serde_json::to_string(&serde_json::json!({"notFound": true}))
                                .map_err(ResponseError::InternalServerError)?,
                        ))
                        .map_err(ResponseError::InternalServerError)?),
                }
            }
            Err(_) => {
                let body = Body::from(serde_json::to_string(&serde_json::json!({
                    "pageProps": {
                        "__N_REDIRECT": format!("/auth/login?next=%2Fshare%2F{}%2Fcontinue", share_id.0),
                        "__N_REDIRECT_STATUS": 307
                    },
                    "__N_SSP": true
                })).map_err(ResponseError::InternalServerError)?);
                Ok(Response::builder()
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(body)
                    .map_err(ResponseError::InternalServerError)?)
            }
        };
    }
    redirect_login()
}

async fn get_image(
    params: Option<axum::extract::Query<ImageQuery>>,
) -> Result<impl IntoResponse, ResponseError> {
    let query = params.ok_or(ResponseError::BadRequest(anyhow::anyhow!(
        "Missing URL parameter"
    )))?;
    let resp = context::Context::get_instance()
        .await
        .load_client()
        .get(&query.url)
        .send()
        .await;
    response_convert(resp)
}

async fn error_404() -> Result<Response<Body>, ResponseError> {
    let mut ctx = tera::Context::new();
    let props = json!(
        {
            "props": {
                "pageProps": {"statusCode": 404}
            },
            "page": "/_error",
            "query": {},
            "buildId": BUILD_ID,
            "nextExport": true,
            "isFallback": false,
            "gip": false,
            "scriptLoader": []
        }
    );
    ctx.insert(
        "props",
        &serde_json::to_string(&props).map_err(ResponseError::InternalServerError)?,
    );
    render_template(TEMP_404, &ctx)
}

fn extract_session(cookie_value: &str) -> Result<Session, ResponseError> {
    Session::try_from(cookie_value)
        .map_err(|_| ResponseError::Unauthorized(anyhow!("invalid session")))
        .and_then(|session| match check_token(&session.access_token) {
            Ok(_) => Ok(session),
            Err(err) => Err(err),
        })
}

fn redirect_login() -> Result<Response<Body>, ResponseError> {
    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, LOGIN_INDEX)
        .body(Body::empty())
        .map_err(ResponseError::InternalServerError)?)
}

fn render_template(name: &str, context: &tera::Context) -> Result<Response<Body>, ResponseError> {
    let tm = TEMPLATE
        .get()
        .expect("template not init")
        .render(name, context)
        .map_err(ResponseError::InternalServerError)?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(tm))
        .map_err(ResponseError::InternalServerError)?)
}

fn settings_template_data(ctx: &mut tera::Context) {
    let data = TEMPLATE_DATA.get().expect("template data not init");
    if let Some(site_key) = &data.cf_site_key {
        ctx.insert("site_key", site_key);
    }
    if let Some(api_prefix) = &data.api_prefix {
        ctx.insert("api_prefix", api_prefix);
    }
    if let Some(arkose_endpoint) = &data.arkose_endpoint {
        ctx.insert("arkose_endpoint", arkose_endpoint)
    }
}

fn check_token(token: &str) -> Result<(), ResponseError> {
    let _ = crate::token::check(token).map_err(ResponseError::Unauthorized)?;
    Ok(())
}

async fn cf_captcha_check(addr: IpAddr, cf_response: Option<&str>) -> Result<(), ResponseError> {
    let data = TEMPLATE_DATA.get().expect("template data not init");
    if data.cf_site_key.is_some() && data.cf_secret_key.is_some() {
        let cf_response = cf_response.ok_or(ResponseError::BadRequest(anyhow::anyhow!(
            "Missing cf_captcha_response"
        )))?;

        if cf_response.is_empty() {
            return Err(ResponseError::BadRequest(anyhow::anyhow!(
                "Missing cf_captcha_response"
            )));
        }

        let form = CfCaptchaForm {
            secret: data.cf_secret_key.as_ref().expect("cf_secret_key not init"),
            response: cf_response,
            remoteip: &addr.to_string(),
            idempotency_key: crate::uuid::uuid(),
        };

        let resp = context::Context::get_instance()
            .await
            .load_client()
            .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .form(&form)
            .send()
            .await
            .map_err(ResponseError::InternalServerError)?;

        let _ = resp
            .error_for_status()
            .map_err(ResponseError::Unauthorized)?;

        return Ok(());
    };
    Ok(())
}

fn get_url() -> &'static str {
    let data = TEMPLATE_DATA.get().expect("template data not init");
    match data.api_prefix.as_ref() {
        Some(ref api_prefix) => api_prefix,
        None => URL_CHATGPT_API,
    }
}
#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct ImageQuery {
    url: String,
    w: String,
    q: String,
}

#[derive(serde::Serialize)]
struct CfCaptchaForm<'a> {
    secret: &'a str,
    response: &'a str,
    remoteip: &'a str,
    idempotency_key: String,
}
