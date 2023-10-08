use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
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
use crate::now_duration;
use crate::serve;
use crate::serve::err::ResponseError;
use crate::serve::header_convert;
use crate::serve::response_convert;
use crate::serve::turnstile;
use crate::serve::Launcher;
use crate::serve::EMPTY;
use crate::warn;
use crate::{
    auth::{model::AuthAccount, provide::AuthProvider},
    model::AuthenticateToken,
    URL_CHATGPT_API,
};

use super::get_static_resource;

const DEFAULT_INDEX: &str = "/";
const LOGIN_INDEX: &str = "/auth/login";
const SESSION_ID: &str = "ninja_session";
const BUILD_ID: &str = "cdCfIN9NUpAX8XOZwcgjh";
const TEMP_404: &str = "404.htm";
const TEMP_AUTH: &str = "auth.htm";
const TEMP_CHAT: &str = "chat.htm";
const TEMP_DETAIL: &str = "detail.htm";
const TEMP_LOGIN: &str = "login.htm";
const TEMP_SHARE: &str = "share.htm";

static TEMPLATE: OnceLock<tera::Tera> = OnceLock::new();

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

impl FromStr for Session {
    type Err = ResponseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = base64::engine::general_purpose::URL_SAFE
            .decode(s)
            .map_err(ResponseError::Unauthorized)?;
        serde_json::from_slice(&data).map_err(ResponseError::Unauthorized)
    }
}

impl From<AuthenticateToken> for Session {
    fn from(value: AuthenticateToken) -> Self {
        Session {
            user_id: value.user_id().to_owned(),
            email: value.email().to_owned(),
            picture: Some(value.picture().to_owned()),
            access_token: value.access_token().to_owned(),
            expires_in: value.expires_in(),
            expires: value.expires(),
            refresh_token: value.refresh_token().map(|v| v.to_owned()),
        }
    }
}

// this function could be located in a different module
pub(super) fn config(router: Router, args: &Launcher) -> Router {
    if !args.disable_ui {
        let ctx = context::get_instance();
        if let Some(url) = ctx.api_prefix() {
            info!("WebUI site use API: {url}")
        }

        if let Some(endpoint) = ctx.arkose_endpoint() {
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
            .route("/share/e/:share_id", get(get_share_chat))
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
    mut account: axum::Form<AuthAccount>,
) -> Result<Response<Body>, ResponseError> {
    turnstile::cf_turnstile_check(&addr.ip(), account.cf_turnstile_response.as_deref()).await?;

    match serve::retry_login(&mut account).await {
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
        Err(err) => {
            let mut ctx = tera::Context::new();
            ctx.insert("username", &account.username);
            ctx.insert("error", &err.to_string());
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

    let session = match context::get_instance()
        .auth_client()
        .do_get_user_picture(access_token)
        .await
    {
        Ok(picture) => Session {
            refresh_token: None,
            access_token: access_token.to_owned(),
            user_id: profile.user_id().to_owned(),
            email: profile.email().to_owned(),
            picture,
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
                    let ctx = context::get_instance();
                    let _a = ctx.auth_client().do_revoke_token(&refresh_token).await;
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
        // Extract session from cookie
        let session = extract_session(cookie.value())?;

        let current_timestamp = now_duration()?.as_secs() as i64;

        if session.expires < current_timestamp {
            return redirect_login();
        }

        fn to_body(session: Session) -> anyhow::Result<String> {
            let expires = time::OffsetDateTime::from_unix_timestamp(session.expires)
                .map(|v| v.format(&Rfc3339))??;
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
            Ok(props.to_string())
        }

        fn to_response(
            session: Session,
            cookie: &cookie::Cookie,
        ) -> Result<Response<Body>, ResponseError> {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::LOCATION, LOGIN_INDEX)
                .header(header::SET_COOKIE, cookie.to_string())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(to_body(session)?))
                .map_err(ResponseError::InternalServerError)?)
        }

        if let Some(refresh_token) = session.refresh_token.as_ref() {
            if session.expires - current_timestamp <= (session.expires_in / 2) {
                let ctx = context::get_instance();
                match ctx.auth_client().do_refresh_token(&refresh_token).await {
                    Ok(refresh_token) => {
                        let authentication_token = AuthenticateToken::try_from(refresh_token)?;
                        let session = Session::from(authentication_token);
                        let cookie = cookie::Cookie::build(SESSION_ID, session.to_string())
                            .path(DEFAULT_INDEX)
                            .same_site(cookie::SameSite::Lax)
                            .max_age(time::Duration::seconds(session.expires_in))
                            .secure(false)
                            .http_only(false)
                            .finish();
                        return to_response(session, &cookie);
                    }
                    Err(err) => warn!("Refresh token error: {}", err),
                }
            }
        }

        return to_response(session, cookie);
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
                    "assetPrefix": "https://cdn.oaistatic.com",
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
    mut headers: HeaderMap,
    jar: CookieJar,
    share_id: Path<String>,
) -> Result<Response<Body>, ResponseError> {
    let share_id = share_id.0;
    if let Some(cookie) = jar.get(SESSION_ID) {
        return match extract_session(cookie.value()) {
            Ok(session) => {
                set_auth_header(&mut headers, &session.access_token)?;
                let ctx = context::get_instance();
                let url = get_url();
                let resp = ctx
                    .client()
                    .get(format!("{url}/backend-api/share/{share_id}"))
                    .headers(header_convert(&headers, &jar).await?)
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
                                    "assetPrefix": "https://cdn.oaistatic.com",
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
                            "assetPrefix": "https://cdn.oaistatic.com",
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
    mut headers: HeaderMap,
    jar: CookieJar,
    share_id: Path<String>,
) -> Result<Response<Body>, ResponseError> {
    let share_id = share_id.0.replace(".json", "");
    if let Some(cookie) = jar.get(SESSION_ID) {
        if let Ok(session) = extract_session(cookie.value()) {
            set_auth_header(&mut headers, &session.access_token)?;
            let ctx = context::get_instance();
            let url = get_url();
            let resp = ctx
                .client()
                .get(format!("{url}/backend-api/share/{share_id}"))
                .headers(header_convert(&headers, &jar).await?)
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
    mut headers: HeaderMap,
    jar: CookieJar,
    share_id: Path<String>,
) -> Result<Response<Body>, ResponseError> {
    if let Some(cookie) = jar.get(SESSION_ID) {
        return match extract_session(cookie.value()) {
            Ok(session) => {
                set_auth_header(&mut headers, &session.access_token)?;
                let ctx = context::get_instance();
                let url = get_url();
                let resp = ctx
                    .client()
                    .get(format!("{url}/backend-api/share/{}", share_id.0))
                    .headers(header_convert(&headers, &jar).await?)
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
    let resp = context::get_instance()
        .client()
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
            "assetPrefix": "https://cdn.oaistatic.com",
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
    Session::from_str(cookie_value)
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
    let g_ctx = context::get_instance();
    if let Some(site_key) = g_ctx.cf_turnstile() {
        ctx.insert("site_key", &site_key.site_key);
    }
    if let Some(api_prefix) = g_ctx.api_prefix() {
        ctx.insert("api_prefix", api_prefix);
    }
    if let Some(arkose_endpoint) = g_ctx.arkose_endpoint() {
        ctx.insert("arkose_endpoint", arkose_endpoint)
    }
}

fn check_token(token: &str) -> Result<(), ResponseError> {
    let _ = crate::token::check(token).map_err(ResponseError::Unauthorized)?;
    Ok(())
}

fn get_url() -> &'static str {
    let ctx = context::get_instance();
    match ctx.api_prefix() {
        Some(api_prefix) => api_prefix,
        None => URL_CHATGPT_API,
    }
}

fn set_auth_header(headers: &mut HeaderMap, access_token: &str) -> Result<(), ResponseError> {
    headers.insert(
        header::AUTHORIZATION,
        header::HeaderValue::from_str(&format!("Bearer {access_token}"))
            .map_err(|err| ResponseError::BadRequest(anyhow!(err)))?,
    );
    Ok(())
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct ImageQuery {
    url: String,
    w: String,
    q: String,
}
