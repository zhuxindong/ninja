use std::str::FromStr;

use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use axum_extra::extract::CookieJar;
use base64::Engine;
use http::HeaderMap;
use serde::{Deserialize, Serialize};

use crate::{
    auth::API_AUTH_SESSION_COOKIE_KEY,
    serve::{error::ResponseError, route::ui::SESSION_ID},
    token::model::AuthenticateToken,
};

const LOGIN_INDEX: &str = "/auth/login";

#[derive(Serialize, Deserialize)]
pub(super) struct Session {
    pub access_token: String,
    pub refresh_token: Option<String>,
    #[serde(skip_serializing)]
    pub auth_session: Option<String>,
    pub user_id: String,
    pub email: String,
    pub expires: i64,
}

impl ToString for Session {
    fn to_string(&self) -> String {
        let json = serde_json::to_string(self)
            .expect("An error occurred during the internal serialization session");
        base64::engine::general_purpose::STANDARD.encode(json.as_bytes())
    }
}

impl FromStr for Session {
    type Err = ResponseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = base64::engine::general_purpose::STANDARD
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
            access_token: value.access_token().to_owned(),
            expires: value.expires(),
            refresh_token: value.refresh_token().map(|v| v.to_owned()),
            auth_session: value.auth_session().map(|v| v.to_owned()),
        }
    }
}

pub(super) struct SessionExtractor {
    pub session: Session,
    pub session_token: Option<String>,
    pub headers: HeaderMap,
    pub jar: CookieJar,
}

#[async_trait]
impl<S> FromRequestParts<S> for SessionExtractor
where
    S: Send + Sync,
{
    type Rejection = ResponseError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        match jar.get(SESSION_ID) {
            Some(c) => {
                let session = extract_session(c.value())?;
                let session_token = jar
                    .get(API_AUTH_SESSION_COOKIE_KEY)
                    .map(|c| c.value().to_owned());
                Ok(SessionExtractor {
                    session,
                    session_token,
                    jar,
                    headers: parts.headers.clone(),
                })
            }
            None => Err(ResponseError::TempporaryRedirect(LOGIN_INDEX)),
        }
    }
}

fn extract_session(cookie_value: &str) -> Result<Session, ResponseError> {
    Session::from_str(cookie_value)
        .map_err(|_| ResponseError::Unauthorized(anyhow::anyhow!("invalid session")))
        .and_then(|session| match check_token(&session.access_token) {
            Ok(_) => Ok(session),
            Err(err) => Err(err),
        })
}

fn check_token(token: &str) -> Result<(), ResponseError> {
    let _ = crate::token::check(token).map_err(ResponseError::Unauthorized)?;
    Ok(())
}
