use std::str::FromStr;

use axum::http::{HeaderMap, Request};
use axum::{async_trait, extract::FromRequest};
use axum_extra::extract::CookieJar;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::constant::API_AUTH_SESSION_COOKIE_KEY;
use crate::debug;
use crate::token::TokenProfile;
use crate::{
    serve::{error::ResponseError, route::ui::LOGIN_INDEX, route::ui::SESSION_ID},
    token::model::Token,
};

#[derive(Serialize, Deserialize)]
pub(super) struct Session {
    pub access_token: String,
    pub refresh_token: Option<String>,
    #[serde(skip_serializing)]
    pub session_token: Option<String>,
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

impl From<Token> for Session {
    fn from(value: Token) -> Self {
        Session {
            user_id: value.user_id().to_owned(),
            email: value.email().to_owned(),
            expires: value.expires(),
            access_token: value.access_token().to_owned(),
            refresh_token: value.refresh_token().map(|v| v.to_owned()),
            session_token: value.session_token().map(|v| v.to_owned()),
        }
    }
}

impl From<(&str, TokenProfile)> for Session {
    fn from(value: (&str, TokenProfile)) -> Self {
        Session {
            user_id: value.1.user_id().to_owned(),
            email: value.1.email().to_owned(),
            expires: value.1.expires(),
            access_token: value.0.to_owned(),
            refresh_token: None,
            session_token: None,
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
impl<S, B> FromRequest<S, B> for SessionExtractor
where
    B: Send + 'static,
    S: Send + Sync,
{
    type Rejection = ResponseError;

    async fn from_request(req: Request<B>, _: &S) -> Result<Self, Self::Rejection> {
        let (parts, _) = req.into_parts().into();
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
        .map_err(|_| ResponseError::TempporaryRedirect(LOGIN_INDEX))
        .and_then(|session| match crate::token::check(&session.access_token) {
            Ok(_) => Ok(session),
            Err(err) => {
                debug!("Session token is invalid: {}", err);
                Err(ResponseError::TempporaryRedirect(LOGIN_INDEX))
            }
        })
}
