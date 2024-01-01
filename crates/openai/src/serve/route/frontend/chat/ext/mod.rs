pub mod session;

use axum::body::HttpBody;
use axum::http::{header, HeaderMap, Method, Request, Uri};
use axum::{async_trait, extract::FromRequest};
use axum::{BoxError, Form};
use axum_extra::extract::CookieJar;
use serde::de::DeserializeOwned;
use std::str::FromStr;

use self::session::Session;
use super::{LOGIN_INDEX, SESSION_ID};
use crate::constant::API_AUTH_SESSION_COOKIE_KEY;
use crate::debug;
use crate::serve::error::ResponseError;

/// ChatGPT session Extension
pub struct SessionExt {
    pub session: Session,
    pub session_token: Option<String>,
    pub headers: HeaderMap,
    pub jar: CookieJar,
}

/// Arkose session Extension
pub struct ArkoseSessionExt<T: DeserializeOwned> {
    pub uri: Uri,
    pub method: Method,
    pub headers: HeaderMap,
    pub session: Option<Session>,
    pub body: Option<Form<T>>,
}

#[async_trait]
impl<S, B> FromRequest<S, B> for SessionExt
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
                Ok(SessionExt {
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

#[async_trait]
impl<S, B, T> FromRequest<S, B> for ArkoseSessionExt<T>
where
    T: DeserializeOwned,
    B: Send + 'static,
    S: Send + Sync,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Rejection = ResponseError;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        // Try to extract session from cookie
        let session = CookieJar::from_headers(&req.headers())
            .get(SESSION_ID)
            .map(|v| extract_session(v.value()))
            .map(|v| v.ok())
            .flatten();

        let uri = req.uri().clone();
        let method = req.method().clone();
        let headers = req.headers().clone();

        // Try to extract body if content type is form
        let body = if let Some(v) = headers.get(header::CONTENT_TYPE) {
            if v.eq(mime::APPLICATION_WWW_FORM_URLENCODED.as_ref()) {
                Form::from_request(req, state)
                    .await
                    .map_or(None, |v| Some(v))
            } else {
                None
            }
        } else {
            None
        };

        Ok(ArkoseSessionExt {
            uri,
            method,
            headers,
            session,
            body,
        })
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
