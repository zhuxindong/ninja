use std::str::FromStr;

use axum::body::Bytes;
use axum::response::{IntoResponse, Response};
use axum::{
    async_trait,
    extract::FromRequest,
    http::{self, Request},
};
use axum_extra::extract::CookieJar;
use http::header::CONTENT_TYPE;
use http::{header, Uri};
use typed_builder::TypedBuilder;

use crate::serve::error::ResponseError;

/// Context extension.
#[derive(TypedBuilder)]
pub(crate) struct ContextExt {
    // Enable stream
    pub(crate) stream: bool,
    // Mapper model
    pub(crate) model: String,
}

/// Response extension.
#[derive(TypedBuilder)]
pub(crate) struct ResponseExt {
    #[builder(setter(into), default)]
    pub(crate) context: Option<ContextExt>,
    pub(crate) inner: reqwest::Response,
}

/// Extractor for request parts.
pub(crate) struct RequestExt {
    pub(crate) uri: Uri,
    pub(crate) method: http::Method,
    pub(crate) headers: http::HeaderMap,
    pub(crate) jar: CookieJar,
    pub(crate) body: Option<Bytes>,
}

impl RequestExt {
    /// Trim start path.
    pub(crate) fn trim_start_path(&mut self, path: &str) -> Result<(), ResponseError> {
        let path_and_query = self
            .uri
            .path_and_query()
            .map(|v| v.as_str())
            .unwrap_or(self.uri.path());
        let path = path_and_query.trim_start_matches(path);
        self.uri = Uri::from_str(path).map_err(ResponseError::BadRequest)?;
        Ok(())
    }

    /// Append header.
    pub(crate) fn append_haeder(
        &mut self,
        name: header::HeaderName,
        value: &str,
    ) -> Result<(), ResponseError> {
        self.headers.insert(
            name,
            header::HeaderValue::from_str(value).map_err(ResponseError::BadRequest)?,
        );
        Ok(())
    }

    /// Get bearer auth.
    pub(crate) fn bearer_auth(&self) -> Option<&str> {
        let mut value = self.headers.get_all(header::AUTHORIZATION).iter();
        let is_missing = value.size_hint() == (0, Some(0));
        if is_missing {
            return None;
        }

        value.find_map(|v| {
            v.to_str().ok().and_then(|s| {
                let parts: Vec<&str> = s.split_whitespace().collect();
                match parts.as_slice() {
                    ["Bearer", token] => Some(*token),
                    _ => None,
                }
            })
        })
    }
}

#[async_trait]
pub(crate) trait SendRequestExt {
    async fn send_request(
        &self,
        origin: &'static str,
        req: RequestExt,
    ) -> Result<ResponseExt, ResponseError>;
}

#[async_trait]
impl<S, B> FromRequest<S, B> for RequestExt
where
    Bytes: FromRequest<S, B>,
    B: Send + 'static,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();

        let body = if parts.headers.get(CONTENT_TYPE).is_some() {
            Some(
                Bytes::from_request(Request::new(body), state)
                    .await
                    .map_err(IntoResponse::into_response)?,
            )
        } else {
            None
        };

        Ok(RequestExt {
            uri: parts.uri,
            jar: CookieJar::from_headers(&parts.headers),
            method: parts.method,
            headers: parts.headers,
            body,
        })
    }
}
