use axum::body::Bytes;
use axum::response::{IntoResponse, Response};
use axum::{
    async_trait,
    extract::FromRequest,
    http::{self, Request},
};
use axum_extra::extract::CookieJar;
use http::header::{self, CONTENT_TYPE};
use http::Uri;
use std::str::FromStr;

use super::error::ResponseError;

/// Extractor for request parts.
pub(super) struct RequestExtractor {
    pub(super) uri: Uri,
    pub(super) method: http::Method,
    pub(super) headers: http::HeaderMap,
    pub(super) jar: CookieJar,
    pub(super) body: Option<Bytes>,
}

impl RequestExtractor {
    pub(super) fn trim_start_path(&mut self, path: &str) -> Result<(), ResponseError> {
        let path_and_query = self
            .uri
            .path_and_query()
            .map(|v| v.as_str())
            .unwrap_or(self.uri.path());
        let path = path_and_query.trim_start_matches(path);
        self.uri = Uri::from_str(path).map_err(ResponseError::BadRequest)?;
        Ok(())
    }

    pub(super) fn append_haeder(
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
}

#[async_trait]
impl<S, B> FromRequest<S, B> for RequestExtractor
where
    Bytes: FromRequest<S, B>,
    B: Send + 'static,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();

        let body = if parts
            .headers
            .get(CONTENT_TYPE)
            .filter(|&value| {
                value.eq(mime::APPLICATION_JSON.as_ref())
                    || value.eq(mime::APPLICATION_JAVASCRIPT.as_ref())
                    || value.eq(mime::APPLICATION_JAVASCRIPT_UTF_8.as_ref())
                    || value.eq(mime::APPLICATION_OCTET_STREAM.as_ref())
                    || value.eq(mime::APPLICATION_MSGPACK.as_ref())
                    || value.eq(mime::APPLICATION_PDF.as_ref())
                    || value.eq(mime::APPLICATION_WWW_FORM_URLENCODED.as_ref())
                    || value.eq(mime::MULTIPART_FORM_DATA.as_ref())
                    || value.is_empty()
            })
            .is_some()
        {
            let request = Request::new(body);
            let bytes = Bytes::from_request(request, state)
                .await
                .map_err(IntoResponse::into_response)?;
            Some(bytes)
        } else {
            None
        };

        Ok(RequestExtractor {
            uri: parts.uri,
            method: parts.method,
            jar: CookieJar::from_headers(&parts.headers),
            headers: parts.headers,
            body,
        })
    }
}
