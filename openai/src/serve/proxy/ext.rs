use std::str::FromStr;

use axum::body::Bytes;
use axum::extract::FromRequestParts;
use axum::headers::authorization::Bearer;
use axum::headers::Authorization;
use axum::response::{IntoResponse, Response};
use axum::TypedHeader;
use axum::{
    async_trait,
    extract::FromRequest,
    http::{self, Request},
};
use axum_extra::extract::CookieJar;
use http::header::CONTENT_TYPE;
use http::{header, Uri};

use crate::serve::error::ResponseError;

/// ChatGPT To API extension.
pub(super) struct ToApiExt {
    // Enable stream
    pub(super) stream: bool,
    // Mapper model
    pub(super) model: String,
}

pub(crate) struct ResponseExt {
    pub(super) to_api: Option<ToApiExt>,
    pub(crate) inner: reqwest::Response,
}

/// Extractor for request parts.
pub(crate) struct RequestExt {
    pub(crate) uri: Uri,
    pub(crate) method: http::Method,
    pub(crate) headers: http::HeaderMap,
    pub(crate) baerer: Option<TypedHeader<Authorization<Bearer>>>,
    pub(crate) jar: CookieJar,
    pub(crate) body: Option<Bytes>,
}

impl RequestExt {
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
        let (mut parts, body) = req.into_parts();

        // Extract the baerer token from the request.
        let baerer = match TypedHeader::from_request_parts(&mut parts, state)
            .await
            .map(|baerer: TypedHeader<Authorization<Bearer>>| baerer)
        {
            Ok(ok) => Some(ok),
            Err(_) => None,
        };

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

        Ok(RequestExt {
            uri: parts.uri,
            jar: CookieJar::from_headers(&parts.headers),
            method: parts.method,
            headers: parts.headers,
            baerer,
            body,
        })
    }
}
