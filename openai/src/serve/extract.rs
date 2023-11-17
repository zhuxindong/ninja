use std::str::FromStr;

use axum::body::Bytes;
use axum::response::{IntoResponse, Response};
use axum::{
    async_trait,
    extract::FromRequest,
    http::{self, Request},
};
use axum_extra::extract::CookieJar;
use http::header::{self, CONTENT_TYPE};
use http::{HeaderMap, Method, Uri};
use serde_json::{json, Value};

use crate::arkose::Type;
use crate::{arkose, context};

use super::convert::header_convert;
use super::error::ResponseError;
use super::puid::{get_or_init_puid, reduce_cache_key};
use super::EMPTY;

/// Extractor for request parts.
pub(super) struct RequestExtractor {
    uri: Uri,
    method: http::Method,
    headers: http::HeaderMap,
    jar: CookieJar,
    body: Option<Bytes>,
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

#[async_trait]
pub(super) trait SendRequestExt {
    async fn send_request(
        &self,
        origin: &'static str,
        req: RequestExtractor,
    ) -> Result<reqwest::Response, ResponseError>;
}

#[async_trait]
impl SendRequestExt for reqwest::Client {
    async fn send_request(
        &self,
        origin: &'static str,
        mut req: RequestExtractor,
    ) -> Result<reqwest::Response, ResponseError> {
        // Build rqeuest path and query
        let path_and_query = req
            .uri
            .path_and_query()
            .map(|v| v.as_str())
            .unwrap_or(req.uri.path());
        // Build url
        let url = format!("{origin}{path_and_query}");

        // Handle request
        handle_request(&mut req).await?;

        // Handle dashboard request
        handle_dashboard_request(&mut req).await?;

        // Build request
        let mut builder =
            self.request(req.method, url)
                .headers(header_convert(&req.headers, &req.jar, origin)?);
        if let Some(body) = req.body {
            builder = builder.body(body);
        }
        // Send request
        Ok(builder.send().await?)
    }
}

/// Check if the request has puid
pub(super) fn has_puid(headers: &HeaderMap) -> Result<bool, ResponseError> {
    if let Some(hv) = headers.get(header::COOKIE) {
        let cookie_str = hv.to_str().map_err(ResponseError::BadRequest)?;
        Ok(cookie_str.contains("_puid"))
    } else {
        Ok(false)
    }
}

/// Extract token from Authorization header
fn extract_authorization<'a>(headers: &'a HeaderMap) -> Result<&'a str, ResponseError> {
    let token = match headers.get(header::AUTHORIZATION) {
        Some(v) => Some(v),
        None => headers.get("X-Authorization"),
    }
    .ok_or(ResponseError::Unauthorized(anyhow::anyhow!(
        "AccessToken required!"
    )))?
    .to_str()
    .map_err(ResponseError::BadGateway)?;
    Ok(token)
}

/// Handle request
async fn handle_request(req: &mut RequestExtractor) -> Result<(), ResponseError> {
    // Only handle POST request
    if !(req.uri.path().eq("/backend-api/conversation") && req.method.eq(&Method::POST)) {
        return Ok(());
    }

    // Handle empty body
    let body = req
        .body
        .as_ref()
        .ok_or(ResponseError::BadRequest(anyhow::anyhow!(
            "Body can not be empty!"
        )))?;

    // Use serde_json to parse body
    let mut json = serde_json::from_slice::<Value>(&body).map_err(ResponseError::BadRequest)?;
    let body = json
        .as_object_mut()
        .ok_or(ResponseError::BadRequest(anyhow::anyhow!("Body is empty")))?;

    // If model is not exist, then return error
    let model = body
        .get("model")
        .and_then(|m| m.as_str())
        .ok_or(ResponseError::BadRequest(anyhow::anyhow!(
            "Model is not exist in body!"
        )))?;

    // If puid is exist, then return
    if !has_puid(&req.headers)? {
        // extract token from Authorization header
        let token = extract_authorization(&req.headers)?;

        // Exstract the token from the Authorization header
        let cache_id = reduce_cache_key(token)?;

        // Get or init puid
        let puid = get_or_init_puid(token, model, cache_id).await?;

        if let Some(puid) = puid {
            req.headers.insert(
                header::COOKIE,
                header::HeaderValue::from_str(&format!("_puid={puid};"))
                    .map_err(ResponseError::BadRequest)?,
            );
        }
    }

    // Parse model
    let model = arkose::GPTModel::from_str(model).map_err(ResponseError::BadRequest)?;

    // If model is gpt3 or gpt4, then add arkose_token
    if (context::get_instance().arkose_gpt3_experiment() && model.is_gpt3()) || model.is_gpt4() {
        let condition = match body.get("arkose_token") {
            Some(s) => {
                let s = s.as_str().unwrap_or(EMPTY);
                s.is_empty() || s.eq("null")
            }
            None => true,
        };

        if condition {
            let arkose_token = arkose::ArkoseToken::new_from_context(model.into()).await?;
            body.insert("arkose_token".to_owned(), json!(arkose_token));
            // Updaye Modify bytes
            req.body = Some(Bytes::from(
                serde_json::to_vec(&json).map_err(ResponseError::BadRequest)?,
            ));
        }
    }

    drop(json);

    Ok(())
}

/// Handle dashboard request
async fn handle_dashboard_request(req: &mut RequestExtractor) -> Result<(), ResponseError> {
    // Only handle POST request
    if !req.uri.path().contains("/dashboard/user/api_keys") || !req.method.eq("POST") {
        return Ok(());
    }

    // Handle empty body
    let body = req
        .body
        .as_ref()
        .ok_or(ResponseError::BadRequest(anyhow::anyhow!(
            "Body can not be empty!"
        )))?;

    // Use serde_json to parse body
    let mut json = serde_json::from_slice::<Value>(&body).map_err(ResponseError::BadRequest)?;
    let body = json
        .as_object_mut()
        .ok_or(ResponseError::BadRequest(anyhow::anyhow!("Body is empty")))?;

    // If arkose_token is not exist, then add it
    if body.get("arkose_token").is_none() {
        let arkose_token = arkose::ArkoseToken::new_from_context(Type::Platform).await?;
        body.insert("arkose_token".to_owned(), json!(arkose_token));
        // Updaye Modify bytes
        req.body = Some(Bytes::from(
            serde_json::to_vec(&json).map_err(ResponseError::BadRequest)?,
        ));
    }

    drop(json);

    Ok(())
}
