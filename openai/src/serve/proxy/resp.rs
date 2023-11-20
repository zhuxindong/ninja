use std::time::UNIX_EPOCH;

use crate::with_context;
use crate::{debug, LIB_VERSION};
use axum::body::Body;
use axum::body::StreamBody;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::{cookie, CookieJar};
use reqwest::header::HeaderMap;
use serde_json::Value;

use crate::serve::error::ResponseError;

use super::ext::ResponseExt;
use super::toapi;

/// Request headers convert
pub(crate) fn header_convert(
    h: &HeaderMap,
    jar: &CookieJar,
    origin: &'static str,
) -> Result<HeaderMap, ResponseError> {
    let mut headers = HeaderMap::new();

    h.get("Access-Control-Request-Headers")
        .map(|h| headers.insert("Access-Control-Request-Headers", h.clone()));

    h.get("Access-Control-Request-Method").map(|h| {
        headers.insert("Access-Control-Request-Method", h.clone());
    });

    h.get("X-Ms-Blob-Type")
        .map(|v| headers.insert("X-Ms-Blob-Type", v.clone()));

    h.get("X-Ms-Version")
        .map(|v| headers.insert("X-Ms-Version", v.clone()));

    h.get(header::AUTHORIZATION)
        .map(|h| headers.insert(header::AUTHORIZATION, h.clone()));

    h.get(header::CONTENT_TYPE)
        .map(|h| headers.insert(header::CONTENT_TYPE, h.clone()));

    h.get(header::DNT)
        .map(|v| headers.insert(header::DNT, v.clone()));

    headers.insert(header::ORIGIN, header::HeaderValue::from_static(origin));
    headers.insert(header::REFERER, header::HeaderValue::from_static(origin));

    let mut cookies = Vec::new();

    jar.iter()
        .filter(|c| {
            let name = c.name().to_lowercase();
            name.eq("_puid") || name.eq("cf_clearance")
        })
        .for_each(|c| {
            let c = format!("{}={}", c.name(), cookie_encoded(c.value()));
            debug!("cookie: {}", c);
            cookies.push(c);
        });

    // setting cookie
    if !cookies.is_empty() {
        headers.insert(
            header::COOKIE,
            header::HeaderValue::from_str(&cookies.join(";")).expect("setting cookie error"),
        );
    }
    Ok(headers)
}

/// Response convert
pub(crate) async fn response_convert(
    resp: ResponseExt,
) -> Result<impl IntoResponse, ResponseError> {
    // If to api is some, then convert to api response
    if resp.to_api.is_some() {
        return Ok(toapi::response_convert(resp).await?.into_response());
    }

    let status = resp.inner.status();
    let mut builder = Response::builder()
        .status(status)
        .header("ninja-version", LIB_VERSION);

    // Copy headers except for "set-cookie"
    for kv in resp
        .inner
        .headers()
        .into_iter()
        .filter(|(k, _)| k.as_str().to_lowercase().ne("set-cookie"))
    {
        builder = builder.header(kv.0, kv.1);
    }

    // Filter and transform cookies
    for cookie in resp.inner.cookies() {
        let name = cookie.name().to_lowercase();
        if name == "_puid" || name == "cf_clearance" {
            if let Some(expires) = cookie.expires() {
                let timestamp_secs = expires
                    .duration_since(UNIX_EPOCH)
                    .expect("Failed to get timestamp")
                    .as_secs_f64();
                let cookie = Cookie::build(cookie.name(), cookie.value())
                    .path("/")
                    .max_age(time::Duration::seconds_f64(timestamp_secs))
                    .same_site(cookie::SameSite::Lax)
                    .secure(false)
                    .http_only(false)
                    .finish();
                builder = builder.header(header::SET_COOKIE, cookie.to_string());
            }
        }
    }

    // Modify files endpoint response
    if with_context!(enable_file_proxy) && resp.inner.url().path().contains("/backend-api/files") {
        let url = resp.inner.url().clone();
        // Files endpoint handling
        let mut json = resp
            .inner
            .json::<Value>()
            .await
            .map_err(ResponseError::BadRequest)?;

        let body_key = if url.path().contains("download") || url.path().contains("uploaded") {
            "download_url"
        } else {
            "upload_url"
        };

        if let Some(download_upload_url) = json.get_mut(body_key) {
            if let Some(download_url_str) = download_upload_url.as_str() {
                const FILES_ENDPOINT: &str = "https://files.oaiusercontent.com";
                if download_url_str.starts_with(FILES_ENDPOINT) {
                    *download_upload_url =
                        serde_json::json!(download_url_str.replace(FILES_ENDPOINT, "/files"));
                }
            }
        }

        let json_bytes = serde_json::to_vec(&json)?;
        Ok(builder
            .body(Body::from(json_bytes))
            .map_err(ResponseError::InternalServerError)?
            .into_response())
    } else {
        // Non-files endpoint handling
        Ok(builder
            .body(StreamBody::new(resp.inner.bytes_stream()))
            .map_err(ResponseError::InternalServerError)?
            .into_response())
    }
}

fn cookie_encoded(input: &str) -> String {
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
