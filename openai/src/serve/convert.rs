use std::time::UNIX_EPOCH;

use crate::{debug, LIB_VERSION};
use axum::body::StreamBody;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::{cookie, CookieJar};
use reqwest::header::HeaderMap;

use super::error::ResponseError;

/// Request headers convert
pub(super) fn header_convert(
    h: &HeaderMap,
    jar: &CookieJar,
    origin: &'static str,
) -> Result<HeaderMap, ResponseError> {
    let authorization = match h.get(header::AUTHORIZATION) {
        Some(v) => Some(v),
        // support Pandora WebUI passing X-Authorization header
        None => h.get("X-Authorization"),
    };

    let mut headers = HeaderMap::new();
    if let Some(h) = authorization {
        headers.insert(header::AUTHORIZATION, h.clone());
    }
    if let Some(content_type) = h.get(header::CONTENT_TYPE) {
        headers.insert(header::CONTENT_TYPE, content_type.clone());
    }
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
pub(super) fn response_convert(
    resp: reqwest::Response,
) -> Result<impl IntoResponse, ResponseError> {
    let mut builder = Response::builder()
        .status(resp.status())
        .header("ninja-version", LIB_VERSION);
    for kv in resp
        .headers()
        .into_iter()
        .filter(|(k, _)| k.as_str().to_lowercase().ne("set-cookie"))
    {
        builder = builder.header(kv.0, kv.1);
    }

    for c in resp
        .cookies()
        .filter(|c| {
            let name = c.name().to_lowercase();
            name.eq("_puid") || name.eq("cf_clearance")
        })
        .into_iter()
    {
        if let Some(expires) = c.expires() {
            let timestamp_secs = expires
                .duration_since(UNIX_EPOCH)
                .expect("Failed to get timestamp")
                .as_secs_f64();
            let cookie = Cookie::build(c.name(), c.value())
                .path("/")
                .max_age(time::Duration::seconds_f64(timestamp_secs))
                .same_site(cookie::SameSite::Lax)
                .secure(false)
                .http_only(false)
                .finish();
            builder = builder.header(axum::http::header::SET_COOKIE, cookie.to_string());
        }
    }
    Ok(builder
        .body(StreamBody::new(resp.bytes_stream()))
        .map_err(ResponseError::InternalServerError)?)
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
