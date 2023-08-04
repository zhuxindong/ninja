use std::collections::HashMap;

use crate::serve::err::{self, ResponseError};
use crate::serve::{api_client, Launcher};
use axum::body::Body;
use axum::http::header;
use axum::http::method::Method;
use axum::http::Response;
use axum::http::StatusCode;
use axum::{
    http::{HeaderMap, Uri},
    routing::any,
    Form, Router,
};
use serde::{Deserialize, Serialize};

use super::STATIC_FILES;

pub(super) fn config(router: Router, args: &Launcher) -> Router {
    if args.arkose_endpoint.is_none() {
        return router
            .route("/cdn/*path", any(proxy))
            .route("/v2/*path", any(proxy))
            .route("/fc/*path", any(proxy));
    }
    router
}

#[derive(Serialize, Deserialize, Debug)]
struct ReqForm {
    bda: String,
    public_key: String,
    site: String,
    userbrowser: String,
    capi_version: String,
    capi_mode: String,
    style_theme: String,
    rnd: String,
}

async fn proxy(
    uri: Uri,
    method: Method,
    mut headers: HeaderMap,
    mut body: Option<Form<HashMap<String, String>>>,
) -> Result<Response<Body>, ResponseError> {
    let mut x = unsafe { STATIC_FILES.as_ref().unwrap().iter() };
    if let Some((_, v)) = x.find(|(k, _v)| k.contains(uri.path())) {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, v.mime_type)
            .body(Body::from(v.data))
            .map_err(|err| err::ResponseError::InternalServerError(err))?);
    }

    if uri
        .path()
        .eq("/fc/gt2/public_key/35536E1E-65B4-4D96-9D97-6ADB7EFF8147")
    {
        if let Some(body) = &mut body {
            if let Some(v) = body.get_mut("site") {
                if v.starts_with("http") {
                    *v = "http://localhost:3000".to_owned();
                }
            }
        }
    }

    headers.insert("Origin", "http://localhost:3000".parse().unwrap());
    headers.insert(
        "Referer",
        "http://localhost:3000/v2/1.5.4/enforcement.cd12da708fe6cbe6e068918c38de2ad9.html"
            .parse()
            .unwrap(),
    );
    headers.remove("Host");
    headers.remove("connection");
    headers.remove("Content-Type");
    headers.remove("Content-Length");
    headers.remove("Cf-Connecting-Ip");
    headers.remove("Cf-Ipcountry");
    headers.remove("Cf-Ray");
    headers.remove("Cf-Request-Id");
    headers.remove("Cf-Visitor");
    headers.remove("Cf-Warp-Tag-Id");
    headers.remove("Cf-Worker");
    headers.remove("Cf-Device-Type");
    headers.remove("Cf-Request-Id");
    headers.remove("X-Forwarded-Host");
    headers.remove("X-Forwarded-Proto");
    headers.remove("X-Forwarded-For");
    headers.remove("X-Forwarded-Port");
    headers.remove("X-Forwarded-Server");
    headers.remove("X-Real-Ip");

    let client = api_client();

    let url = format!("https://client-api.arkoselabs.com{}", uri.path());
    let resp = match body {
        Some(form) => {
            client
                .request(method, url)
                .headers(headers)
                .form(&form.0)
                .send()
                .await
        }
        None => client.request(method, url).headers(headers).send().await,
    };

    match resp {
        Ok(resp) => {
            let mut builder = Response::builder();
            for ele in resp.headers() {
                builder = builder.header(ele.0, ele.1);
            }
            let bytes = resp
                .bytes()
                .await
                .map_err(|err| err::ResponseError::InternalServerError(err))?;
            Ok(builder
                .status(StatusCode::OK)
                .body(Body::from(bytes))
                .map_err(|err| err::ResponseError::InternalServerError(err))?)
        }
        Err(err) => Ok(Response::builder()
            .status(err.status().unwrap())
            .body(Body::empty())
            .map_err(|err| err::ResponseError::InternalServerError(err))?),
    }
}
