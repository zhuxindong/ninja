use std::collections::HashMap;

use crate::serve::err::{self, ResponseError};
use crate::serve::{context, Launcher};
use axum::body::Body;
use axum::http::header;
use axum::http::method::Method;
use axum::http::Response;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{
    http::{HeaderMap, Uri},
    routing::any,
    Form, Router,
};

pub(super) fn config(router: Router, args: &Launcher) -> Router {
    if args.arkose_endpoint.is_none() {
        return router
            .route("/cdn/*path", any(proxy))
            .route("/v2/*path", any(proxy))
            .route("/fc/*path", any(proxy));
    }
    router
}

async fn proxy(
    uri: Uri,
    method: Method,
    mut headers: HeaderMap,
    mut body: Option<Form<HashMap<String, String>>>,
) -> Result<impl IntoResponse, ResponseError> {
    let mut x = unsafe { super::STATIC_FILES.as_ref().unwrap().iter() };
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
        let env = context::ENV_HOLDER.get_instance();
        if let Ok(arkose_token) = env.get_arkose_token().await {
            let body = serde_json::json!({
                "token": arkose_token,
                "challenge_url":"",
                "challenge_url_cdn":"https://client-api.arkoselabs.com/cdn/fc/assets/ec-game-core/bootstrap/1.14.1/standard/game_core_bootstrap.js",
                "challenge_url_cdn_sri":null,
                "noscript":"Disable",
                "inject_script_integrity":null,
                "inject_script_url":null,
                "mbio":true,
                "tbio":true,
                "kbio":true,
                "styles":null,
                "iframe_width":null,
                "iframe_height":null,
                "disable_default_styling":false,
                "string_table":{
                    "meta.api_timeout_error":"与验证服务器的连接已中断。请重新加载挑战以重试。",
                    "meta.generic_error":"出错了。请重新加载挑战以重试。",
                    "meta.loading_info":"进行中，请稍候...",
                    "meta.reload_challenge":"重新加载挑战",
                    "meta.visual_challenge_frame_title":"视觉挑战"
                }
            });

            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(body.to_string()))
                .map_err(|err| ResponseError::InternalServerError(err))?);
        }

        if let Some(body) = &mut body {
            if let Some(v) = body.get_mut("site") {
                if v.starts_with("http") {
                    *v = "http://localhost:3000".to_owned();
                }
            }
        }
    }

    headers.insert(header::ORIGIN, "http://localhost:3000".parse().unwrap());
    headers.insert(
        header::REFERER,
        "http://localhost:3000/v2/1.5.4/enforcement.cd12da708fe6cbe6e068918c38de2ad9.html"
            .parse()
            .unwrap(),
    );
    headers.remove(header::HOST);
    headers.remove(header::CONNECTION);
    headers.remove(header::CONTENT_TYPE);
    headers.remove(header::CONTENT_LENGTH);
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

    let client = context::ENV_HOLDER.get_instance().load_client();

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
