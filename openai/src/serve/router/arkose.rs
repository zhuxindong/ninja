use crate::arkose::ArkoseToken;
use crate::arkose::Type;
use crate::context;
use crate::serve::err::ResponseError;
use crate::serve::router::STATIC_FILES;
use crate::serve::Launcher;
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
use std::collections::HashMap;

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
    body: Option<Form<HashMap<String, String>>>,
) -> Result<impl IntoResponse, ResponseError> {
    if let Some((_, v)) = STATIC_FILES
        .get()
        .expect("static file")
        .iter()
        .find(|(k, _v)| k.contains(uri.path()))
    {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, v.mime_type)
            .body(Body::from(v.data))
            .map_err(ResponseError::InternalServerError)?);
    }

    if uri
        .path()
        .eq("/fc/gt2/public_key/35536E1E-65B4-4D96-9D97-6ADB7EFF8147")
    {
        if let Ok(arkose_token) = ArkoseToken::new_from_context(Type::Chat).await {
            if arkose_token.success() {
                let target = serde_json::json!({
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
                    .body(Body::from(target.to_string()))
                    .map_err(ResponseError::InternalServerError)?);
            }
        }
    }

    headers.remove(header::CONNECTION);
    headers.remove(header::CONTENT_TYPE);
    headers.remove(header::CONTENT_LENGTH);

    let client = context::get_instance().load_client();

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
    }
    .map_err(ResponseError::InternalServerError)?;

    let mut builder = Response::builder().status(resp.status());
    for ele in resp.headers() {
        builder = builder.header(ele.0, ele.1);
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(ResponseError::InternalServerError)?;

    Ok(builder
        .body(Body::from(bytes))
        .map_err(ResponseError::InternalServerError)?)
}
