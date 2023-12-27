use super::STATIC_FILES;
use crate::arkose;
use crate::arkose::ArkoseToken;
use crate::arkose::Type;
use crate::context::args::Args;
use crate::serve::error::ResponseError;
use crate::warn;
use crate::with_context;
use axum::body::Body;
use axum::body::StreamBody;
use axum::extract::Path;
use axum::http::header;
use axum::http::method::Method;
use axum::http::response::Builder;
use axum::http::Response;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Json;
use axum::{http::Uri, routing::any, Form, Router};
use hyper::HeaderMap;
use std::collections::HashMap;

pub(super) fn config(router: Router, args: &Args) -> Router {
    // Enable arkose token endpoint proxy
    let router = if args.enable_arkose_proxy {
        router.route("/arkose_token/:path", get(get_arkose_token))
    } else {
        router
    };

    // Enable arkose endpoint proxy
    if args.arkose_endpoint.is_none() {
        return router
            .route("/cdn/*path", any(proxy))
            .route("/v2/*path", any(proxy))
            .route("/fc/*path", any(proxy));
    }
    router
}

/// GET /arkose_token/:path
/// Example: /arkose_token/35536E1E-65B4-4D96-9D97-6ADB7EFF8147
async fn get_arkose_token(pk: Path<String>) -> Result<Json<ArkoseToken>, ResponseError> {
    let typed = arkose::Type::from_pk(pk.as_str()).map_err(ResponseError::BadRequest)?;
    ArkoseToken::new_from_context(typed)
        .await
        .map(Json)
        .map_err(ResponseError::ExpectationFailed)
}

async fn proxy(
    uri: Uri,
    method: Method,
    mut headers: HeaderMap,
    body: Option<Form<HashMap<String, String>>>,
) -> Result<impl IntoResponse, ResponseError> {
    let req_path = uri.path();

    if let Some((_, v)) = STATIC_FILES
        .get()
        .expect("static file")
        .iter()
        .find(|(k, _v)| k.contains(req_path))
    {
        let mime_type = if v.mime_type.eq(mime::APPLICATION_OCTET_STREAM.as_ref()) {
            mime::TEXT_HTML.as_ref()
        } else {
            v.mime_type
        };
        return Ok(create_response_with_data(StatusCode::OK, mime_type, v.data).into_response());
    }

    if req_path.contains("/fc/gt2/public_key/") {
        let pk = req_path.trim_start_matches("/fc/gt2/public_key/");
        match ArkoseToken::new_from_context(Type::from_pk(pk)?).await {
            Ok(arkose_token) => {
                if arkose_token.success() {
                    let target = serde_json::json!({
                        "token": arkose_token.value(),
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
                    return Ok(create_response_with_data(
                        StatusCode::OK,
                        mime::APPLICATION_JSON.as_ref(),
                        target.to_string(),
                    )
                    .into_response());
                }
            }
            Err(err) => {
                warn!("ArkoseToken::new_from_context error: {}", err);
            }
        }
    }

    for header in &[
        header::CONNECTION,
        header::CONTENT_LENGTH,
        header::ACCEPT,
        header::ACCEPT_ENCODING,
        header::HOST,
    ] {
        headers.remove(header);
    }

    let client = with_context!(arkose_client);
    let url = format!("https://client-api.arkoselabs.com{}", req_path);

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

    Ok(create_response(builder, resp)?.into_response())
}

fn create_response_with_data(
    status: StatusCode,
    content_type: &str,
    data: impl Into<Body>,
) -> Result<Response<Body>, ResponseError> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(data.into())
        .map_err(ResponseError::InternalServerError)
}

fn create_response(
    builder: Builder,
    resp: reqwest::Response,
) -> Result<impl IntoResponse, ResponseError> {
    let resp = builder
        .body(StreamBody::new(resp.bytes_stream()))
        .map_err(ResponseError::InternalServerError)?;
    Ok(resp)
}
