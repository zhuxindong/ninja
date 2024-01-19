use std::collections::HashMap;

use crate::arkose::ArkoseToken;
use crate::arkose::Type;
use crate::context::args::Args;
use crate::serve::error::ResponseError;
use crate::serve::route::frontend::get_static_resource;
use crate::warn;
use crate::with_context;
use axum::body::Body;
use axum::body::StreamBody;
use axum::extract::Path;
use axum::http::header;
use axum::http::Response;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{routing::any, Router};

use super::session::ArkoseSessionExt;

pub(super) fn config(router: Router, args: &Args) -> Router {
    // Enable arkose endpoint proxy
    if args.arkose_endpoint.is_none() {
        return router
            .route("/cdn/*path", any(proxy))
            .route("/v2/*path", any(proxy))
            .route("/fc/*path", any(proxy));
    }
    router
}

async fn proxy(
    mut s: ArkoseSessionExt<HashMap<String, String>>,
) -> Result<impl IntoResponse, ResponseError> {
    let req_path = s
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or(s.uri.path());

    // try to get static resource
    if let Ok(resp) = get_static_resource(Path(req_path.to_owned())).await {
        if resp.status().is_success() {
            return Ok(resp.into_response());
        }
    }

    if req_path.contains("/fc/gt2/public_key/") {
        let pk = req_path.trim_start_matches("/fc/gt2/public_key/");
        match ArkoseToken::new_from_context(Type::from_pk(pk)?, s.session.map(|s| s.access_token))
            .await
        {
            Ok(arkose_token) => {
                if arkose_token.success() {
                    let target = serde_json::json!({
                        "token": arkose_token.value(),
                        "challenge_url":"",
                        "challenge_url_cdn":"/cdn/fc/assets/ec-game-core/bootstrap/1.17.1/standard/game_core_bootstrap.js",
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
        s.headers.remove(header);
    }

    let url = format!("https://tcr9i.chat.openai.com{req_path}");

    let resp = match s.body {
        Some(form) => {
            with_context!(arkose_client)
                .request(s.method, url)
                .headers(s.headers)
                .form(&form.0)
                .send()
                .await
        }
        None => {
            with_context!(arkose_client)
                .request(s.method, url)
                .headers(s.headers)
                .send()
                .await
        }
    }
    .map_err(ResponseError::InternalServerError)?;

    Ok(create_response(resp)?.into_response())
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

fn create_response(resp: reqwest::Response) -> Result<impl IntoResponse, ResponseError> {
    let mut builder = Response::builder().status(resp.status());
    // Copy headers
    for ele in resp.headers() {
        builder = builder.header(ele.0, ele.1);
    }
    Ok(builder
        .body(StreamBody::new(resp.bytes_stream()))
        .map_err(ResponseError::InternalServerError)?)
}
