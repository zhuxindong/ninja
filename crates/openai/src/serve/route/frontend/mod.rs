use std::collections::HashMap;
use tokio::sync::OnceCell;

use axum::http::header;
use axum::http::StatusCode;
use axum::{body::Body, extract::Path, http::Response, Router};

use crate::context::args::Args;
use crate::serve::error::ResponseError;

mod chat;
mod har;

pub(super) fn config(router: Router, args: &Args) -> Router {
    let router = har::config(router, args);
    let router = chat::config(router, args);
    router
}

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// Build-in static files
static STATIC_FILES: OnceCell<HashMap<&'static str, static_files::Resource>> =
    OnceCell::const_new();

/// Get static resource
async fn get_static_resource(path: Path<String>) -> Result<Response<Body>, ResponseError> {
    let path = path.0;
    let mut static_files = STATIC_FILES
        .get_or_init(|| async { generate() })
        .await
        .iter();
    match static_files.find(|(k, _)| k.contains(&path)) {
        Some((_, v)) => {
            let mime_type = if v.mime_type.eq(mime::APPLICATION_OCTET_STREAM.as_ref()) {
                mime::TEXT_HTML.as_ref()
            } else {
                v.mime_type
            };
            create_response_with_data(StatusCode::OK, mime_type, v.data)
        }
        None => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .map_err(ResponseError::InternalServerError)?),
    }
}

fn create_response_with_data(
    status: StatusCode,
    content_type: &str,
    data: impl Into<Body>,
) -> Result<Response<Body>, ResponseError> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header("Access-Control-Allow-Credentials", "true")
        .header("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,PATCH,HEAD,CONNECT,OPTIONS,TRACE")
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "Origin,Content-Type,Accept,User-Agent,Cookie,Authorization,X-Auth-Token,X-Requested-With")
        .header("Access-Control-Max-Age", "3628800")
        .header(header::CONTENT_SECURITY_POLICY, "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: *.arkoselabs.com *.funcaptcha.com *.arkoselabs.cn *.arkose.com.cn *.chat.openai.com;")
        .body(data.into())
        .map_err(ResponseError::InternalServerError)
}
