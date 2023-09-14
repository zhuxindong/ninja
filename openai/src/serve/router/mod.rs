use std::collections::HashMap;
use std::sync::OnceLock;

use axum::http::header;
use axum::http::StatusCode;
use axum::{body::Body, extract::Path, http::Response, Router};

use super::{err::ResponseError, Launcher};

mod arkose;
mod har;
pub(super) mod toapi;
mod ui;

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

static STATIC_FILES: OnceLock<HashMap<&'static str, static_files::Resource>> = OnceLock::new();

pub(super) fn config(router: Router, args: &Launcher) -> Router {
    init_static_files();
    let router = ui::config(router, args);
    let router = arkose::config(router, args);
    let router = har::config(router, args);
    router
}

fn init_static_files() {
    STATIC_FILES.get_or_init(|| generate());
}

async fn get_static_resource(path: Path<String>) -> Result<Response<Body>, ResponseError> {
    let path = path.0;
    let mut static_files = STATIC_FILES.get().expect("static file not init").iter();
    match static_files.find(|(k, _v)| k.contains(&path)) {
        Some((_, v)) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, v.mime_type)
            .body(Body::from(v.data))
            .map_err(ResponseError::InternalServerError)?),
        None => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .map_err(ResponseError::InternalServerError)?),
    }
}
