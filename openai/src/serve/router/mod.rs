use std::{collections::HashMap, sync::Once};

use axum::http::header;
use axum::http::StatusCode;
use axum::{body::Body, extract::Path, http::Response, Router};

use super::{
    err::{self, ResponseError},
    Launcher,
};

mod arkose;
mod har;
pub(super) mod toapi;
mod ui;

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

static INIT: Once = Once::new();
static mut STATIC_FILES: Option<HashMap<&'static str, static_files::Resource>> = None;

pub(super) fn config(router: Router, args: &Launcher) -> Router {
    init_static_files();
    let router = ui::config(router, args);
    let router = arkose::config(router, args);
    let router = har::config(router, args);
    router
}

fn init_static_files() {
    INIT.call_once(|| {
        let generated_files = generate();
        unsafe {
            STATIC_FILES = Some(generated_files);
        }
    });
}

async fn get_static_resource(path: Path<String>) -> Result<Response<Body>, ResponseError> {
    let path = path.0;
    let mut x = unsafe { STATIC_FILES.as_ref().unwrap().iter() };
    match x.find(|(k, _v)| k.contains(&path)) {
        Some((_, v)) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, v.mime_type)
            .body(Body::from(v.data))
            .map_err(|err| err::ResponseError::InternalServerError(err))?),
        None => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .map_err(|err| err::ResponseError::InternalServerError(err))?),
    }
}
