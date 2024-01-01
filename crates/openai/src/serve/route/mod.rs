mod files;
mod frontend;

use crate::context::args::Args;
use axum::Router;

pub(super) fn config(router: Router, args: &Args) -> Router {
    let router = files::config(router, args);
    let router = frontend::config(router, args);
    router
}
