use axum::http::header;
use axum::{response::IntoResponse, routing::any, Router};

use crate::{
    context::args::Args,
    serve::{
        error::ResponseError, proxy::ext::RequestExt, proxy::ext::SendRequestExt,
        proxy::resp::response_convert,
    },
    with_context,
};

/// file endpoint proxy
pub(super) fn config(router: Router, args: &Args) -> Router {
    if args.enable_file_proxy {
        router.route("/files/*path", any(proxy))
    } else {
        router
    }
}

async fn proxy(mut req: RequestExt) -> Result<impl IntoResponse, ResponseError> {
    req.trim_start_path("/files")?;
    req.append_haeder(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")?;
    let resp = with_context!(api_client)
        .send_request("https://files.oaiusercontent.com", req)
        .await?;
    response_convert(resp).await
}
