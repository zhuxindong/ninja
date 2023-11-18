use axum::{response::IntoResponse, routing::any, Router};
use http::header;

use crate::{
    context::ContextArgs,
    serve::{
        error::ResponseError, extract::RequestExtractor, req::SendRequestExt,
        resp::response_convert,
    },
    with_context,
};

/// file endpoint proxy
pub(super) fn config(router: Router, args: &ContextArgs) -> Router {
    if args.enable_file_proxy {
        router.route("/files/*path", any(proxy))
    } else {
        router
    }
}

async fn proxy(mut req: RequestExtractor) -> Result<impl IntoResponse, ResponseError> {
    req.trim_start_path("/files")?;
    req.append_haeder(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")?;
    let resp = with_context!(client)
        .send_request("https://files.oaiusercontent.com", req)
        .await?;
    response_convert(resp).await
}
