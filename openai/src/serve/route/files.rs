use axum::{response::IntoResponse, routing::any, Router};
use http::header;

use crate::{
    context,
    serve::{
        error::ResponseError, extract::RequestExtractor, req::SendRequestExt,
        resp::response_convert,
    },
};

/// file endpoint proxy
pub(super) fn config(router: Router) -> Router {
    router.route("/files/*path", any(proxy))
}

async fn proxy(mut req: RequestExtractor) -> Result<impl IntoResponse, ResponseError> {
    req.trim_start_path("/files")?;
    req.append_haeder(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")?;
    let resp = context::get_instance()
        .client()
        .send_request("https://files.oaiusercontent.com", req)
        .await?;
    response_convert(resp).await
}
