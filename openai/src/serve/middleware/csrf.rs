use axum::{
    body::{self, BoxBody, Full},
    middleware::Next,
    response::Response,
    Form,
};
use axum_csrf::CsrfToken;
use http::{Method, Request, StatusCode};

use crate::{auth::model::AuthAccount, warn};

/// Can only be done with the feature layer enabled
pub async fn auth_middleware(
    token: CsrfToken,
    method: Method,
    mut request: Request<BoxBody>,
    next: Next<BoxBody>,
) -> Result<Response, StatusCode> {
    if method == Method::POST {
        let (parts, body) = request.into_parts();
        let bytes = hyper::body::to_bytes(body)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let value = serde_urlencoded::from_bytes(&bytes)
            .map_err(|_| -> StatusCode { StatusCode::INTERNAL_SERVER_ERROR })?;
        let payload: Form<AuthAccount> = Form(value);
        match payload.0.csrf_token {
            Some(csrf_token) => {
                if token.verify(&csrf_token).is_err() {
                    warn!("csrf token verify failed: {csrf_token}");
                    return Err(StatusCode::UNAUTHORIZED);
                }
            }
            None => {
                warn!("csrf token not found");
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        request = Request::from_parts(parts, body::boxed(Full::from(bytes)));
    }

    Ok(next.run(request).await)
}
