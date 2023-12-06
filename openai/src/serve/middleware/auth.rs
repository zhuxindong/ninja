use crate::serve::error::{ProxyError, ResponseError};
use crate::serve::whitelist;
use crate::token;
use axum::http::header;
use axum::{http::Request, middleware::Next, response::Response};

pub(crate) async fn auth_middleware<B>(
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, ResponseError> {
    // Allow access to the public folder
    if ["/backend-api/public", "/backend-api/o11y/v1/traces"]
        .iter()
        .any(|v| request.uri().path().contains(*v))
    {
        return Ok(next.run(request).await);
    };

    // Check if the request has an authorization header
    let token = match request.headers().get(header::AUTHORIZATION) {
        Some(token) => token,
        None => return Err(ResponseError::Unauthorized(ProxyError::AccessTokenRequired)),
    };

    // Check if the token is valid
    match token::check_for_u8(token.as_bytes()) {
        Ok(Some(profile)) => {
            whitelist::check_whitelist(profile.email())?;
            Ok(next.run(request).await)
        }
        Ok(None) => {
            // for now, we don't allow anonymous access
            Ok(next.run(request).await)
        }
        Err(err) => Err(ResponseError::Forbidden(err)),
    }
}
