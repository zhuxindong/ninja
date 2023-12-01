use axum::http::{self, Request};
use axum::{middleware::Next, response::Response};
use http::header;

use crate::serve::error::{ProxyError, ResponseError};
use crate::serve::whitelist;
use crate::token;

/// Middleware to check if the request is in the whitelist
#[allow(dead_code)]
pub async fn whitelist_middleware<B>(
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, ResponseError> {
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
        _ => Err(ResponseError::Forbidden(ProxyError::AccessNotInWhitelist)),
    }
}
