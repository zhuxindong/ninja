#[cfg(feature = "limit")]
pub mod tokenbucket;

use anyhow::anyhow;
use axum::http::header;
use axum::{http::Request, middleware::Next, response::Response};

use super::err::ResponseError;

pub(super) async fn token_authorization_middleware<B>(
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, ResponseError> {
    let ok = ["/backend-api/public/plugins/by-id"];

    if let Some(_) = ok.iter().find(|v| request.uri().path().contains(*v)) {
        return Ok(next.run(request).await);
    };

    let authorization = request.headers().get(header::AUTHORIZATION);

    match authorization {
        Some(token) => match crate::token::check_for_u8(token.as_bytes()) {
            Ok(_) => Ok(next.run(request).await),
            Err(err) => Err(ResponseError::Unauthorized(err)),
        },
        None => Err(ResponseError::Unauthorized(anyhow!(
            "access_token is required!"
        ))),
    }
}

#[cfg(feature = "limit")]
use tokenbucket::{TokenBucket, TokenBucketLimitContext};

#[cfg(feature = "limit")]
pub(super) async fn token_bucket_limit_middleware<B>(
    axum::extract::State(limit): axum::extract::State<std::sync::Arc<TokenBucketLimitContext>>,
    axum::extract::ConnectInfo(socket_addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, ResponseError> {
    let addr = socket_addr.ip();
    match limit.acquire(addr).await {
        Ok(condition) => match condition {
            true => Ok(next.run(request).await),
            false => Err(ResponseError::TooManyRequests(anyhow!("Too Many Requests"))),
        },
        Err(err) => Err(ResponseError::InternalServerError(err)),
    }
}
