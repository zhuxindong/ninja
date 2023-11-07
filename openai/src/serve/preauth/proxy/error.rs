use rcgen::RcgenError;
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid CA")]
    Tls(#[from] RcgenError),
    #[error("network error")]
    HyperError(#[from] hyper::Error),
    #[error("body error")]
    BodyErrpr(#[from] http::Error),
    #[error("request connect error")]
    RequestConnectError(#[from] reqwest::Error),
    #[error("IO error")]
    IO(#[from] io::Error),
}
