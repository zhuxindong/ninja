use rcgen::RcgenError;
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid CA")]
    Tls(#[from] RcgenError),
    #[error("network error")]
    HyperError(#[from] hyper::Error),
    #[error("IO error")]
    IO(#[from] io::Error),
    #[error("unable to decode response body")]
    Decode,
    #[error("unknown error")]
    Unknown,
}
