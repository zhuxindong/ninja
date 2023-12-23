use std::sync::Arc;

#[derive(thiserror::Error, Debug)]
pub enum ArkoseError {
    #[error("submit funcaptcha answer error {0:?}")]
    SubmitAnswerError(anyhow::Error),
    #[error("Invalid arkose platform type: {0:?}")]
    InvalidPlatformType(String),
    #[error("Invalid public key: {0:?}")]
    InvalidPublicKey(String),
    #[error("No solver available or solver is invalid")]
    NoSolverAvailable,
    #[error("Error creating arkose session error {0:?}")]
    CreateSessionError(anyhow::Error),
    #[error("invalid funcaptcha error")]
    InvalidFunCaptcha,
    #[error("hex decode error")]
    HexDecodeError,
    #[error("unsupported hash algorithm")]
    UnsupportedHashAlgorithm,
    #[error("Unable to find har related request entry")]
    HarEntryNotFound,
    #[error("Invalid HAR file")]
    InvalidHarFile,
    #[error("{0:?} not a file")]
    NotAFile(String),
    #[error("Failed to get HAR entry error {0:?}")]
    FailedToGetHarEntry(Arc<anyhow::Error>),
    #[error("Deserialize error {0:?}")]
    DeserializeError(#[from] reqwest::Error),
    #[error("Funcaptcha submit error: {0:?}")]
    FuncaptchaSubmitError(String),
    #[error("Funcaptcha not solved error: {0:?}")]
    FuncaptchaNotSolvedError(String),
}
