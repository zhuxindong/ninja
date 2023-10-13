#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("bad request (error {0:?})")]
    BadRequest(String),
    #[error("too many requests (error {0:?})")]
    TooManyRequests(String),
    #[error("Unauthorized request (error {0:?})")]
    Unauthorized(String),
    #[error("Server error ({0:?})")]
    ServerError(String),
    #[error("failed to get public key")]
    FailedPubKeyRequest,
    #[error("failed login")]
    FailedLogin,
    #[error(transparent)]
    FailedRequest(#[from] reqwest::Error),
    #[error("invalid client request (error {0:?})")]
    InvalidClientRequest(String),
    #[error("invalid arkose token ({0:?})")]
    InvalidArkoseToken(anyhow::Error),
    #[error("failed get code from callback url")]
    FailedCallbackCode,
    #[error("failed callback url")]
    FailedCallbackURL,
    #[error("failed to get authorized url")]
    FailedAuthorizedUrl,
    #[error("Failed to get state")]
    FailedState,
    #[error("failed get csrf token")]
    FailedCsrfToken,
    #[error("invalid request login url (error {0:?})")]
    InvalidLoginUrl(String),
    #[error("invalid email or password")]
    InvalidEmailOrPassword,
    #[error("invalid request (error {0:?})")]
    InvalidRequest(String),
    #[error("invalid email")]
    InvalidEmail,
    #[error("invalid Location")]
    InvalidLocation,
    #[error("invalid access token")]
    InvalidAccessToken,
    #[error("invalid refresh token")]
    InvalidRefreshToken,
    #[error("token expired")]
    TokenExpired,
    #[error("MFA failed")]
    MFAFailed,
    #[error("MFA required")]
    MFARequired,
    #[error("json deserialize error (error {0:?})")]
    DeserializeError(String),
    #[error("implementation is not supported")]
    NotSupportedImplementation,
}

#[derive(thiserror::Error, Debug)]
pub enum TokenStoreError {
    #[error("failed to access token")]
    AccessError,
    #[error("token not found error")]
    NotFoundError,
    #[error("failed token deserialize")]
    DeserializeError(#[from] serde_json::error::Error),
    #[error("failed to verify access_token")]
    AccessTokenVerifyError,
    #[error("failed to create default token store file")]
    CreateDefaultTokenFileError,
}
