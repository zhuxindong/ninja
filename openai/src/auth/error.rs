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
    #[error("failed login")]
    FailedLogin,
    #[error(transparent)]
    FailedRequest(#[from] reqwest::Error),
    #[error("invalid client request (error {0:?})")]
    InvalidClientRequest(String),
    #[error("failed to get access token (error {0:?})")]
    FailedAccessToken(String),
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
    #[error("failed to get auth session cookie")]
    FailedAuthSessionCookie,
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
    #[error("invalid refresh token")]
    InvalidRefreshToken,
    #[error("invalid location path")]
    InvalidLocationPath,
    #[error("MFA failed")]
    MFAFailed,
    #[error("MFA required")]
    MFARequired,
    #[error("json deserialize error (error {0:?})")]
    DeserializeError(String),
    #[error("implementation is not supported")]
    NotSupportedImplementation,
    #[error("failed to get preauth cookie")]
    PreauthCookieNotFound,
}
