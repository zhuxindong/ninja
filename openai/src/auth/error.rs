#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("Bad request (error {0:?})")]
    BadRequest(String),
    #[error("Too many requests (error {0:?})")]
    TooManyRequests(String),
    #[error("Unauthorized request (error {0:?})")]
    Unauthorized(String),
    #[error("Server error ({0:?})")]
    ServerError(String),
    #[error("Failed login")]
    FailedLogin,
    #[error(transparent)]
    FailedRequest(#[from] reqwest::Error),
    #[error("Failed to get access token (error {0:?})")]
    FailedAccessToken(String),
    #[error("Failed get code from callback url")]
    FailedCallbackCode,
    #[error("Failed callback url")]
    FailedCallbackURL,
    #[error("Failed to get authorized url")]
    FailedAuthorizedUrl,
    #[error("Failed to get state")]
    FailedState,
    #[error("Failed get csrf token")]
    FailedCsrfToken,
    #[error("Failed to get auth session cookie")]
    FailedAuthSessionCookie,
    #[error("Invalid client request (error {0:?})")]
    InvalidClientRequest(String),
    #[error("Invalid arkose token ({0:?})")]
    InvalidArkoseToken(anyhow::Error),
    #[error("Invalid request login url (error {0:?})")]
    InvalidLoginUrl(String),
    #[error("Invalid email or password")]
    InvalidEmailOrPassword,
    #[error("Invalid request (error {0:?})")]
    InvalidRequest(String),
    #[error("Invalid email")]
    InvalidEmail,
    #[error("Invalid Location")]
    InvalidLocation,
    #[error("Invalid refresh token")]
    InvalidRefreshToken,
    #[error("Accidentally jumped back to the login homepage, please try again.")]
    InvalidLocationPath,
    #[error("MFA failed")]
    MFAFailed,
    #[error("MFA required")]
    MFARequired,
    #[error("Json deserialize error (error {0:?})")]
    DeserializeError(String),
    #[error("Implementation is not supported")]
    NotSupportedImplementation,
    #[error("Failed to get preauth cookie")]
    PreauthCookieNotFound,
}
