#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    /// Request Error
    #[error(transparent)]
    FailedRequest(#[from] reqwest::Error),
    #[error("Bad request (error {0:?})")]
    BadRequest(reqwest::Error),
    #[error("Too many requests (error {0:?})")]
    TooManyRequests(reqwest::Error),
    #[error("Unauthorized request (error {0:?})")]
    Unauthorized(reqwest::Error),
    #[error("Forbidden request (error {0:?})")]
    Forbidden(reqwest::Error),
    #[error("Server error ({0:?})")]
    ServerError(reqwest::Error),

    /// Failed Error
    #[error("Failed login")]
    FailedLogin,
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

    /// Invalid Error
    #[error("Invalid login (error {0:?})")]
    InvalidLogin(String),
    #[error("Invalid arkose token ({0:?})")]
    InvalidArkoseToken(anyhow::Error),
    #[error("Invalid request login url (error {0:?})")]
    InvalidLoginUrl(url::ParseError),
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
    DeserializeError(reqwest::Error),
    #[error("Implementation is not supported")]
    NotSupportedImplementation,
    #[error("Failed to get preauth cookie")]
    PreauthCookieNotFound,

    /// Other Error
    #[error("Regex error (error {0:?})")]
    InvalidRegex(regex::Error),
}
