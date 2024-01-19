#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    /// Request Error
    #[error(transparent)]
    FailedRequest(#[from] reqwest::Error),
    #[error("Bad request (error {0})")]
    BadRequest(String),
    #[error("Too many requests ({0})")]
    TooManyRequests(String),
    #[error("Unauthorized request ({0})")]
    Unauthorized(String),
    #[error("Forbidden request ({0})")]
    Forbidden(String),
    #[error("Server error ({0})")]
    ServerError(reqwest::Error),

    /// Failed Error
    #[error("Failed login, it may be an IP or speed limit issue, please try again")]
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
    #[error("Invalid login ({0})")]
    InvalidLogin(String),
    #[error("Invalid arkose token ({0:?})")]
    InvalidArkoseToken(anyhow::Error),
    #[error("Invalid request login url ({0:?})")]
    InvalidLoginUrl(url::ParseError),
    #[error("Invalid email or password")]
    InvalidEmailOrPassword,
    #[error("Invalid request ({0})")]
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
    #[error("Json deserialize error ({0:?})")]
    DeserializeError(reqwest::Error),
    #[error("Implementation is not supported")]
    NotSupportedImplementation,
    #[error("Failed to get preauth cookie")]
    PreauthCookieNotFound,

    /// Other Error
    #[error("Regex error ({0:?})")]
    InvalidRegex(regex::Error),
}
