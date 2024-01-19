use crate::auth::error::AuthError;
use axum::http::header::{CONTENT_TYPE, LOCATION};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::Json;
use eventsource_stream::EventStreamError;

#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    #[error("Session not found")]
    SessionNotFound,
    #[error("Authentication Key error")]
    AuthKeyError,
    #[error("AccessToken is required")]
    AccessTokenRequired,
    #[error("Model required")]
    ModelRequired,
    #[error("Body required")]
    BodyRequired,
    #[error("Body must be a json object")]
    BodyMustBeJsonObject,
    #[error("Body message is empty")]
    BodyMessageIsEmpty,
    #[error("Request Content is empty")]
    RequestContentIsEmpty,
    #[error("System time before UNIX EPOCH! ({0})")]
    SystemTimeBeforeEpoch(anyhow::Error),
    #[error("new filename is empty")]
    NewFilenameIsEmpty,
    #[error("filename is invalid")]
    FilenameIsInvalid,
    #[error("invalid upload field")]
    InvalidUploadField,
    #[error("Too Many Requests")]
    TooManyRequests,
    #[error("Your access is not in the whitelist")]
    AccessNotInWhitelist,
    #[error("Auth Key required!")]
    AuthKeyRequired,
    #[error("Event-source stream error ({0})")]
    EventSourceStreamError(EventStreamError<reqwest::Error>),
    #[error("Deserialize error ({0})")]
    DeserializeError(serde_json::Error),
    #[error("Invalid access token")]
    InvalidAccessToken,

    /// get access token profile error
    #[error("Get access token profile error")]
    GetAccessTokenProfileError,

    /// Cloudflare error
    #[error("Missing cf_captcha_response")]
    CfMissingCaptcha,
    #[error("Cloudflare error ({0})")]
    CfError(reqwest::Error),

    /// Request error
    #[error("Request error ({0})")]
    RequestError(reqwest::Error),
}

// Make our own error that wraps `anyhow::Error`.
#[derive(serde::Serialize)]
pub struct ResponseError {
    code: u16,
    msg: Option<String>,
    // 3xx, not serialize
    #[serde(skip)]
    path: Option<String>,
}

impl ResponseError {
    pub fn new(msg: String, code: StatusCode) -> Self {
        Self {
            msg: Some(msg),
            code: code.as_u16(),
            path: None,
        }
    }
}

// Tell axum how to convert `ResponseError` into a response.
impl IntoResponse for ResponseError {
    fn into_response(self) -> Response {
        // Convert our error into a response with the appropriate status code.
        let status_code =
            StatusCode::from_u16(self.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        // 3xx, redirect
        if let Some(path) = self.path {
            return (status_code, [(LOCATION, &path)], ()).into_response();
        }

        // 4xx, 5xx, json
        (
            status_code,
            [(CONTENT_TYPE, "application/json")],
            Json(self),
        )
            .into_response()
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, ResponseError>`. That way you don't need to do that manually.
impl<E> From<E> for ResponseError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        let err: anyhow::Error = err.into();
        let err_msg = err.to_string();

        let make_error = |code: StatusCode| ResponseError {
            msg: Some(err_msg),
            code: code.as_u16(),
            path: None,
        };

        // Try to downcast the error to our own AuthError type.
        if let Some(auth_error) = err.downcast_ref::<AuthError>() {
            return match auth_error {
                // 4xx
                AuthError::BadRequest(_)
                | AuthError::InvalidRequest(_)
                | AuthError::InvalidArkoseToken(_)
                | AuthError::InvalidLoginUrl(_)
                | AuthError::InvalidEmailOrPassword
                | AuthError::InvalidEmail
                | AuthError::InvalidLocation
                | AuthError::InvalidRefreshToken
                | AuthError::InvalidLocationPath
                | AuthError::MFAFailed
                | AuthError::MFARequired => make_error(StatusCode::BAD_REQUEST),
                // 401
                AuthError::Unauthorized(_) => make_error(StatusCode::UNAUTHORIZED),
                // 403
                AuthError::Forbidden(_) | AuthError::InvalidLogin(_) => {
                    make_error(StatusCode::FORBIDDEN)
                }
                // 429
                AuthError::TooManyRequests(_) => make_error(StatusCode::TOO_MANY_REQUESTS),
                // 5xx
                _ => make_error(StatusCode::INTERNAL_SERVER_ERROR),
            };
        }

        // default 500
        make_error(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

macro_rules! static_err {
    ($name:ident, $status:expr) => {
        #[allow(non_snake_case, missing_docs)]
        pub fn $name<E>(err: E) -> ResponseError
        where
            E: Into<anyhow::Error> + ToString,
        {
            let code: StatusCode = $status;
            ResponseError {
                msg: Some(err.to_string()),
                code: code.as_u16(),
                path: None,
            }
        }
    };
}

macro_rules! static_3xx {
    ($name:ident, $status:expr) => {
        #[allow(non_snake_case, missing_docs)]
        pub fn $name(path: &str) -> ResponseError {
            let code: StatusCode = $status;
            ResponseError {
                msg: None,
                code: code.as_u16(),
                path: Some(path.to_string()),
            }
        }
    };
}

impl ResponseError {
    // 3xx
    static_3xx!(TempporaryRedirect, StatusCode::TEMPORARY_REDIRECT);

    // 4xx
    static_err!(BadRequest, StatusCode::BAD_REQUEST);
    static_err!(NotFound, StatusCode::NOT_FOUND);
    static_err!(Unauthorized, StatusCode::UNAUTHORIZED);
    static_err!(PaymentRequired, StatusCode::PAYMENT_REQUIRED);
    static_err!(Forbidden, StatusCode::FORBIDDEN);
    static_err!(MethodNotAllowed, StatusCode::METHOD_NOT_ALLOWED);
    static_err!(NotAcceptable, StatusCode::NOT_ACCEPTABLE);
    static_err!(
        ProxyAuthenticationRequired,
        StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );
    static_err!(RequestTimeout, StatusCode::REQUEST_TIMEOUT);
    static_err!(Conflict, StatusCode::CONFLICT);
    static_err!(Gone, StatusCode::GONE);
    static_err!(LengthRequired, StatusCode::LENGTH_REQUIRED);
    static_err!(PreconditionFailed, StatusCode::PRECONDITION_FAILED);
    static_err!(PreconditionRequired, StatusCode::PRECONDITION_REQUIRED);
    static_err!(PayloadTooLarge, StatusCode::PAYLOAD_TOO_LARGE);
    static_err!(UriTooLong, StatusCode::URI_TOO_LONG);
    static_err!(UnsupportedMediaType, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    static_err!(RangeNotSatisfiable, StatusCode::RANGE_NOT_SATISFIABLE);
    static_err!(ExpectationFailed, StatusCode::EXPECTATION_FAILED);
    static_err!(UnprocessableEntity, StatusCode::UNPROCESSABLE_ENTITY);
    static_err!(TooManyRequests, StatusCode::TOO_MANY_REQUESTS);
    static_err!(
        RequestHeaderFieldsTooLarge,
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );
    static_err!(
        UnavailableForLegalReasons,
        StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
    );

    // 5xx
    static_err!(InternalServerError, StatusCode::INTERNAL_SERVER_ERROR);
    static_err!(NotImplemented, StatusCode::NOT_IMPLEMENTED);
    static_err!(BadGateway, StatusCode::BAD_GATEWAY);
    static_err!(ServiceUnavailable, StatusCode::SERVICE_UNAVAILABLE);
    static_err!(GatewayTimeout, StatusCode::GATEWAY_TIMEOUT);
    static_err!(VersionNotSupported, StatusCode::HTTP_VERSION_NOT_SUPPORTED);
    static_err!(VariantAlsoNegotiates, StatusCode::VARIANT_ALSO_NEGOTIATES);
    static_err!(InsufficientStorage, StatusCode::INSUFFICIENT_STORAGE);
    static_err!(LoopDetected, StatusCode::LOOP_DETECTED);
}
