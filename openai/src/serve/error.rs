use axum::http::header::{CONTENT_TYPE, LOCATION};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::Json;
use eventsource_stream::EventStreamError;
use serde_json::json;

use crate::auth::error::AuthError;

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
    #[error("System time before UNIX EPOCH!: {0}")]
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
    #[error("Session: {0} required")]
    SessionRequired(&'static str),
    #[error("Missing cf_captcha_response")]
    MissingCfCaptchaResponse,
    #[error("event-source stream error: {0}")]
    EventSourceStreamError(EventStreamError<reqwest::Error>),
    #[error("Deserialize error: {0}")]
    DeserializeError(serde_json::Error),
}

// Make our own error that wraps `anyhow::Error`.
pub struct ResponseError {
    msg: Option<String>,
    code: StatusCode,
    path: Option<String>,
}

impl ResponseError {
    pub fn new(msg: String, code: StatusCode) -> Self {
        Self {
            msg: Some(msg),
            code,
            path: None,
        }
    }

    pub fn msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }

    pub fn code(&self) -> &StatusCode {
        &self.code
    }
}

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for ResponseError {
    fn into_response(self) -> Response {
        if let Some(path) = self.path {
            return (self.code, [(LOCATION, &path)], ()).into_response();
        }
        let body = Json(json!({
            "code": self.code.as_str(),
            "msg": self.msg,
        }));
        (self.code, [(CONTENT_TYPE, "application/json")], body).into_response()
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
impl<E> From<E> for ResponseError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        let err = err.into();

        // Make ResponseError
        let make_error = |msg: String, code: StatusCode| ResponseError {
            msg: Some(msg),
            code,
            path: None,
        };

        if let Some(auth_error) = err.downcast_ref::<AuthError>() {
            match auth_error {
                // 500
                AuthError::FailedRequest(_)
                | AuthError::ServerError(_)
                | AuthError::FailedLogin
                | AuthError::FailedAccessToken(_)
                | AuthError::FailedCallbackCode
                | AuthError::FailedCallbackURL
                | AuthError::FailedAuthorizedUrl
                | AuthError::FailedState
                | AuthError::FailedCsrfToken
                | AuthError::FailedAuthSessionCookie
                | AuthError::DeserializeError(_)
                | AuthError::NotSupportedImplementation
                | AuthError::PreauthCookieNotFound
                | AuthError::InvalidRegex(_) => {
                    make_error(auth_error.to_string(), StatusCode::INTERNAL_SERVER_ERROR)
                }
                // 400
                AuthError::BadRequest(_)
                | AuthError::InvalidLogin(_)
                | AuthError::InvalidArkoseToken(_)
                | AuthError::InvalidLoginUrl(_)
                | AuthError::InvalidEmailOrPassword
                | AuthError::InvalidRequest(_)
                | AuthError::InvalidEmail
                | AuthError::InvalidLocation
                | AuthError::InvalidRefreshToken
                | AuthError::InvalidLocationPath
                | AuthError::MFAFailed
                | AuthError::MFARequired => {
                    make_error(auth_error.to_string(), StatusCode::BAD_REQUEST)
                }
                // 401
                AuthError::Unauthorized(_) => {
                    make_error(auth_error.to_string(), StatusCode::UNAUTHORIZED)
                }
                // 403
                AuthError::Forbidden(_) => {
                    make_error(auth_error.to_string(), StatusCode::FORBIDDEN)
                }
                // 429
                AuthError::TooManyRequests(_) => {
                    make_error(auth_error.to_string(), StatusCode::TOO_MANY_REQUESTS)
                }
            }
        } else {
            make_error(err.to_string(), StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

macro_rules! static_err {
    ($name:ident, $status:expr) => {
        #[allow(non_snake_case, missing_docs)]
        pub fn $name<E>(err: E) -> ResponseError
        where
            E: Into<anyhow::Error>,
        {
            ResponseError {
                msg: Some(err.into().to_string()),
                code: $status,
                path: None,
            }
        }
    };
}

macro_rules! static_3xx {
    ($name:ident, $status:expr) => {
        #[allow(non_snake_case, missing_docs)]
        pub fn $name(path: &str) -> ResponseError {
            ResponseError {
                msg: None,
                code: $status,
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
