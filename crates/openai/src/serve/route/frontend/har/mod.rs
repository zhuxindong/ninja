mod token;

use std::path::PathBuf;
use std::str::FromStr;

use crate::context::args::Args;
use crate::serve::error::{ProxyError, ResponseError};
use crate::{arkose, warn, with_context};
use axum::body::Body;
use axum::extract::{Multipart, Query};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::post;
use axum::{response::Html, routing::get, Router};
use axum::{Form, Json, TypedHeader};

const COOKIE_NAME: &'static str = "har_token";
const FIELD_FILE: &'static str = "files";

const LOGIN_PATH: &'static str = "/har/login";
const UPLOAD_PATH: &'static str = "/har/upload";

const LOGIN_PAGE: &'static str = include_str!("../../../../../frontend/har/login.html");
const UPLOAD_PAGE: &'static str = include_str!("../../../../../frontend/har/upload.html");
const SUCCESS_PAGE: &'static str = include_str!("../../../../../frontend/har/success.html");
const ERROR_PAGE: &'static str = include_str!("../../../../../frontend/har/error.html");

const FAILED_UPLOAD_TITLE: &'static str = "Failed to upload file";
const FAILED_AUTH_TITLE: &'static str = "Failed Authenticate";

pub(super) fn config(router: Router, _: &Args) -> Router {
    router
        .route("/har/login", get(login).post(post_login))
        .route("/har/upload", get(upload).post(post_upload))
        .route("/har/list", get(get_files))
        .route("/har/delete", post(delete_file))
        .route("/har/rename", post(rename_file))
}

fn error_html(title: &str, error_message: &str, back: bool) -> Html<String> {
    let mut error = ERROR_PAGE
        .replace("{{.error}}", error_message)
        .replace("{{.title}}", title);
    if !back {
        error = error.replace("window.history.back()", "window.location.reload()")
    }
    Html::from(error)
}

fn success_html(title: &str, success_message: &str) -> Html<String> {
    let success = SUCCESS_PAGE
        .replace("{{.success}}", success_message)
        .replace("{{.title}}", title);
    Html::from(success)
}

/// Check session
async fn check_session(jar: CookieJar) -> bool {
    if with_context!(arkose_har_upload_key).is_none() {
        return true;
    }
    if let Some(cookie) = jar.get(COOKIE_NAME) {
        return token::verifier(cookie.value()).await.is_ok();
    }
    false
}

/// Login page
async fn login(jar: CookieJar) -> impl IntoResponse {
    if check_session(jar).await {
        return Redirect::temporary(UPLOAD_PATH).into_response();
    }
    Html::from(LOGIN_PAGE).into_response()
}

/// Generate success response
async fn generate_success_response() -> Result<Response<Body>, ResponseError> {
    let token = token::generate_token().await?;
    let resp = Response::builder()
        .status(302)
        .header(header::LOCATION, UPLOAD_PATH)
        .header(
            header::SET_COOKIE,
            format!(
                "{COOKIE_NAME}={}; Max-Age={}; Path=/; HttpOnly",
                token,
                token::EXP
            ),
        )
        .body(Body::empty())
        .map_err(ResponseError::InternalServerError)?;
    Ok(resp)
}

#[derive(serde::Deserialize)]
struct AuthenticateKey {
    password: String,
}

/// Login with password
async fn post_login(
    password: Option<Form<AuthenticateKey>>,
) -> Result<impl IntoResponse, ResponseError> {
    if let Some(upload_key) = with_context!(arkose_har_upload_key) {
        if password.as_ref().map(|p| p.0.password.as_ref()) == Some(upload_key) {
            return Ok(generate_success_response().await.into_response());
        }
    } else {
        return Ok(generate_success_response().await.into_response());
    }

    Ok(error_html(FAILED_AUTH_TITLE, "Invalid authentication", true).into_response())
}

/// Upload page
async fn upload(jar: CookieJar) -> impl IntoResponse {
    if check_session(jar).await {
        return Html::from(UPLOAD_PAGE).into_response();
    }
    Redirect::temporary(LOGIN_PATH).into_response()
}

/// Upload file
async fn post_upload(
    jar: CookieJar,
    _type: TypedHeader<PlatformType>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, ResponseError> {
    if !check_session(jar).await {
        return Ok(Redirect::temporary(LOGIN_PATH).into_response());
    }

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(ResponseError::InternalServerError)?
    {
        // only accept file field
        if field
            .name()
            .ok_or(ResponseError::BadRequest(ProxyError::InvalidUploadField))?
            != FIELD_FILE
        {
            return Ok(error_html(FAILED_UPLOAD_TITLE, "Upload failed", false).into_response());
        }

        // require file name
        let filename = field
            .file_name()
            .ok_or(ResponseError::BadRequest(ProxyError::FilenameIsInvalid))?
            .to_string();

        let data = field
            .bytes()
            .await
            .map_err(ResponseError::InternalServerError)?;

        if let Some(err) = arkose::har::parse_from_slice(&data).err() {
            warn!("upload har file check error: {}", err);
            return Ok(error_html(
                FAILED_UPLOAD_TITLE,
                "The content and format of the Har file do not meet the requirements",
                false,
            )
            .into_response());
        }

        let har_path = with_context!(arkose_har_path, &_type.0 .0);
        tokio::fs::write(har_path.dir_path.join(filename), data)
            .await
            .map_err(ResponseError::InternalServerError)?;
    }

    Ok(success_html(
        "File uploaded successfully",
        "Your file has been successfully uploaded.",
    )
    .into_response())
}

/// Get file list
async fn get_files(
    jar: CookieJar,
    _type: TypedHeader<PlatformType>,
) -> Result<impl IntoResponse, ResponseError> {
    if !check_session(jar).await {
        return Ok(Redirect::temporary(LOGIN_PATH).into_response());
    }

    let dir = with_context!(arkose_har_path, &_type.0 .0).dir_path;

    let mut dirs = tokio::fs::read_dir(&dir)
        .await
        .map_err(ResponseError::InternalServerError)?;

    let mut files = Vec::new();
    while let Ok(Some(entry)) = dirs.next_entry().await {
        files.push(entry.file_name().to_string_lossy().to_string())
    }

    Ok(Json(files).into_response())
}

#[derive(serde::Deserialize)]
struct Filename {
    filename: String,
    new_filename: Option<String>,
}

/// Delete file
async fn delete_file(
    jar: CookieJar,
    filename: Query<Filename>,
    _type: TypedHeader<PlatformType>,
) -> Result<impl IntoResponse, ResponseError> {
    if !check_session(jar).await {
        return Ok(Redirect::temporary(LOGIN_PATH).into_response());
    }

    let dir = with_context!(arkose_har_path, &_type.0 .0).dir_path;

    let file = &dir.join(&filename.filename);

    // only accept har file
    if let Some(err) = check_file_extension(&file).err() {
        return Ok(err.into_response());
    };

    // Try to delete file
    if let Some(err) = tokio::fs::remove_file(file).await.err() {
        return Ok(error_html(
            "File deleted failed",
            &format!("Your file has been failed to delete: {err}"),
            false,
        )
        .into_response());
    }

    Ok(success_html(
        "File deleted successfully",
        "Your file has been successfully deleted.",
    )
    .into_response())
}

/// Rename file
async fn rename_file(
    jar: CookieJar,
    filename: Query<Filename>,
    _type: TypedHeader<PlatformType>,
) -> Result<impl IntoResponse, ResponseError> {
    if !check_session(jar).await {
        return Ok(Redirect::temporary(LOGIN_PATH).into_response());
    }

    let dir = with_context!(arkose_har_path, &_type.0 .0).dir_path;

    let old_file = PathBuf::from(&dir).join(&filename.filename);
    let new_file = PathBuf::from(&dir).join(
        &filename
            .new_filename
            .as_ref()
            .ok_or(ResponseError::BadRequest(ProxyError::NewFilenameIsEmpty))?,
    );

    // only accept har file
    if let Some(err) = check_file_extension(&new_file).err() {
        return Ok(err.into_response());
    };

    if tokio::fs::try_exists(&new_file)
        .await
        .map_err(ResponseError::BadRequest)?
    {
        return Ok(error_html(
            "File renamed failed",
            "Your file has been failed to rename: file already exists",
            false,
        )
        .into_response());
    }

    tokio::fs::rename(old_file, new_file)
        .await
        .map_err(ResponseError::BadRequest)?;

    Ok(success_html(
        "File renamed successfully",
        "Your file has been successfully renamed.",
    )
    .into_response())
}

fn check_file_extension(file: &PathBuf) -> Result<(), Html<String>> {
    if let Some(ext) = file.extension() {
        if ext != "har" {
            return Err(error_html(
                "File renamed failed",
                "Your file has been failed to rename: invalid file extension",
                false,
            ));
        }
    }
    Ok(())
}

use axum::headers::{Header, HeaderName, HeaderValue};
use axum::http::header;
use axum_extra::extract::CookieJar;

struct PlatformType(arkose::Type);

static TYPE: HeaderName = HeaderName::from_static("type");

impl Header for PlatformType {
    fn name() -> &'static HeaderName {
        &TYPE
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, axum::headers::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = values.next().ok_or_else(axum::headers::Error::invalid)?;
        let s = value
            .to_str()
            .map_err(|_| axum::headers::Error::invalid())?;
        let target = arkose::Type::from_str(s).map_err(|_| axum::headers::Error::invalid())?;
        Ok(PlatformType(target))
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let s = match self {
            PlatformType(arkose::Type::GPT3) => "gpt3",
            PlatformType(arkose::Type::GPT4) => "gpt4",
            PlatformType(arkose::Type::Auth) => "auth",
            PlatformType(arkose::Type::Platform) => "platform",
            PlatformType(arkose::Type::SignUp) => "signup",
        };
        let value = HeaderValue::from_str(s).expect("invalid header value");
        values.extend(std::iter::once(value));
    }
}
