use anyhow::anyhow;
use axum::extract::Multipart;
use axum::headers::authorization::Bearer;
use axum::headers::Authorization;
use axum::TypedHeader;
use axum::{response::Html, routing::get, Router};

use crate::context::Context;
use crate::serve::{err::ResponseError, Launcher};

const FIELD_FILE: &'static str = "file";

const ERROR_PAGE: &'static str = include_str!("../../../ui/har/error.html");
const UPLOAD_PAGE: &'static str = include_str!("../../../ui/har/upload.html");
const SUCCESS_PAGE: &'static str = include_str!("../../../ui/har/success.html");

pub(super) fn config(router: Router, _: &Launcher) -> Router {
    router.route(
        "/har/upload",
        get(upload)
            .post(upload_form)
            .layer(axum::extract::DefaultBodyLimit::max(200 * 1024 * 1024)),
    )
}

async fn upload() -> Html<&'static str> {
    Html::from(UPLOAD_PAGE)
}

async fn upload_form(
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    mut multipart: Multipart,
) -> Result<Html<String>, ResponseError> {
    let ctx = Context::get_instance().await;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(ResponseError::InternalServerError)?
    {
        let field_name = field
            .name()
            .ok_or(ResponseError::BadRequest(anyhow!("invalid field")))?;

        if field_name != FIELD_FILE {
            return error_html("Upload failed");
        }

        let data = field
            .bytes()
            .await
            .map_err(ResponseError::InternalServerError)?;

        if let Some(key) = ctx.arkose_har_upload_key() {
            if key != bearer.token() {
                return error_html("Authentication key is required");
            }
        }

        match ctx.arkose_har_file_path() {
            Some(path) => {
                if tokio::fs::write(path, data).await.is_err() {
                    return error_html("File write error");
                }
            }
            None => {
                return error_html("You have to set the path of the uploaded file");
            }
        }
    }

    Ok(Html::from(SUCCESS_PAGE.to_owned()))
}

fn error_html(error_message: &str) -> Result<Html<String>, ResponseError> {
    let error = ERROR_PAGE.replace("{{.error}}", error_message);
    Ok(Html::from(error))
}
