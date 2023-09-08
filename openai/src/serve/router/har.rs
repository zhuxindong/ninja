use crate::context::Context;
use crate::serve::{err::ResponseError, Launcher};
use crate::{arkose, debug};
use anyhow::anyhow;
use axum::extract::Multipart;
use axum::headers::authorization::Bearer;
use axum::headers::Authorization;
use axum::TypedHeader;
use axum::{response::Html, routing::get, Router};

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

async fn upload() -> Html<String> {
    let ctx = Context::get_instance().await;
    let tm = UPLOAD_PAGE.replace(
        "{{.key}}",
        &ctx.arkose_har_upload_key().is_some().to_string(),
    );
    return Html::from(tm);
}

async fn upload_form(
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    mut multipart: Multipart,
) -> Result<Html<String>, ResponseError> {
    let ctx = Context::get_instance().await;

    if let Some(field) = multipart
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
            match bearer {
                Some(h) => {
                    if key != h.token() {
                        return error_html("Authorization key error");
                    }
                }
                None => return error_html("Authorization key is required"),
            }
        }

        if let Some(err) = arkose::har::parse_from_slice(&data).err() {
            debug!("Error {err}");
            return error_html(
                "The content and format of the Har file do not meet the requirements",
            );
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
