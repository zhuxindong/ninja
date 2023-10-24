use std::str::FromStr;

use crate::context::{self, ContextArgs};
use crate::serve::err::ResponseError;
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

pub(super) fn config(router: Router, _: &ContextArgs) -> Router {
    router.route(
        "/har/upload",
        get(upload)
            .post(upload_form)
            .layer(axum::extract::DefaultBodyLimit::max(200 * 1024 * 1024)),
    )
}

async fn upload() -> Html<String> {
    let ctx = context::get_instance();
    let tm = UPLOAD_PAGE.replace(
        "{{.key}}",
        &ctx.arkose_har_upload_key().is_some().to_string(),
    );
    return Html::from(tm);
}

async fn upload_form(
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    _type: TypedHeader<PlatformType>,
    mut multipart: Multipart,
) -> Result<Html<String>, ResponseError> {
    let ctx = context::get_instance();
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
                    if key.ne(h.token()) {
                        return error_html("Authorization key error");
                    }
                }
                None => return error_html("Authorization key is required"),
            }
        }

        if let Some(err) = arkose::har::check_from_slice(&data).err() {
            debug!("Error {err}");
            return error_html(
                "The content and format of the Har file do not meet the requirements",
            );
        }

        if tokio::fs::write(ctx.arkose_har_path(&_type.0 .0).1, data)
            .await
            .is_err()
        {
            return error_html("File write error");
        }
    }

    Ok(Html::from(SUCCESS_PAGE.to_owned()))
}

fn error_html(error_message: &str) -> Result<Html<String>, ResponseError> {
    let error = ERROR_PAGE.replace("{{.error}}", error_message);
    Ok(Html::from(error))
}

use axum::headers::{Header, HeaderName, HeaderValue};

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
            PlatformType(arkose::Type::Chat3) => "chat3",
            PlatformType(arkose::Type::Chat4) => "chat4",
            PlatformType(arkose::Type::Platform) => "platform",
            PlatformType(arkose::Type::Auth0) => "auth0",
        };
        let value = HeaderValue::from_str(s).expect("invalid header value");
        values.extend(std::iter::once(value));
    }
}
