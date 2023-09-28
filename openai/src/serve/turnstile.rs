use crate::context;

use super::err::ResponseError;

pub(super) async fn cf_turnstile_check(
    addr: &std::net::IpAddr,
    cf_response: Option<&str>,
) -> Result<(), ResponseError> {
    #[derive(serde::Serialize)]
    struct CfCaptchaForm<'a> {
        secret: &'a str,
        response: &'a str,
        remoteip: &'a std::net::IpAddr,
        idempotency_key: String,
    }

    let ctx = context::get_instance();

    if let Some(turnsile) = ctx.cf_turnstile() {
        let response = cf_response.filter(|r| !r.is_empty()).ok_or_else(|| {
            ResponseError::BadRequest(anyhow::anyhow!("Missing cf_captcha_response".to_owned()))
        })?;

        let form = CfCaptchaForm {
            secret: &turnsile.secret_key,
            response,
            remoteip: addr,
            idempotency_key: crate::uuid::uuid(),
        };

        let resp = context::get_instance()
            .client()
            .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .form(&form)
            .send()
            .await
            .map_err(ResponseError::InternalServerError)?;

        let _ = resp.error_for_status().map_err(ResponseError::BadRequest)?;
    }
    Ok(())
}
