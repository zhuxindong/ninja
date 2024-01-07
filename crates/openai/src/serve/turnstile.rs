use crate::{serve::error::ProxyError, with_context};
use std::net::IpAddr;

pub(super) async fn cf_turnstile_check(
    addr: IpAddr,
    cf_response: Option<&str>,
) -> Result<(), ProxyError> {
    #[derive(serde::Serialize)]
    struct CfCaptchaForm<'a> {
        secret: &'a str,
        response: &'a str,
        remoteip: &'a IpAddr,
        idempotency_key: String,
    }

    let ctx = with_context!();

    if let Some(turnsile) = ctx.cf_turnstile() {
        let response = cf_response
            .filter(|r| !r.is_empty())
            .ok_or_else(|| ProxyError::CfMissingCaptcha)?;

        let form = CfCaptchaForm {
            secret: &turnsile.secret_key,
            response,
            remoteip: &addr,
            idempotency_key: crate::uuid::uuid(),
        };

        let _ = ctx
            .api_client()
            .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .form(&form)
            .send()
            .await
            .map_err(ProxyError::RequestError)?
            .error_for_status()
            .map_err(ProxyError::CfError)?;
    }
    Ok(())
}
