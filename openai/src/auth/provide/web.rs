use crate::{
    auth::{
        model::{self, AuthStrategy},
        provide::AuthenticateData,
        AuthClient, OPENAI_OAUTH_URL,
    },
    error::AuthError,
};
use crate::{debug, warn, URL_CHATGPT_API};
use anyhow::{bail, Context};
use reqwest::{Client, StatusCode};
use serde_json::Value;
use url::Url;

use super::{
    AuthProvider, AuthResult, AuthenticateMfaData, GetAuthorizedUrlData, IdentifierData,
    RequestContext, RequestContextExt,
};

pub(crate) struct WebAuthProvider {
    inner: Client,
}

impl WebAuthProvider {
    pub fn new(inner: Client) -> impl AuthProvider + Send + Sync {
        Self { inner }
    }

    async fn csrf_token(&self, ctx: &mut RequestContext<'_>) -> AuthResult<()> {
        let resp = self
            .inner
            .get(format!("{URL_CHATGPT_API}/api/auth/csrf"))
            .send()
            .await
            .map_err(AuthError::FailedRequest)?
            .ext_context(ctx);

        match resp.error_for_status_ref() {
            Ok(_) => {
                let res = resp.json::<Value>().await?;
                let csrf_token = res
                    .as_object()
                    .and_then(|obj| obj.get("csrfToken"))
                    .and_then(|csrf| csrf.as_str())
                    .context(AuthError::FailedCsrfToken)?;
                ctx.set_csrf_token(csrf_token);
                return Ok(());
            }
            Err(err) => {
                warn!("{err}");
                bail!(AuthError::FailedCsrfToken)
            }
        }
    }

    async fn authorized(&self, ctx: &mut RequestContext<'_>) -> AuthResult<()> {
        let resp = self
            .inner
            .post(format!(
                "{URL_CHATGPT_API}/api/auth/signin/auth0?prompt=login"
            ))
            .ext_context(ctx)
            .form(
                &GetAuthorizedUrlData::builder()
                    .callback_url("/")
                    .csrf_token(&ctx.csrf_token)
                    .json("true")
                    .build(),
            )
            .send()
            .await
            .map_err(AuthError::FailedRequest)?
            .ext_context(ctx);

        match resp.error_for_status() {
            Ok(resp) => {
                let res = resp.json::<Value>().await?;
                let url = res
                    .as_object()
                    .and_then(|v| v.get("url"))
                    .and_then(|v| v.as_str())
                    .context(AuthError::FailedAuthorizedUrl)?;
                return self.state(url, ctx).await;
            }
            Err(err) => {
                debug!("WebAuthHandle authorized url error: {err}");
                bail!(AuthError::FailedAuthorizedUrl)
            }
        }
    }

    async fn state(&self, url: &str, ctx: &mut RequestContext<'_>) -> AuthResult<()> {
        let resp = self
            .inner
            .get(url)
            .ext_context(ctx)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?
            .ext_context(ctx);

        let identifier_location = AuthClient::get_location_path(resp.headers())?;
        let resp = self
            .inner
            .get(format!("{OPENAI_OAUTH_URL}{identifier_location}"))
            .ext_context(ctx)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;

        let state = AuthClient::get_callback_state(&resp.url());
        ctx.set_state(state.as_str());

        Ok(AuthClient::response_handle_unit(resp)
            .await
            .map_err(|_| AuthError::FailedState)?)
    }

    async fn authenticate_username(&self, ctx: &mut RequestContext<'_>) -> AuthResult<()> {
        let url = format!("{OPENAI_OAUTH_URL}/u/login/identifier?state={}", ctx.state);
        let resp = self
            .inner
            .post(&url)
            .ext_context(ctx)
            .form(
                &IdentifierData::builder()
                    .action("default")
                    .state(&ctx.state)
                    .username(&ctx.account.username)
                    .js_available(true)
                    .webauthn_available(true)
                    .is_brave(false)
                    .webauthn_platform_available(false)
                    .build(),
            )
            .send()
            .await?
            .ext_context(ctx);

        AuthClient::response_handle_unit(resp)
            .await
            .context(AuthError::InvalidEmail)
    }

    async fn authenticate_password(
        &self,
        ctx: &mut RequestContext<'_>,
    ) -> AuthResult<model::AccessToken> {
        ctx.load_arkose_token().await?;

        let resp = self
            .inner
            .post(format!(
                "{OPENAI_OAUTH_URL}/u/login/password?state={}",
                ctx.state
            ))
            .ext_context(ctx)
            .form(
                &AuthenticateData::builder()
                    .action("default")
                    .state(&ctx.state)
                    .username(&ctx.account.username)
                    .password(&ctx.account.password)
                    .build(),
            )
            .send()
            .await
            .map_err(AuthError::FailedRequest)?
            .ext_context(ctx);

        if resp.status().is_redirection() {
            let location = AuthClient::get_location_path(&resp.headers())?;
            let resp = self
                .inner
                .get(format!("{OPENAI_OAUTH_URL}{location}"))
                .ext_context(ctx)
                .send()
                .await
                .map_err(AuthError::FailedRequest)?
                .ext_context(ctx);

            if resp.status().is_redirection() {
                let location = AuthClient::get_location_path(resp.headers())?;
                if location.starts_with("/u/mfa-otp-challenge") {
                    let mfa = ctx.account.mfa.clone().ok_or(AuthError::MFARequired)?;
                    return self.authenticate_mfa(ctx, &mfa, location).await;
                }

                let resp = self
                    .inner
                    .get(location)
                    .ext_context(ctx)
                    .send()
                    .await
                    .map_err(AuthError::FailedRequest)?
                    .ext_context(ctx);

                return match resp.status() {
                    StatusCode::FOUND => self.get_access_token(ctx).await,
                    StatusCode::TEMPORARY_REDIRECT => {
                        bail!(AuthError::InvalidEmailOrPassword)
                    }
                    _ => {
                        bail!(AuthError::FailedLogin)
                    }
                };
            }
        }
        bail!(AuthError::FailedLogin)
    }

    async fn authenticate_mfa(
        &self,
        ctx: &mut RequestContext<'_>,
        mfa_code: &str,
        location: &str,
    ) -> AuthResult<model::AccessToken> {
        let url = format!("{OPENAI_OAUTH_URL}{}", location);
        let state = AuthClient::get_callback_state(&Url::parse(&url)?);
        let data = AuthenticateMfaData::builder()
            .action("default")
            .state(&state)
            .code(mfa_code)
            .build();

        let resp = self
            .inner
            .post(&url)
            .ext_context(ctx)
            .json(&data)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?
            .ext_context(ctx);

        let location: &str = AuthClient::get_location_path(resp.headers())?;
        if location.starts_with("/authorize/resume?") && ctx.account.mfa.is_none() {
            bail!(AuthError::MFAFailed)
        }
        self.get_access_token(ctx).await
    }

    async fn get_access_token(
        &self,
        ctx: &mut RequestContext<'_>,
    ) -> AuthResult<model::AccessToken> {
        let resp = self
            .inner
            .get(format!("{URL_CHATGPT_API}/api/auth/session"))
            .ext_context(ctx)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;
        match resp.status() {
            StatusCode::OK => Ok(model::AccessToken::Session(
                resp.json::<model::SessionAccessToken>().await?,
            )),
            StatusCode::TOO_MANY_REQUESTS => {
                bail!(AuthError::TooManyRequests("Too Many Requests".to_owned()))
            }
            _ => {
                bail!("Failed to get access token")
            }
        }
    }
}

#[async_trait::async_trait]
impl AuthProvider for WebAuthProvider {
    fn supports(&self, t: &AuthStrategy) -> bool {
        t.eq(&AuthStrategy::Web)
    }

    async fn do_access_token(
        &self,
        account: &model::AuthAccount,
    ) -> AuthResult<model::AccessToken> {
        let mut ctx = RequestContext::new(account);
        // csrf token
        self.csrf_token(&mut ctx).await?;

        // authorized
        self.authorized(&mut ctx).await?;

        // check username
        self.authenticate_username(&mut ctx).await?;

        // check password and username
        self.authenticate_password(&mut ctx).await
    }

    async fn do_refresh_token(&self, _refresh_token: &str) -> AuthResult<model::RefreshToken> {
        bail!("Not yet implemented")
    }

    async fn do_revoke_token(&self, _refresh_token: &str) -> AuthResult<()> {
        bail!("Not yet implemented")
    }
}
