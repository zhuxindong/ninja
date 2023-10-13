use crate::auth::provide::{AuthenticateDataBuilder, AuthorizationCodeDataBuilder, GrantType};
use crate::auth::AuthClient;
use crate::debug;
use crate::{
    auth::{
        model::{self, AuthStrategy},
        OPENAI_OAUTH_REVOKE_URL, OPENAI_OAUTH_TOKEN_URL, OPENAI_OAUTH_URL,
    },
    error::AuthError,
};
use anyhow::{bail, Context};
use async_recursion::async_recursion;
use axum::http::HeaderValue;
use reqwest::Client;
use url::Url;

use super::{
    AuthProvider, AuthResult, AuthenticateMfaDataBuilder, IdentifierDataBuilder,
    RefreshTokenDataBuilder, RequestContext, RequestContextExt, RevokeTokenDataBuilder,
};

const PLATFORM_CLIENT_ID: &str = "DRivsnm2Mu42T3KOpqdtwB3NYviHYzwD";
const OPENAI_OAUTH_PLATFORM_CALLBACK_URL: &str = "https://platform.openai.com/auth/callback";

pub(crate) struct PlatformAuthProvider {
    inner: Client,
}

impl PlatformAuthProvider {
    pub fn new(inner: Client) -> impl AuthProvider + Send + Sync {
        Self { inner }
    }

    async fn authorize(&self, ctx: &mut RequestContext<'_>) -> AuthResult<()> {
        let url = format!("{OPENAI_OAUTH_URL}/authorize?client_id={PLATFORM_CLIENT_ID}&scope=openid%20email%20profile%20offline_access%20model.request%20model.read%20organization.read%20organization.write&audience=https://api.openai.com/v1&redirect_uri=https://platform.openai.com/auth/callback&response_type=code");
        let resp = self
            .inner
            .get(&url)
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
            .map_err(AuthError::FailedRequest)?
            .ext_context(ctx);

        let state = AuthClient::get_callback_state(&resp.url());
        ctx.set_state(state.as_str());

        Ok(AuthClient::response_handle_unit(resp)
            .await
            .map_err(|e| AuthError::InvalidLoginUrl(e.to_string()))?)
    }

    async fn authenticate_username(&self, ctx: &mut RequestContext<'_>) -> AuthResult<()> {
        let url = format!("{OPENAI_OAUTH_URL}/u/login/identifier?state={}", ctx.state);
        let resp = self
            .inner
            .post(&url)
            .ext_context(ctx)
            .json(
                &IdentifierDataBuilder::default()
                    .action("default")
                    .state(&ctx.state)
                    .username(&ctx.account.username)
                    .js_available(true)
                    .webauthn_available(true)
                    .is_brave(false)
                    .webauthn_platform_available(false)
                    .build()?,
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
            .json(
                &AuthenticateDataBuilder::default()
                    .action("default")
                    .state(&ctx.state)
                    .username(&ctx.account.username)
                    .password(&ctx.account.password)
                    .build()?,
            )
            .send()
            .await
            .map_err(AuthError::FailedRequest)?
            .ext_context(ctx);

        let location = AuthClient::get_location_path(&resp.headers())
            .map_err(|_| AuthError::InvalidEmailOrPassword)?;

        if location.starts_with("/authorize/resume?") {
            return self.authenticate_resume(ctx, location).await;
        }
        bail!(AuthError::FailedLogin)
    }

    async fn authenticate_resume(
        &self,
        ctx: &mut RequestContext<'_>,
        location: &str,
    ) -> AuthResult<model::AccessToken> {
        let resp = self
            .inner
            .get(&format!("{OPENAI_OAUTH_URL}{location}"))
            .ext_context(ctx)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?
            .ext_context(ctx);

        let location: &str = AuthClient::get_location_path(&resp.headers())
            .map_err(|_| AuthError::InvalidLocation)?;

        if location.starts_with("/u/mfa-otp-challenge?") {
            self.authenticate_mfa(ctx, location).await
        } else if !location.starts_with(OPENAI_OAUTH_PLATFORM_CALLBACK_URL) {
            bail!(AuthError::FailedCallbackURL)
        } else {
            self.authorization_code(location).await
        }
    }

    #[async_recursion]
    async fn authenticate_mfa(
        &self,
        ctx: &mut RequestContext<'_>,
        location: &str,
    ) -> AuthResult<model::AccessToken> {
        let mfa_code = &ctx.account.mfa.clone().ok_or(AuthError::MFARequired)?;
        let url = format!("{OPENAI_OAUTH_URL}{}", location);
        let state = AuthClient::get_callback_state(&Url::parse(&url)?);
        let data = AuthenticateMfaDataBuilder::default()
            .action("default")
            .state(&state)
            .code(mfa_code)
            .build()?;

        let resp = self
            .inner
            .post(&url)
            .ext_context(ctx)
            .json(&data)
            .header(reqwest::header::REFERER, HeaderValue::from_str(&url)?)
            .header(
                reqwest::header::ORIGIN,
                HeaderValue::from_static(OPENAI_OAUTH_URL),
            )
            .send()
            .await
            .map_err(AuthError::FailedRequest)?
            .ext_context(ctx);

        let location: &str = AuthClient::get_location_path(&resp.headers())?;
        if location.starts_with("/authorize/resume?") && ctx.account.mfa.is_none() {
            bail!(AuthError::MFAFailed)
        }
        self.authenticate_resume(ctx, location).await
    }

    async fn authorization_code(&self, location: &str) -> AuthResult<model::AccessToken> {
        debug!("authorization_code location path: {location}");
        let code = AuthClient::get_callback_code(&Url::parse(location)?)?;
        let data = AuthorizationCodeDataBuilder::default()
            .redirect_uri(OPENAI_OAUTH_PLATFORM_CALLBACK_URL)
            .grant_type(GrantType::AuthorizationCode)
            .client_id(PLATFORM_CLIENT_ID)
            .code(&code)
            .code_verifier(None)
            .build()?;

        let resp = self
            .inner
            .post(OPENAI_OAUTH_TOKEN_URL)
            .json(&data)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;

        let access_token = AuthClient::response_handle::<model::OAuthAccessToken>(resp).await?;
        Ok(model::AccessToken::OAuth(access_token))
    }
}

#[async_trait::async_trait]
impl AuthProvider for PlatformAuthProvider {
    fn supports(&self, t: &AuthStrategy) -> bool {
        t.eq(&AuthStrategy::Platform)
    }

    async fn do_access_token(
        &self,
        account: &model::AuthAccount,
    ) -> AuthResult<model::AccessToken> {
        let mut ctx = RequestContext::new(account);
        // authorized
        self.authorize(&mut ctx).await?;

        // check username
        self.authenticate_username(&mut ctx).await?;

        // check password and username
        self.authenticate_password(&mut ctx).await
    }

    async fn do_refresh_token(&self, refresh_token: &str) -> AuthResult<model::RefreshToken> {
        let refresh_token = AuthClient::trim_bearer(refresh_token)?;
        let data = RefreshTokenDataBuilder::default()
            .redirect_uri(OPENAI_OAUTH_PLATFORM_CALLBACK_URL)
            .grant_type(GrantType::RefreshToken)
            .client_id(PLATFORM_CLIENT_ID)
            .refresh_token(refresh_token)
            .build()?;

        let resp = self
            .inner
            .post(OPENAI_OAUTH_TOKEN_URL)
            .json(&data)
            .send()
            .await?;

        let mut token = AuthClient::response_handle::<model::RefreshToken>(resp).await?;
        token.refresh_token = refresh_token.to_owned();
        Ok(token)
    }

    async fn do_revoke_token(&self, refresh_token: &str) -> AuthResult<()> {
        let refresh_token = AuthClient::trim_bearer(refresh_token)?;
        let data = RevokeTokenDataBuilder::default()
            .client_id(PLATFORM_CLIENT_ID)
            .token(refresh_token)
            .build()?;

        let resp = self
            .inner
            .post(OPENAI_OAUTH_REVOKE_URL)
            .json(&data)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;

        AuthClient::response_handle_unit(resp).await
    }
}
