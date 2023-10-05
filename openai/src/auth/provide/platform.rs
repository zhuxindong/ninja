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
    RefreshTokenDataBuilder, RevokeTokenDataBuilder,
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

    async fn get_state(&self, authorized_url: Url) -> AuthResult<String> {
        let resp = self
            .inner
            .get(authorized_url)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;

        if resp.status().is_success() {
            let html = resp.text().await?;
            let tag_start = "<input";
            let attribute_name = "name=\"state\"";
            let value_start = "value=\"";
            let mut remaining = html.as_str();

            while let Some(tag_start_index) = remaining.find(tag_start) {
                remaining = &remaining[tag_start_index..];

                if let Some(attribute_index) = remaining.find(attribute_name) {
                    remaining = &remaining[attribute_index..];

                    if let Some(value_start_index) = remaining.find(value_start) {
                        remaining = &remaining[value_start_index + value_start.len()..];

                        if let Some(value_end_index) = remaining.find("\"") {
                            let value = &remaining[..value_end_index];
                            return Ok(value.trim().to_string());
                        }
                    }
                }
                remaining = &remaining[tag_start.len()..];
            }
        }

        bail!(AuthError::FailedState)
    }

    async fn get_authorized_url(&self) -> AuthResult<Url> {
        let url = format!("{OPENAI_OAUTH_URL}/authorize?client_id={PLATFORM_CLIENT_ID}&scope=openid%20email%20profile%20offline_access%20model.request%20model.read%20organization.read%20organization.write&audience=https://api.openai.com/v1&redirect_uri=https://platform.openai.com/auth/callback&response_type=code");
        let resp = self
            .inner
            .get(&url)
            .header(
                reqwest::header::REFERER,
                HeaderValue::from_static(OPENAI_OAUTH_URL),
            )
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;

        let url = resp.url().clone();

        AuthClient::response_handle_unit(resp)
            .await
            .map_err(|e| AuthError::InvalidLoginUrl(e.to_string()))?;

        Ok(url)
    }

    async fn authenticate_username(
        &self,
        state: &str,
        account: &model::AuthAccount,
    ) -> AuthResult<()> {
        let url = format!("{OPENAI_OAUTH_URL}/u/login/identifier?state={state}");
        let resp = self
            .inner
            .post(&url)
            .json(
                &IdentifierDataBuilder::default()
                    .action("default")
                    .state(state)
                    .username(&account.username)
                    .js_available(true)
                    .webauthn_available(true)
                    .is_brave(false)
                    .webauthn_platform_available(false)
                    .build()?,
            )
            .send()
            .await?;

        AuthClient::response_handle_unit(resp)
            .await
            .context(AuthError::InvalidEmail)
    }

    async fn authenticate_password(
        &self,
        state: &str,
        account: &model::AuthAccount,
    ) -> AuthResult<model::AccessToken> {
        debug!("authenticate_password state: {state}");
        let data = AuthenticateDataBuilder::default()
            .action("default")
            .state(state)
            .username(&account.username)
            .password(&account.password)
            .build()?;

        let resp = self
            .inner
            .post(format!("{OPENAI_OAUTH_URL}/u/login/password?state={state}"))
            .json(&data)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;

        let headers = resp.headers().clone();
        AuthClient::response_handle_unit(resp)
            .await
            .map_err(|_| AuthError::InvalidEmailOrPassword)?;

        let location = AuthClient::get_location_path(&headers)?;
        debug!("authenticate_password location path: {location}");
        if location.starts_with("/authorize/resume?") {
            return self.authenticate_resume(location, account).await;
        }
        bail!(AuthError::FailedLogin)
    }

    async fn authenticate_resume(
        &self,
        location: &str,
        account: &model::AuthAccount,
    ) -> AuthResult<model::AccessToken> {
        let resp = self
            .inner
            .get(&format!("{OPENAI_OAUTH_URL}{location}"))
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;

        let headers = resp.headers().clone();

        AuthClient::response_handle_unit(resp)
            .await
            .map_err(|_| AuthError::InvalidLocation)?;

        let location: &str = AuthClient::get_location_path(&headers)?;
        debug!("authenticate_resume location path: {location}");
        if location.starts_with("/u/mfa-otp-challenge?") {
            let mfa = account.mfa.clone().ok_or(AuthError::MFARequired)?;
            self.authenticate_mfa(&mfa, location, account).await
        } else if !location.starts_with(OPENAI_OAUTH_PLATFORM_CALLBACK_URL) {
            bail!(AuthError::FailedCallbackURL)
        } else {
            self.authorization_code(location).await
        }
    }

    #[async_recursion]
    async fn authenticate_mfa(
        &self,
        mfa_code: &str,
        location: &str,
        account: &model::AuthAccount,
    ) -> AuthResult<model::AccessToken> {
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
            .json(&data)
            .header(reqwest::header::REFERER, HeaderValue::from_str(&url)?)
            .header(
                reqwest::header::ORIGIN,
                HeaderValue::from_static(OPENAI_OAUTH_URL),
            )
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;
        let headers = resp.headers().clone();

        AuthClient::response_handle_unit(resp).await?;

        let location: &str = AuthClient::get_location_path(&headers)?;
        if location.starts_with("/authorize/resume?") && account.mfa.is_none() {
            bail!(AuthError::MFAFailed)
        }
        self.authenticate_resume(location, &account).await
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
        // authorized url
        let authorized_url = self.get_authorized_url().await?;

        // state code
        let state = self.get_state(authorized_url).await?;

        // check username
        self.authenticate_username(&state, account).await?;

        // check password and username
        self.authenticate_password(&state, account).await
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
