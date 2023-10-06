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

const STATE: &str = "TMf_R7zSeBRzTs86WAfQJh9Q_AbDh3382e7Y-pae1wQ";
const APP_VERSION: &str = "7657";
const AUTH0_CLIENT: &str = "eyJlbnYiOnsiaU9TIjoiMTYuNSIsInN3aWZ0IjoiNS54In0sInZlcnNpb24iOiIyLjUuMCIsIm5hbWUiOiJBdXRoMC5zd2lmdCJ9";
const APPLE_CLIENT_ID: &str = "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh";
const OPENAI_OAUTH_APPLE_CALLBACK_URL: &str =
    "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback";

pub(crate) struct AppleAuthProvider {
    preauth_api: Url,
    inner: Client,
}

impl AppleAuthProvider {
    pub fn new(inner: Client, preauth_api: Url) -> impl AuthProvider + Send + Sync {
        Self { inner, preauth_api }
    }

    async fn get_authorized_url(&self, code_challenge: &str) -> AuthResult<Url> {
        let preauth_cookie = self.get_preauth_cookie().await?;
        let url = format!("{OPENAI_OAUTH_URL}/authorize?state={STATE}&ios_app_version={APP_VERSION}&client_id={APPLE_CLIENT_ID}&redirect_uri={OPENAI_OAUTH_APPLE_CALLBACK_URL}&code_challenge={code_challenge}&scope=openid%20email%20profile%20offline_access%20model.request%20model.read%20organization.read%20organization.write&prompt=login&preauth_cookie={preauth_cookie}&audience=https://api.openai.com/v1&code_challenge_method=S256&response_type=code&auth0Client={AUTH0_CLIENT}");
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

        Ok(url.clone())
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
            .header(reqwest::header::REFERER, HeaderValue::from_str(&url)?)
            .header(
                reqwest::header::ORIGIN,
                HeaderValue::from_static(OPENAI_OAUTH_URL),
            )
            .json(
                &IdentifierDataBuilder::default()
                    .action("default")
                    .state(&state)
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
        code_verifier: &str,
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
            return self
                .authenticate_resume(code_verifier, location, account)
                .await;
        }
        bail!(AuthError::FailedLogin)
    }

    async fn authenticate_resume(
        &self,
        code_verifier: &str,
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
            self.authenticate_mfa(&mfa, code_verifier, location, account)
                .await
        } else if !location.starts_with(OPENAI_OAUTH_APPLE_CALLBACK_URL) {
            bail!(AuthError::FailedCallbackURL)
        } else {
            self.authorization_code(code_verifier, location).await
        }
    }

    #[async_recursion]
    async fn authenticate_mfa(
        &self,
        mfa_code: &str,
        code_verifier: &str,
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
        self.authenticate_resume(code_verifier, location, &account)
            .await
    }

    async fn authorization_code(
        &self,
        code_verifier: &str,
        location: &str,
    ) -> AuthResult<model::AccessToken> {
        debug!("authorization_code location path: {location}");
        let code = AuthClient::get_callback_code(&Url::parse(location)?)?;
        let data = AuthorizationCodeDataBuilder::default()
            .redirect_uri(OPENAI_OAUTH_APPLE_CALLBACK_URL)
            .grant_type(GrantType::AuthorizationCode)
            .client_id(APPLE_CLIENT_ID)
            .code(&code)
            .code_verifier(Some(code_verifier))
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

    async fn get_preauth_cookie(&self) -> AuthResult<String> {
        let resp = self
            .inner
            .get(self.preauth_api.as_ref())
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;

        let json = resp
            .error_for_status()
            .map_err(AuthError::FailedRequest)?
            .json::<serde_json::Value>()
            .await?;

        let preauth_cookie = json
            .as_object()
            .map(|v| v.get("preauth_cookie"))
            .flatten()
            .map(|v| v.as_str())
            .flatten()
            .ok_or(anyhow::anyhow!("failed to extract preauth_cookie"))?
            .to_owned();
        Ok(preauth_cookie)
    }
}

#[async_trait::async_trait]
impl AuthProvider for AppleAuthProvider {
    fn supports(&self, t: &AuthStrategy) -> bool {
        t.eq(&AuthStrategy::Apple)
    }

    async fn do_access_token(
        &self,
        account: &model::AuthAccount,
    ) -> AuthResult<model::AccessToken> {
        let code_verifier = AuthClient::generate_code_verifier();
        let code_challenge = AuthClient::generate_code_challenge(&code_verifier);

        let url = self.get_authorized_url(&code_challenge).await?;
        let state = AuthClient::get_callback_state(&url);

        // check username
        self.authenticate_username(&state, account).await?;

        // check password and username
        self.authenticate_password(&code_verifier, &state, account)
            .await
    }

    async fn do_refresh_token(&self, refresh_token: &str) -> AuthResult<model::RefreshToken> {
        let refresh_token = AuthClient::trim_bearer(refresh_token)?;
        let data = RefreshTokenDataBuilder::default()
            .redirect_uri(OPENAI_OAUTH_APPLE_CALLBACK_URL)
            .grant_type(GrantType::RefreshToken)
            .client_id(APPLE_CLIENT_ID)
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
            .client_id(APPLE_CLIENT_ID)
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
