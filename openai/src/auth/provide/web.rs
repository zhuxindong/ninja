use crate::{
    auth::{
        model::{self, AuthStrategy},
        provide::{AuthenticateDataBuilder, GetAuthorizedUrlDataBuilder},
        AuthClient, OPENAI_OAUTH_URL,
    },
    error::AuthError,
};
use crate::{debug, warn, URL_CHATGPT_API};
use anyhow::{bail, Context};
use axum::http::HeaderValue;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use url::Url;

use super::{AuthProvider, AuthResult, AuthenticateMfaDataBuilder, IdentifierDataBuilder};

pub(crate) struct WebAuthProvider {
    inner: Client,
}

impl WebAuthProvider {
    pub fn new(inner: Client) -> impl AuthProvider + Send + Sync {
        Self { inner }
    }

    async fn get_state(&self, authorized_url: String) -> AuthResult<String> {
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

    async fn get_csrf_token(&self) -> AuthResult<String> {
        let resp = self
            .inner
            .get(format!("{URL_CHATGPT_API}/api/auth/csrf"))
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;

        match resp.error_for_status_ref() {
            Ok(_) => {
                let res = resp.json::<Value>().await?;
                let csrf_token = res
                    .as_object()
                    .and_then(|obj| obj.get("csrfToken"))
                    .and_then(|csrf| csrf.as_str())
                    .context(AuthError::FailedCsrfToken)?;
                return Ok(csrf_token.to_string());
            }
            Err(err) => {
                warn!("{err}");
                bail!(AuthError::FailedCsrfToken)
            }
        }
    }

    async fn get_authorized_url(&self, csrf_token: String) -> AuthResult<String> {
        let form = GetAuthorizedUrlDataBuilder::default()
            .callback_url("/")
            .csrf_token(&csrf_token)
            .json("true")
            .build()?;
        let resp = self
            .inner
            .post(format!(
                "{URL_CHATGPT_API}/api/auth/signin/auth0?prompt=login"
            ))
            .form(&form)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;

        if resp.status().is_success() {
            let res = resp.json::<Value>().await?;
            let url = res
                .as_object()
                .and_then(|v| v.get("url"))
                .and_then(|v| v.as_str())
                .context(AuthError::FailedAuthorizedUrl)?
                .to_owned();
            debug!("WebAuthHandle authorized url: {url}");
            return Ok(url);
        }

        bail!(AuthError::FailedAuthorizedUrl)
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
        state: &str,
        account: &model::AuthAccount,
    ) -> AuthResult<model::AccessToken> {
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
        let status = resp.status();

        AuthClient::response_handle_unit(resp)
            .await
            .map_err(|_| AuthError::InvalidEmailOrPassword)?;

        if status.is_redirection() {
            let location = AuthClient::get_location_path(&headers)?;
            let resp = self
                .inner
                .get(format!("{OPENAI_OAUTH_URL}{location}"))
                .send()
                .await
                .map_err(AuthError::FailedRequest)?;
            if resp.status().is_redirection() {
                let location = AuthClient::get_location_path(resp.headers())?;
                if location.starts_with("/u/mfa-otp-challenge") {
                    let mfa = account.mfa.clone().ok_or(AuthError::MFARequired)?;
                    return self.authenticate_mfa(&mfa, location, &account).await;
                }
                let resp = self
                    .inner
                    .get(location)
                    .send()
                    .await
                    .map_err(AuthError::FailedRequest)?;

                return match resp.status() {
                    StatusCode::FOUND => self.get_access_token().await,
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
        self.get_access_token().await
    }

    async fn get_access_token(&self) -> AuthResult<model::AccessToken> {
        let resp = self
            .inner
            .get(format!("{URL_CHATGPT_API}/api/auth/session"))
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
        // get csrf token
        let csrf_token = self.get_csrf_token().await?;

        // authorized url
        let authorized_url = self.get_authorized_url(csrf_token).await?;

        // state code
        let state = self.get_state(authorized_url).await?;

        // check username
        self.authenticate_username(&state, &account).await?;

        // check password and username
        self.authenticate_password(&state, &account).await
    }

    async fn do_refresh_token(&self, _refresh_token: &str) -> AuthResult<model::RefreshToken> {
        bail!("Not yet implemented")
    }

    async fn do_revoke_token(&self, _refresh_token: &str) -> AuthResult<()> {
        bail!("Not yet implemented")
    }
}
