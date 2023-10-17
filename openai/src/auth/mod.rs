pub mod provide;

extern crate regex;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::impersonate::Impersonate;
use reqwest::redirect::Policy;
use serde::de::DeserializeOwned;

use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use reqwest::{Client, Proxy, StatusCode, Url};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;

pub mod model;

use crate::debug;
use crate::error::AuthError;

use self::model::{ApiKeyData, AuthStrategy};
use self::provide::apple::AppleAuthProvider;
use self::provide::platform::PlatformAuthProvider;
use self::provide::web::WebAuthProvider;
use self::provide::{AuthProvider, AuthResult};

const OPENAI_API_URL: &str = "https://api.openai.com";
const OPENAI_OAUTH_URL: &str = "https://auth0.openai.com";
const OPENAI_OAUTH_TOKEN_URL: &str = "https://auth0.openai.com/oauth/token";
const OPENAI_OAUTH_REVOKE_URL: &str = "https://auth0.openai.com/oauth/revoke";

static EMAIL_REGEX: OnceCell<Regex> = OnceCell::const_new();

/// You do **not** have to wrap the `Client` in an [`Rc`] or [`Arc`] to **reuse** it,
/// because it already uses an [`Arc`] internally.
///
/// [`Rc`]: std::rc::Rc
#[derive(Clone)]
pub struct AuthClient {
    inner: Client,
    providers: Arc<Vec<Box<dyn AuthProvider + Send + Sync>>>,
}

impl AuthClient {
    pub async fn do_get_user_picture(&self, access_token: &str) -> AuthResult<Option<String>> {
        let access_token = access_token.replace("Bearer ", "");
        let resp = self
            .inner
            .get(format!("https://openai.openai.auth0app.com/userinfo"))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;

        match resp.error_for_status_ref() {
            Ok(_) => Ok(resp
                .json::<Value>()
                .await?
                .as_object()
                .and_then(|v| v.get("picture"))
                .and_then(|v| v.as_str())
                .and_then(|v| Some(v.to_string()))),
            Err(_) => bail!(AuthError::InvalidRequest(resp.text().await?)),
        }
    }

    pub async fn do_dashboard_login(&self, access_token: &str) -> AuthResult<model::DashSession> {
        let access_token = access_token.replace("Bearer ", "");
        let resp = self
            .inner
            .post(format!("{OPENAI_API_URL}/dashboard/onboarding/login"))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;

        Self::response_handle(resp).await
    }

    pub async fn do_get_api_key_list(&self, sensitive_id: &str) -> AuthResult<model::ApiKeyList> {
        let resp = self
            .inner
            .get(format!("{OPENAI_API_URL}/dashboard/user/api_keys"))
            .bearer_auth(sensitive_id)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;
        Self::response_handle(resp).await
    }

    pub async fn do_api_key<'a>(
        &self,
        sensitive_id: &str,
        data: ApiKeyData<'a>,
    ) -> AuthResult<model::ApiKey> {
        let resp = self
            .inner
            .post(format!("{OPENAI_API_URL}/dashboard/user/api_keys"))
            .bearer_auth(sensitive_id)
            .json(&data)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;
        Self::response_handle(resp).await
    }

    pub async fn billing_credit_grants(
        &self,
        sensitive_id: &str,
    ) -> anyhow::Result<model::Billing> {
        let resp = self
            .inner
            .get(format!("{OPENAI_API_URL}/dashboard/billing/credit_grants"))
            .bearer_auth(sensitive_id)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;
        Self::response_handle(resp).await
    }

    async fn response_handle<U: DeserializeOwned>(resp: reqwest::Response) -> AuthResult<U> {
        let url = resp.url().clone();
        match resp.error_for_status_ref() {
            Ok(_) => Ok(resp
                .json::<U>()
                .await
                .map_err(|op| AuthError::DeserializeError(op.to_string()))?),
            Err(err) => {
                let err_msg = format!("error: {}, url: {}", resp.text().await?, url);
                bail!(Self::handle_error(err.status(), err_msg).await)
            }
        }
    }

    async fn response_handle_unit(resp: reqwest::Response) -> AuthResult<()> {
        let url = resp.url().clone();
        match resp.error_for_status_ref() {
            Ok(_) => Ok(()),
            Err(err) => {
                let err_msg = format!("error: {}, url: {}", resp.text().await?, url);
                bail!(Self::handle_error(err.status(), err_msg).await)
            }
        }
    }

    async fn handle_error(status: Option<StatusCode>, err_msg: String) -> AuthError {
        match status {
            Some(
                status_code @ (StatusCode::UNAUTHORIZED
                | StatusCode::REQUEST_TIMEOUT
                | StatusCode::TOO_MANY_REQUESTS
                | StatusCode::BAD_REQUEST
                | StatusCode::PAYMENT_REQUIRED
                | StatusCode::FORBIDDEN
                | StatusCode::INTERNAL_SERVER_ERROR
                | StatusCode::BAD_GATEWAY
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::GATEWAY_TIMEOUT),
            ) => {
                if status_code == StatusCode::UNAUTHORIZED {
                    return AuthError::Unauthorized("Unauthorized".to_owned());
                }
                if status_code == StatusCode::TOO_MANY_REQUESTS {
                    return AuthError::TooManyRequests("Too Many Requests".to_owned());
                }
                if status_code == StatusCode::BAD_REQUEST {
                    return AuthError::BadRequest("Bad Request".to_owned());
                }

                if status_code.is_client_error() {
                    return AuthError::InvalidClientRequest(err_msg);
                }

                AuthError::ServerError(err_msg)
            }
            _ => AuthError::InvalidRequest("Invalid Request".to_owned()),
        }
    }

    fn generate_code_verifier() -> String {
        let token: [u8; 32] = rand::thread_rng().gen();
        let code_verifier = general_purpose::URL_SAFE
            .encode(token)
            .trim_end_matches('=')
            .to_string();
        code_verifier
    }

    fn generate_code_challenge(code_verifier: &str) -> String {
        let mut m = Sha256::new();
        m.update(code_verifier.as_bytes());
        let code_challenge = general_purpose::URL_SAFE
            .encode(m.finalize())
            .trim_end_matches('=')
            .to_string();
        code_challenge
    }

    fn get_callback_code(url: &Url) -> AuthResult<String> {
        let mut url_params = HashMap::new();
        url.query_pairs().into_owned().for_each(|(key, value)| {
            url_params
                .entry(key)
                .and_modify(|v: &mut Vec<String>| v.push(value.clone()))
                .or_insert(vec![value]);
        });

        debug!("get_callback_code: {:?}", url_params);

        if let Some(error) = url_params.get("error") {
            if let Some(error_description) = url_params.get("error_description") {
                let msg = format!("{}: {}", error[0], error_description[0]);
                bail!("{}", msg)
            } else {
                bail!("{}", error[0])
            }
        }

        let code = url_params
            .get("code")
            .ok_or(AuthError::FailedCallbackCode)?[0]
            .to_string();
        Ok(code)
    }

    fn get_callback_state(url: &Url) -> String {
        let url_params = url.query_pairs().into_owned().collect::<HashMap<_, _>>();
        debug!("get_callback_state: {:?}", url_params);
        url_params["state"].to_owned()
    }

    fn get_location_path(header: &HeaderMap<HeaderValue>) -> AuthResult<&str> {
        debug!("get_location_path: {:?}", header);
        Ok(header
            .get("Location")
            .ok_or(AuthError::InvalidLocation)?
            .to_str()?)
    }

    fn trim_bearer(t: &str) -> AuthResult<&str> {
        let refresh_token = t.trim_start_matches("Bearer ");
        if refresh_token.is_empty() {
            bail!(AuthError::InvalidRefreshToken)
        }
        Ok(refresh_token)
    }
}

#[async_trait::async_trait]
impl AuthProvider for AuthClient {
    fn supports(&self, t: &AuthStrategy) -> bool {
        self.providers.iter().any(|strategy| strategy.supports(t))
    }

    async fn do_access_token(
        &self,
        account: &model::AuthAccount,
    ) -> AuthResult<model::AccessToken> {
        let regex = EMAIL_REGEX
            .get_or_try_init(|| async {
                Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")
            })
            .await?;

        if !regex.is_match(&account.username) || account.password.is_empty() {
            bail!(AuthError::InvalidEmailOrPassword)
        }

        for provider in self.providers.iter() {
            if provider.supports(&account.option) {
                return provider.do_access_token(account).await;
            }
        }
        bail!("Login implementation is not supported")
    }

    async fn do_revoke_token(&self, refresh_token: &str) -> AuthResult<()> {
        let mut result: Option<AuthResult<()>> = None;
        for handle in self.providers.iter() {
            if handle.supports(&AuthStrategy::Apple) || handle.supports(&AuthStrategy::Platform) {
                let res = handle.do_revoke_token(refresh_token).await;
                match res {
                    Ok(ok) => {
                        result = Some(Ok(ok));
                        break;
                    }
                    Err(err) => {
                        result = Some(Err(err));
                    }
                }
            }
        }

        result.context(AuthError::NotSupportedImplementation)?
    }

    async fn do_refresh_token(&self, refresh_token: &str) -> AuthResult<model::RefreshToken> {
        let mut result: Option<AuthResult<model::RefreshToken>> = None;

        for handle in self.providers.iter() {
            if handle.supports(&AuthStrategy::Apple) || handle.supports(&AuthStrategy::Platform) {
                let res = handle.do_refresh_token(refresh_token).await;
                match res {
                    Ok(ok) => {
                        result = Some(Ok(ok));
                        break;
                    }
                    Err(err) => {
                        result = Some(Err(err));
                    }
                }
            }
        }

        result.context(AuthError::NotSupportedImplementation)?
    }
}

pub struct AuthClientBuilder {
    preauth_api: Option<Url>,
    inner: reqwest::ClientBuilder,
}

impl AuthClientBuilder {
    // Proxy options
    pub fn proxy(mut self, proxy: Option<String>) -> Self {
        if let Some(url) = proxy {
            self.inner = self.inner.proxy(
                Proxy::all(url.clone()).expect(&format!("reqwest: invalid proxy url: {url}")),
            );
        } else {
            self.inner = self.inner.no_proxy();
        }
        self
    }

    // Timeout options

    /// Enables a request timeout.
    ///
    /// The timeout is applied from when the request starts connecting until the
    /// response body has finished.
    ///
    /// Default is no timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    /// Set a timeout for only the connect phase of a `Client`.
    ///
    /// Default is `None`.
    ///
    /// # Note
    ///
    /// This **requires** the futures be executed in a tokio runtime with
    /// a tokio timer enabled.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.inner = self.inner.connect_timeout(timeout);
        self
    }

    // HTTP options

    /// Set an optional timeout for idle sockets being kept-alive.
    ///
    /// Pass `None` to disable timeout.
    ///
    /// Default is 90 seconds.
    pub fn pool_idle_timeout<D>(mut self, val: D) -> Self
    where
        D: Into<Option<Duration>>,
    {
        self.inner = self.inner.pool_idle_timeout(val);
        self
    }

    /// Sets the maximum idle connection per host allowed in the pool.
    pub fn pool_max_idle_per_host(mut self, max: usize) -> Self {
        self.inner = self.inner.pool_max_idle_per_host(max);
        self
    }

    /// Set that all sockets have `SO_KEEPALIVE` set with the supplied duration.
    ///
    /// If `None`, the option will not be set.
    pub fn tcp_keepalive<D>(mut self, val: D) -> Self
    where
        D: Into<Option<Duration>>,
    {
        self.inner = self.inner.tcp_keepalive(val);
        self
    }

    /// Sets the necessary values to mimic the specified impersonate client version.
    pub fn impersonate(mut self, ver: Impersonate) -> Self {
        self.inner = self.inner.impersonate(ver);
        self
    }

    /// Sets the `User-Agent` header to be used by this client.
    pub fn user_agent(mut self, value: &str) -> Self {
        self.inner = self.inner.user_agent(value);
        self
    }

    /// Setting Custom PreAuth Cookie API
    pub fn preauth_api(mut self, preauth_api: Option<String>) -> Self {
        if let Some(preauth_api) = preauth_api {
            self.preauth_api = Some(Url::parse(&preauth_api).expect("invalid preauth_api url"));
        }
        self
    }

    /// Bind to a local IP Address.
    pub fn local_address<T>(mut self, addr: T) -> Self
    where
        T: Into<Option<IpAddr>>,
    {
        self.inner = self.inner.local_address(addr);
        self
    }

    pub fn build(self) -> AuthClient {
        let client = self.inner.build().expect("ClientBuilder::build()");

        let mut providers: Vec<Box<dyn AuthProvider + Send + Sync>> = Vec::with_capacity(3);
        providers.push(Box::new(WebAuthProvider::new(client.clone())));
        providers.push(Box::new(PlatformAuthProvider::new(client.clone())));
        if let Some(preauth_api) = self.preauth_api {
            providers.push(Box::new(AppleAuthProvider::new(
                client.clone(),
                preauth_api,
            )));
        }

        AuthClient {
            inner: client,
            providers: Arc::new(providers),
        }
    }

    pub fn builder() -> AuthClientBuilder {
        AuthClientBuilder {
            inner: Client::builder()
                .impersonate(Impersonate::OkHttpAndroid13)
                .connect_timeout(Duration::from_secs(30))
                .redirect(Policy::none()),
            preauth_api: None,
        }
    }
}
