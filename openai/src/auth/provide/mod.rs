pub mod apple;
pub mod platform;
pub mod web;

use std::collections::HashSet;

use crate::{
    arkose::{self, ArkoseToken, Type},
    error::AuthError,
};

use super::model::{self, AuthStrategy};
use derive_builder::Builder;
use reqwest::header;
use serde::Serialize;

pub type AuthResult<T, E = anyhow::Error> = anyhow::Result<T, E>;

#[async_trait::async_trait]
pub trait AuthProvider: Send + Sync {
    async fn do_access_token(&self, account: &model::AuthAccount)
        -> AuthResult<model::AccessToken>;

    async fn do_revoke_token(&self, refresh_token: &str) -> AuthResult<()>;

    async fn do_refresh_token(&self, refresh_token: &str) -> AuthResult<model::RefreshToken>;

    fn supports(&self, t: &AuthStrategy) -> bool;
}

trait ResponseExt {
    fn ext_context(self, ctx: &mut AuthContext) -> reqwest::Response;
}

impl ResponseExt for reqwest::Response {
    fn ext_context(self, ctx: &mut AuthContext) -> reqwest::Response {
        ctx.add_cookie(self.cookies());
        self
    }
}

trait RequestBuilderExt {
    fn ext_cookie(self, ctx: &mut AuthContext) -> reqwest::RequestBuilder;
}

impl RequestBuilderExt for reqwest::RequestBuilder {
    fn ext_cookie(self, ctx: &mut AuthContext) -> reqwest::RequestBuilder {
        self.header(header::COOKIE, ctx.get_cookie())
    }
}

struct AuthContext<'a> {
    account: &'a model::AuthAccount,
    cookie: HashSet<String>,
    csrf_token: String,
    auth_url: String,
    state: String,
    code_verifier: String,
    code_challenge: String,
}

impl<'a> AuthContext<'a> {
    pub(super) fn new(account: &'a model::AuthAccount) -> AuthContext<'_> {
        Self {
            account,
            cookie: HashSet::new(),
            csrf_token: String::new(),
            auth_url: String::new(),
            state: String::new(),
            code_verifier: String::new(),
            code_challenge: String::new(),
        }
    }

    pub(super) fn add_cookie<'b>(
        &mut self,
        c: impl Iterator<Item = reqwest::cookie::Cookie<'b>> + 'b,
    ) {
        c.for_each(|v| {
            let _ = self.cookie.insert(format!("{}={}", v.name(), v.value()));
        });
    }

    pub(super) fn get_cookie(&self) -> String {
        self.cookie.iter().cloned().collect::<Vec<_>>().join("; ")
    }

    pub(super) fn set_csrf_token(&mut self, csrf_token: &str) {
        self.csrf_token = csrf_token.to_owned();
    }

    pub(super) fn set_auth_url(&mut self, auth_url: &str) {
        if self.auth_url.is_empty() {
            self.auth_url.push_str(auth_url);
        }
    }

    pub(super) fn set_state(&mut self, state: &str) {
        if self.state.is_empty() {
            self.state.push_str(state);
        }
    }

    pub(super) fn set_code_verifier(&mut self, code_verifier: String) {
        if self.code_verifier.is_empty() {
            self.code_verifier.push_str(&code_verifier);
        }
    }

    pub(super) fn set_code_challenge(&mut self, code_challenge: String) {
        if self.code_challenge.is_empty() {
            self.code_challenge.push_str(&code_challenge);
        }
    }

    pub(super) async fn load_arkose_token(&mut self) -> AuthResult<()> {
        let arkose_token = match self.account.arkose_token.as_deref() {
            Some(arkose_token) => ArkoseToken::from(arkose_token),
            None => arkose::ArkoseToken::new_from_context(Type::Auth0)
                .await
                .map_err(AuthError::InvalidArkoseToken)?,
        };

        self.cookie
            .insert(format!("arkoseToken={}", arkose_token.value()));
        Ok(())
    }
}

#[derive(Serialize, Builder)]
pub(super) struct IdentifierData<'a> {
    state: &'a str,
    username: &'a str,
    #[serde(rename = "js-available")]
    js_available: bool,
    #[serde(rename = "webauthn-available")]
    webauthn_available: bool,
    #[serde(rename = "is-brave")]
    is_brave: bool,
    #[serde(rename = "webauthn-platform-available")]
    webauthn_platform_available: bool,
    action: &'a str,
}

#[derive(Clone)]
pub(super) enum GrantType {
    AuthorizationCode,
    RefreshToken,
}

impl Serialize for GrantType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            GrantType::AuthorizationCode => serializer.serialize_str("authorization_code"),
            GrantType::RefreshToken => serializer.serialize_str("refresh_token"),
        }
    }
}

#[derive(Serialize, Builder)]
pub(super) struct AuthenticateData<'a> {
    state: &'a str,
    username: &'a str,
    password: &'a str,
    action: &'a str,
}

#[derive(Serialize, Builder)]
pub(super) struct AuthenticateMfaData<'a> {
    state: &'a str,
    code: &'a str,
    action: &'a str,
}

#[derive(Serialize, Builder)]
pub(super) struct AuthorizationCodeData<'a> {
    redirect_uri: &'a str,
    grant_type: GrantType,
    client_id: &'a str,
    code_verifier: Option<&'a str>,
    code: &'a str,
}

#[derive(Serialize, Builder)]
pub(super) struct RevokeTokenData<'a> {
    client_id: &'a str,
    token: &'a str,
}

#[derive(Serialize, Builder)]
pub(super) struct RefreshTokenData<'a> {
    redirect_uri: &'a str,
    grant_type: GrantType,
    client_id: &'a str,
    refresh_token: &'a str,
}

#[derive(Serialize, Builder)]
pub(super) struct GetAuthorizedUrlData<'a> {
    #[serde(rename = "callbackUrl")]
    callback_url: &'a str,
    #[serde(rename = "csrfToken")]
    csrf_token: &'a str,
    json: &'a str,
}
