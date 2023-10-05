pub mod apple;
pub mod platform;
pub mod web;

use super::model::{self, AuthStrategy};
use derive_builder::Builder;
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
