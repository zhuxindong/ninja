use serde::{Deserialize, Serialize};

use base64::{engine::general_purpose, Engine};

use serde_json::Value;
use time::format_description::well_known::Rfc3339;

use crate::{
    auth::{self, model::AccessToken},
    now_duration,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthenticateToken {
    access_token: String,
    refresh_token: Option<String>,
    expires: i64,
    expires_in: i64,
    user_id: String,
    name: String,
    email: String,
    picture: String,
}

impl AuthenticateToken {
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn picture(&self) -> &str {
        &self.picture
    }

    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub fn bearer_access_token(&self) -> String {
        format!("Bearer {}", &self.access_token)
    }
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    pub fn is_expired(&self) -> bool {
        let duration = now_duration().expect("Time went backwards");
        (duration.as_secs() as i64) > self.expires
    }

    pub fn expires(&self) -> i64 {
        self.expires
    }

    pub fn expires_in(&self) -> i64 {
        self.expires_in
    }
}

impl TryFrom<auth::model::AccessToken> for AuthenticateToken {
    type Error = anyhow::Error;

    fn try_from(value: auth::model::AccessToken) -> Result<Self, Self::Error> {
        match value {
            AccessToken::Session(value) => {
                let expires_timestamp =
                    time::OffsetDateTime::parse(&value.expires, &Rfc3339)?.unix_timestamp();

                // current timestamp (secends)
                let current_timestamp = now_duration()?.as_secs() as i64;
                // expires (secends)
                let expires_in = expires_timestamp - current_timestamp;

                Ok(Self {
                    access_token: value.access_token,
                    refresh_token: None,
                    expires: expires_timestamp,
                    expires_in,
                    user_id: value.user.id,
                    name: value.user.name,
                    email: value.user.email,
                    picture: value.user.picture,
                })
            }
            AccessToken::OAuth(value) => {
                let profile = Profile::try_from(value.id_token)?;
                let expires = now_duration()?.as_secs() as i64 + value.expires_in;
                Ok(Self {
                    access_token: value.access_token,
                    refresh_token: Some(value.refresh_token),
                    expires,
                    expires_in: value.expires_in,
                    user_id: profile.https_api_openai_com_auth.user_id,
                    name: profile.name,
                    email: profile.email,
                    picture: profile.picture,
                })
            }
        }
    }
}

impl TryFrom<auth::model::RefreshToken> for AuthenticateToken {
    type Error = anyhow::Error;

    fn try_from(value: auth::model::RefreshToken) -> Result<Self, Self::Error> {
        let profile = Profile::try_from(value.id_token)?;
        let expires = now_duration()?.as_secs() as i64 + value.expires_in;
        Ok(Self {
            access_token: value.access_token,
            refresh_token: Some(value.refresh_token),
            expires,
            expires_in: value.expires_in,
            user_id: profile.https_api_openai_com_auth.user_id,
            name: profile.name,
            email: profile.email,
            picture: profile.picture,
        })
    }
}

#[allow(dead_code)]
#[derive(Deserialize, Default)]
struct Profile {
    #[serde(rename = "https://api.openai.com/auth", default)]
    https_api_openai_com_auth: HttpsApiOpenaiComAuth,
    nickname: String,
    name: String,
    picture: String,
    updated_at: String,
    email_verified: bool,
    email: String,
    iss: String,
    aud: String,
    iat: i64,
    exp: i64,
    sub: String,
    #[serde(default)]
    auth_time: i64,
}

impl TryFrom<String> for Profile {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let split_jwt_strings: Vec<_> = value.split('.').collect();
        let jwt_body = split_jwt_strings
            .get(1)
            .ok_or(anyhow::anyhow!("invalid access-token"))?;
        let decoded_jwt_body = general_purpose::URL_SAFE_NO_PAD.decode(jwt_body)?;
        let converted_jwt_body = String::from_utf8(decoded_jwt_body)?;
        let profile = serde_json::from_str::<Profile>(&converted_jwt_body)?;
        Ok(profile)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct HttpsApiOpenaiComAuth {
    groups: Vec<Value>,
    organizations: Vec<Organization>,
    user_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Organization {
    id: String,
    is_default: bool,
    role: String,
    title: String,
}
