use std::str::FromStr;

use crate::token::TokenProfile;
use crate::{serve::error::ResponseError, token::model::Token};
use base64::Engine;
use serde::{Deserialize, Serialize};

/// ChatGPT session
#[derive(Serialize, Deserialize)]
pub struct Session {
    pub access_token: String,
    pub refresh_token: Option<String>,
    #[serde(skip_serializing)]
    pub session_token: Option<String>,
    pub user_id: String,
    pub email: String,
    pub expires: i64,
}

impl Session {
    /// Convert session to base64 string
    pub fn to_string(&self) -> Result<String, ResponseError> {
        let json = serde_json::to_string(&self).map_err(ResponseError::Unauthorized)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(json.as_bytes()))
    }
}

/// Parse session from base64 string
impl FromStr for Session {
    type Err = ResponseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(ResponseError::Unauthorized)?;
        serde_json::from_slice(&data).map_err(ResponseError::Unauthorized)
    }
}

/// Convert token to session
impl From<Token> for Session {
    fn from(value: Token) -> Self {
        Session {
            user_id: value.user_id().to_owned(),
            email: value.email().to_owned(),
            expires: value.expires(),
            access_token: value.access_token().to_owned(),
            refresh_token: value.refresh_token().map(|v| v.to_owned()),
            session_token: value.session_token().map(|v| v.to_owned()),
        }
    }
}

/// Parse from access token and token profile
impl From<(&str, TokenProfile)> for Session {
    fn from(value: (&str, TokenProfile)) -> Self {
        Session {
            user_id: value.1.user_id().to_owned(),
            email: value.1.email().to_owned(),
            expires: value.1.expires(),
            access_token: value.0.to_owned(),
            refresh_token: None,
            session_token: None,
        }
    }
}
