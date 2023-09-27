use crate::now_duration;

use jsonwebtokens::{Algorithm, AlgorithmID, Verifier};
use serde::{Deserialize, Serialize};

pub const PUBLIC_KEY: &[u8] = "-----BEGIN PUBLIC KEY-----\n\
MIIC+zCCAeOgAwIBAgIJLlfMWYK8snRdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAM\n\
TEG9wZW5haS5hdXRoMC5jb20wHhcNMjAwMjExMDUyMjI5WhcNMzMxMDIwMDUyMjI5Wj\n\
AbMRkwFwYDVQQDExBvcGVuYWkuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCA\n\
Q8AMIIBCgKCAQEA27rOErDOPvPc3mOADYtQBeenQm5NS5VHVaoO/Zmgsf1M0Wa/2WgL\n\
m9jX65Ru/K8Az2f4MOdpBxxLL686ZS+K7eJC/oOnrxCRzFYBqQbYo+JMeqNkrCn34ye\n\
d4XkX4ttoHi7MwCEpVfb05Qf/ZAmNI1XjecFYTyZQFrd9LjkX6lr05zY6aM/+MCBNeB\n\
Wp35pLLKhiq9AieB1wbDPcGnqxlXuU/bLgIyqUltqLkr9JHsf/2T4VrXXNyNeQyBq5w\n\
jYlRkpBQDDDNOcdGpx1buRrZ2hFyYuXDRrMcR6BQGC0ur9hI5obRYlchDFhlb0ElsJ2\n\
bshDDGRk5k3doHqbhj2IgQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQ\n\
WBBSzpMyU3UZWR9zdv+ckg/L6GZCcJDAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQ\n\
ELBQADggEBAEuUscoo1BZmCUZG8TEki0NHFjv08u2SHdcMU1xR0PfyKY6h+pLrSrGq8\n\
kYfjCHb/OPt0+Han0fiGRTnKurQ/u1leuJ7qHVHRILmP3e1MC8PUELjHpBo3f38Kk6U\n\
lbR5pbL5K7ZHeEO6CLNTOg54xLY/6e2ben4wv/LP39E6Gg56+iT/goJHkV64+nu3v3d\n\
Tmj+uSHWfkq93oG5tsOk2nTN4UCpyT5fWGv4eh7q2cKElMQM5GT/uZnCjEdDmJU2M11\n\
k6Ttg+FMNPgvH6R4e+lqhtmslXwXv9Xm95eS6JokJaYUimNX+dzhD+eRq+88vGJO63s\n\
afkEyGvifAMJFPwO78=\n\
-----END PUBLIC KEY-----"
    .as_bytes();

pub type TokenResult<T, E = anyhow::Error> = anyhow::Result<T, E>;

#[cfg(feature = "remote-token")]
#[derive(Deserialize)]
struct Keys {
    alg: String,
    x5c: Vec<String>,
}

#[cfg(feature = "remote-token")]
#[derive(Deserialize)]
struct KeyResult {
    keys: Vec<Keys>,
}

#[cfg(feature = "remote--token")]
async fn keys() -> TokenResult<KeyResult> {
    use crate::context::Context;
    use crate::error::AuthError;
    let client = context::get_instance().load_client();
    let resp = client
        .get("https://auth0.openai.com/.well-known/jwks.json")
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await?;
    if resp.status().is_success() {
        let keys = resp.json::<KeyResult>().await?;
        return Ok(keys);
    }
    anyhow::bail!(AuthError::FailedPubKeyRequest)
}

fn check_info(token: &str, pub_key: &[u8], alg: AlgorithmID) -> TokenResult<TokenProfile> {
    let alg = Algorithm::new_rsa_pem_verifier(alg, pub_key)?;
    let verifier = Verifier::create().build()?;
    let claims = verifier.verify(token, &alg)?;
    let claims_str = claims.to_string();
    if claims_str.contains("https://openai.openai.auth0app.com/userinfo")
        && claims_str.contains("https://auth0.openai.com/")
        && claims_str.contains("https://api.openai.com/v1")
        && claims_str.contains("model.read")
        && claims_str.contains("model.request")
    {
        return Ok(serde_json::from_value(claims)?);
    }
    anyhow::bail!("invalid access token")
}

pub fn check_for_u8(token: &[u8]) -> TokenResult<Option<TokenProfile>> {
    let x = String::from_utf8(token.to_vec())?;
    check(&x)
}

#[cfg(feature = "remote-token")]
pub async fn await_check_for_u8(token: &[u8]) -> TokenResult<Option<TokenProfile>> {
    let x = String::from_utf8(token.to_vec())?;
    await_check(&x).await
}

#[cfg(feature = "remote-token")]
pub fn await_check(token: &str) -> TokenResult<Option<TokenProfile>> {
    let token = token.trim_start_matches("Bearer ");
    if token.starts_with("sk-") || token.starts_with("sess-") {
        return Ok(None);
    }
    let key_result = keys().await?;
    let key = key_result
        .keys
        .first()
        .ok_or(AuthError::FailedPubKeyRequest)?;
    let pub_key = key.x5c.first().ok_or(AuthError::FailedPubKeyRequest)?;
    let pub_key = format!("-----BEGIN PUBLIC KEY-----{pub_key}-----END PUBLIC KEY-----");
    let alg = AlgorithmID::from_str(key.alg.as_str())?;
    Ok(Some(check_info(token, pub_key.as_bytes(), alg)))
}

pub fn check(token: &str) -> TokenResult<Option<TokenProfile>> {
    let token = token.trim_start_matches("Bearer ");
    if token.starts_with("sk-") || token.starts_with("sess-") {
        return Ok(None);
    }
    Ok(Some(check_info(token, PUBLIC_KEY, AlgorithmID::RS256)?))
}

#[derive(Default, Serialize, Deserialize)]
pub struct TokenProfile {
    #[serde(rename = "https://api.openai.com/profile")]
    pub https_api_openai_com_profile: HttpsApiOpenaiComProfile,
    #[serde(rename = "https://api.openai.com/auth", default)]
    pub https_api_openai_com_auth: HttpsApiOpenaiComAuth,
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub iat: i64,
    pub exp: i64,
    pub azp: String,
    pub scope: String,
}

impl TokenProfile {
    pub fn email(&self) -> &str {
        &self.https_api_openai_com_profile.email
    }

    pub fn user_id(&self) -> &str {
        &self.https_api_openai_com_auth.user_id
    }

    pub fn expires(&self) -> i64 {
        self.exp
    }

    pub fn expires_in(&self) -> i64 {
        let current_timestamp = now_duration()
            .expect("Failed to get current timestamp")
            .as_secs();
        self.exp - (current_timestamp as i64)
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct HttpsApiOpenaiComProfile {
    pub email: String,
    pub email_verified: bool,
}

#[derive(Default, Serialize, Deserialize)]
pub struct HttpsApiOpenaiComAuth {
    #[serde(default)]
    pub user_id: String,
}
