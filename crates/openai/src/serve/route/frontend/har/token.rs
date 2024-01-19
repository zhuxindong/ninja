use std::path::PathBuf;

use jsonwebtokens::{encode, Algorithm, AlgorithmID, Verifier};
use serde_json::json;
use tokio::sync::OnceCell;

use crate::{
    arkose::{self},
    generate_random_string,
    homedir::home_dir,
    now_duration, with_context,
};

static TOKEN_SECRET: OnceCell<String> = OnceCell::const_new();
pub(super) const EXP: u64 = 3600 * 24;

async fn get_or_init_secret() -> &'static String {
    TOKEN_SECRET
        .get_or_init(|| async {
            let path = home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".token_secret");
            let key = if let Some(upload_key) = with_context!(arkose_har_upload_key) {
                upload_key.to_owned()
            } else {
                generate_random_string(31)
            };
            let x = arkose::murmur::murmurhash3_x64_128(key.as_bytes(), 31);
            let s = format!("{:x}{:x}", x.0, x.1,);
            tokio::fs::write(&path, &s)
                .await
                .expect("write token secret to file");
            s
        })
        .await
}

pub(super) async fn generate_token() -> anyhow::Result<String> {
    let s = get_or_init_secret().await;
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, s.to_owned())?;
    let header = json!({ "alg": alg.name() });
    let claims = json!({
       "exp": now_duration()?.as_secs() + EXP,
    });
    Ok(encode(&header, &claims, &alg)?)
}

pub(super) async fn verifier(token_str: &str) -> anyhow::Result<()> {
    let s = get_or_init_secret().await;
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, s.to_owned())?;
    let verifier = Verifier::create().build()?;
    let _ = verifier.verify(&token_str, &alg)?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_generate_token() {
        let token = generate_token().await.unwrap();
        println!("{}", token);
    }

    #[tokio::test]
    async fn test_verifier() {
        let token = generate_token().await.unwrap();
        verifier(&token).await.unwrap();
    }
}
