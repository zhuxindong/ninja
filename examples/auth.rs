use std::{path::PathBuf, time};

use openai::auth::{
    model::{AuthAccountBuilder, AuthStrategy},
    provide::AuthProvider,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ctx = openai::context::ContextArgsBuilder::default()
        .arkose_auth_har_file(PathBuf::from(
            "/Users/gngpp/VSCode/ninja/login.chat.openai.com.har",
        ))
        .build()
        .unwrap();
    openai::context::init(ctx);
    let email = std::env::var("EMAIL")?;
    let password = std::env::var("PASSWORD")?;
    let auth = openai::auth::AuthClientBuilder::builder()
        .user_agent(openai::HEADER_UA)
        .timeout(time::Duration::from_secs(1000))
        .proxy(Some("socks5://10.0.2.1:1081".to_owned()))
        .preauth_api(Some("https://ai.fakeopen.com/auth/preauth".to_owned()))
        .connect_timeout(time::Duration::from_secs(1000))
        .build();
    let token = auth
        .do_access_token(
            &AuthAccountBuilder::default()
                .username(email)
                .password(password)
                .option(AuthStrategy::Apple)
                .build()?,
        )
        .await?;
    let auth_token = openai::model::AuthenticateToken::try_from(token)?;
    println!("AuthenticationToken: {:#?}", auth_token);
    println!("AccessToken: {}", auth_token.access_token());

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    if let Some(refresh_token) = auth_token.refresh_token() {
        println!("RefreshToken: {}", refresh_token);
        let refresh_token = auth.do_refresh_token(refresh_token).await?;
        println!("RefreshToken: {}", refresh_token.refresh_token);
        auth.do_revoke_token(&refresh_token.refresh_token).await?;
    }

    Ok(())
}
