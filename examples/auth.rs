use std::{path::PathBuf, time};

use openai::auth::{
    model::{AuthAccount, AuthStrategy},
    provide::AuthProvider,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ctx = openai::context::ContextArgs::builder()
        .arkose_auth_har_file(PathBuf::from(
            "/Users/gngpp/VSCode/ninja/login.chat.openai.com.har",
        ))
        .build();
    openai::context::init(ctx);
    let email = std::env::var("EMAIL")?;
    let password = std::env::var("PASSWORD")?;
    let auth = openai::auth::AuthClientBuilder::builder()
        .user_agent(openai::HEADER_UA)
        .timeout(time::Duration::from_secs(30))
        .connect_timeout(time::Duration::from_secs(10))
        .build();
    let token = auth
        .do_access_token(
            &AuthAccount::builder()
                .username(email)
                .password(password)
                .option(AuthStrategy::Web)
                .build(),
        )
        .await?;
    let auth_token = openai::token::model::AuthenticateToken::try_from(token)?;
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
