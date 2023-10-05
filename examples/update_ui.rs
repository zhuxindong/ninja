use std::sync::Arc;

use openai::auth;
use reqwest::cookie::Jar;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let html_404 = "https://chat.openai.com/404";
    let html_chat = "https://chat.openai.com";
    let html_details = "https://chat.openai.com/details";

    let jar = Arc::new(Jar::default());
    let auth_client = auth::AuthClientBuilder::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(500))
        .impersonate(reqwest::impersonate::Impersonate::OkHttpAndroid13)
        .user_agent(openai::HEADER_UA)
        .cookie_provider(jar.clone())
        .build();

    let client = reqwest::Client::builder()
        .cookie_provider(jar)
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(500))
        .impersonate(reqwest::impersonate::Impersonate::OkHttpAndroid13)
        .build()?;

    Ok(())
}
