use std::time;

use openai::auth::AuthHandle;

pub(crate) async fn handle_prompt() -> anyhow::Result<()> {
    let account = super::account_prompt()?;
    let auth = openai::auth::AuthClientBuilder::builder()
        .timeout(time::Duration::from_secs(1000))
        .connect_timeout(time::Duration::from_secs(1000))
        .cookie_store(true)
        .build();

    let token = auth.do_access_token(&account).await;

    match token {
        Ok(token) => match token {
            openai::auth::model::AccessToken::Web(token) => println!("{:?}", token.access_token),
            openai::auth::model::AccessToken::Apple(token) => println!("{:?}", token.access_token),
        },
        Err(_) => println!("Login failed!"),
    }
    let _chatgpt = openai::chatgpt::ChatGPTBuilder::builder().build();
    Ok(())
}
