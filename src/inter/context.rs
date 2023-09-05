use crate::inter::render_config;
use crate::store::conf::Conf;
use anyhow::Context;
use inquire::{min_length, required, Password, PasswordDisplayMode, Select, Text};
use once_cell::sync::Lazy;
use openai::auth::{AuthClient, AuthClientBuilder};
use openai::{
    auth::{
        model::{AccessToken, AuthAccount, AuthStrategy},
        AuthHandle,
    },
    model::AuthenticateToken,
};

use std::time;

use crate::{
    store::{
        account::{Account, AccountFileStore},
        conf::ConfFileStore,
        Store,
    },
    util,
};

pub static ACCOUNT_STORE: Lazy<AccountFileStore> = Lazy::new(|| AccountFileStore::new());

pub static CONF_STORE: Lazy<ConfFileStore> = Lazy::new(|| ConfFileStore::new());

pub static AUTH_CLIENT: Lazy<AuthClient> = Lazy::new(|| {
    let auth_client = match CONF_STORE
        .get(Conf::default())
        .expect("Failed to read configuration")
    {
        Some(conf) => AuthClientBuilder::builder()
            .proxy(conf.proxy)
            .timeout(time::Duration::from_secs(conf.timeout as u64))
            .connect_timeout(time::Duration::from_secs(conf.connect_timeout as u64))
            .tcp_keepalive(time::Duration::from_secs(conf.tcp_keepalive as u64))
            .cookie_store(true)
            .build(),
        None => AuthClientBuilder::builder()
            .timeout(time::Duration::from_secs(600))
            .connect_timeout(time::Duration::from_secs(60))
            .cookie_store(true)
            .build(),
    };
    auth_client
});

pub async fn login_prompt(auth_strategy: Option<AuthStrategy>) -> anyhow::Result<AccessToken> {
    let auth_strategy = if let Some(auth_strategy) = auth_strategy {
        auth_strategy
    } else {
        Select::new(
            "Please choose the authentication strategy ›",
            vec![
                AuthStrategy::Web,
                AuthStrategy::Apple,
                AuthStrategy::Platform,
            ],
        )
        .prompt()?
    };
    let username = Text::new("Email ›")
        .with_render_config(render_config())
        .with_validator(required!("email is required"))
        .with_validator(min_length!(5))
        .with_help_message("OpenAI account email, Format: example@gmail.com")
        .prompt()?;

    let password = Password::new("Password ›")
        .with_render_config(render_config())
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_validator(required!("password is required"))
        .with_validator(min_length!(5))
        .with_help_message("OpenAI account password")
        .without_confirmation()
        .prompt()
        .context("An error happened when asking for your account, try again later.")?;

    let mfa_res = Text::new("MFA Code [Option] ›")
        .with_render_config(render_config())
        .with_help_message("OpenAI account MFA Code, If it is empty, please enter directly.")
        .prompt_skippable();

    let mfa_code = match mfa_res {
        Ok(mfa_code) => mfa_code,
        Err(_) => {
            println!("An error happened when asking for your mfa code, try again later.");
            None
        }
    };

    let auth_account = AuthAccount {
        username,
        password,
        mfa: mfa_code,
        option: auth_strategy.into(),
        cf_turnstile_response: None,
    };

    let mut pb = util::long_spinner_progress_bar("Logging...");
    pb.start();
    let result = AUTH_CLIENT.do_access_token(&auth_account).await;
    pb.finish_and_clear().await;
    result
}

pub async fn login_store_prompt(auth_strategy: AuthStrategy) {
    match login_prompt(Some(auth_strategy.clone())).await {
        Ok(token) => {
            if let Ok(authenticate_token) = AuthenticateToken::try_from(token) {
                let mut account = Account::new(authenticate_token.email());
                account.push_state(auth_strategy, authenticate_token);
                if let Some(err) = ACCOUNT_STORE.add(account).err() {
                    eprintln!("Error: {err}")
                } else {
                    println!("Login success!")
                }
            }
        }
        Err(err) => {
            eprintln!("Login error: {err}")
        }
    }
}
