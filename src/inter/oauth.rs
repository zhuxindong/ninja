use super::{context::Context, enums::OAuth, render_config, ProgressBar};
use colored_json::prelude::*;
use inquire::{min_length, required, Select, Text};

use crate::store::{account::Account, Store};
use inquire::{Password, PasswordDisplayMode};
use openai::{
    auth::{
        model::{AccessToken, AuthAccount, AuthStrategy},
        AuthHandle,
    },
    model::AuthenticateToken,
};

pub(super) async fn oauth_prompt() -> anyhow::Result<()> {
    loop {
        let wizard = tokio::task::spawn_blocking(move || {
            Select::new("OAuth Wizard ›", OAuth::OAUTH_VARS.to_vec())
                .with_render_config(render_config())
                .with_formatter(&|i| format!("${i}"))
                .with_vim_mode(true)
                .prompt()
        })
        .await??;

        match wizard {
            OAuth::AccessToken => do_access_token().await?,
            OAuth::RefreshToken => do_refresh_token().await?,
            OAuth::RevokeToken => do_revoke_token().await?,
            OAuth::Quit => return Ok(()),
        }
    }
}

async fn do_access_token() -> anyhow::Result<()> {
    match login_prompt(None).await {
        Ok(token) => {
            println!(
                "\n{}",
                serde_json::to_string_pretty(&token)?.to_colored_json_auto()?
            )
        }
        Err(err) => println!("Error: {err}"),
    }
    Ok(())
}

async fn do_refresh_token() -> anyhow::Result<()> {
    let refresh_token = Text::new("Please enter refresh token:")
        .with_render_config(render_config())
        .with_validator(required!("refresh token is required"))
        .with_validator(min_length!(5))
        .with_help_message("OpenAI account refresh token, Esc to quit")
        .prompt_skippable()?;

    if let Some(refresh_token) = refresh_token {
        let pb = ProgressBar::new("Waiting...");
        pb.start();
        match Context::get_auth_client()
            .await
            .do_refresh_token(&refresh_token)
            .await
        {
            Ok(token) => {
                pb.finish().await;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&token)?.to_colored_json_auto()?
                )
            }
            Err(error) => {
                pb.finish().await;
                println!("Error: {error}")
            }
        }
    }
    Ok(())
}

async fn do_revoke_token() -> anyhow::Result<()> {
    let refresh_token = Text::new("Please enter refresh token:")
        .with_render_config(render_config())
        .with_validator(required!("refresh token is required"))
        .with_validator(min_length!(5))
        .with_help_message("OpenAI account refresh token, Esc to quit")
        .prompt_skippable()?;
    if let Some(refresh_token) = refresh_token {
        let pb = ProgressBar::new("Waiting...");
        pb.start();
        let _ = Context::get_auth_client()
            .await
            .do_revoke_token(&refresh_token)
            .await;
        pb.finish().await;
    }
    Ok(())
}

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
        .prompt()?;

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
        option: auth_strategy,
        cf_turnstile_response: None,
    };

    let pb = ProgressBar::new("Logging...");
    pb.start();
    let result = Context::get_auth_client()
        .await
        .do_access_token(&auth_account)
        .await;
    pb.finish().await;
    result
}

pub async fn login_store_prompt(auth_strategy: AuthStrategy) {
    match login_prompt(Some(auth_strategy.clone())).await {
        Ok(token) => {
            if let Ok(authenticate_token) = AuthenticateToken::try_from(token) {
                let mut account = Account::new(authenticate_token.email());
                account.push_state(auth_strategy, authenticate_token);
                if let Some(err) = Context::get_account_store().await.add(account).err() {
                    eprintln!("Error: {err}")
                } else {
                    println!("Login success!")
                }
            }
        }
        Err(err) => {
            eprintln!("Error: {err}")
        }
    }
}
