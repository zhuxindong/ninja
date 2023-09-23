use inquire::{min_length, required, Select, Text};

use crate::inter::{context::Context, enums, render_config};
use inquire::{Password, PasswordDisplayMode};
use openai::auth::{
    model::{AccessToken, AuthAccount, AuthStrategy},
    AuthHandle,
};

use super::new_spinner;

pub mod oauth;
pub mod signin;

pub async fn prompt() -> anyhow::Result<()> {
    loop {
        let wizard = tokio::task::spawn_blocking(move || {
            Select::new(
                "Authorization Wizard ›",
                enums::Authorize::AUTHORIZE_VARS.to_vec(),
            )
            .with_render_config(render_config())
            .with_formatter(&|i| format!("${i}"))
            .with_help_message("↑↓ to move, enter to select, type to filter, Esc to quit")
            .with_vim_mode(true)
            .prompt_skippable()
        })
        .await??;

        if let Some(wizard) = wizard {
            match wizard {
                enums::Authorize::SignIn => signin::sign_in_prompt().await?,
                enums::Authorize::OAuth => oauth::oauth_prompt().await?,
            }
        } else {
            // Esc to quit
            return Ok(());
        }
    }
}

pub async fn login_prompt(auth_strategy: Option<AuthStrategy>) -> anyhow::Result<AccessToken> {
    let auth_strategy = if let Some(auth_strategy) = auth_strategy {
        auth_strategy
    } else {
        tokio::task::spawn_blocking(move || {
            Select::new(
                "Please choose the authentication strategy ›",
                vec![
                    AuthStrategy::Web,
                    AuthStrategy::Apple,
                    AuthStrategy::Platform,
                ],
            )
            .prompt()
        })
        .await??
    };

    let (username, password, mfa_res) = tokio::task::spawn_blocking(move || {
        let username = Text::new("Email ›")
            .with_render_config(render_config())
            .with_validator(required!("email is required"))
            .with_validator(min_length!(5))
            .with_help_message("OpenAI account email, Format: example@gmail.com")
            .prompt();

        let password = Password::new("Password ›")
            .with_render_config(render_config())
            .with_display_mode(PasswordDisplayMode::Masked)
            .with_validator(required!("password is required"))
            .with_validator(min_length!(5))
            .with_help_message("OpenAI account password")
            .without_confirmation()
            .prompt();

        let mfa_res = Text::new("MFA Code [Option] ›")
            .with_render_config(render_config())
            .with_help_message("OpenAI account MFA Code, If it is empty, please enter directly.")
            .prompt_skippable();

        (username, password, mfa_res)
    })
    .await?;

    let username = username?;
    let password = password?;

    let mfa_code = mfa_res
        .map_err(|_| {
            println!("An error happened when asking for your mfa code, try again later.");
        })
        .unwrap_or(None);

    let auth_account = AuthAccount {
        username,
        password,
        mfa: mfa_code,
        option: auth_strategy,
        cf_turnstile_response: None,
    };

    let pb = new_spinner("Authenticating...");
    let access_token = Context::get_auth_client()
        .await
        .do_access_token(&auth_account)
        .await?;
    pb.finish_and_clear();
    Ok(access_token)
}
