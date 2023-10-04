use colored_json::prelude::*;
use inquire::{min_length, required, Select, Text};
use openai::auth::AuthHandle;

use crate::inter::{context::Context, new_spinner, render_config, standard::OAuth};

use super::login_prompt;

pub async fn oauth_prompt() -> anyhow::Result<()> {
    loop {
        let wizard = tokio::task::spawn_blocking(move || {
            Select::new("OAuth Wizard ›", OAuth::OAUTH_VARS.to_vec())
                .with_render_config(render_config())
                .with_formatter(&|i| format!("${i}"))
                .with_help_message("↑↓ to move, enter to select, type to filter, Esc to quit")
                .with_vim_mode(true)
                .prompt_skippable()
        })
        .await??;

        if let Some(wizard) = wizard {
            match wizard {
                OAuth::AccessToken => do_access_token().await?,
                OAuth::RefreshToken => do_refresh_token().await?,
                OAuth::RevokeToken => do_revoke_token().await?,
            }
        } else {
            // Esc to quit
            return Ok(());
        }
    }
}

async fn do_access_token() -> anyhow::Result<()> {
    match login_prompt(None).await {
        Ok(token) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&token)?.to_colored_json_auto()?
            )
        }
        Err(err) => println!("Error: {err}"),
    }
    Ok(())
}

async fn do_refresh_token() -> anyhow::Result<()> {
    let refresh_token = tokio::task::spawn_blocking(move || {
        Text::new("Please enter refresh token:")
            .with_render_config(render_config())
            .with_validator(required!("refresh token is required"))
            .with_validator(min_length!(5))
            .with_help_message("OpenAI account refresh token, Esc to quit")
            .prompt_skippable()
    })
    .await??;

    if let Some(refresh_token) = refresh_token {
        let pb = new_spinner("Waiting...");
        match Context::get_auth_client()
            .await
            .do_refresh_token(&refresh_token)
            .await
        {
            Ok(token) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&token)?.to_colored_json_auto()?
                )
            }
            Err(error) => {
                println!("Error: {error}")
            }
        }
        pb.finish_with_message("Done");
    }

    Ok(())
}

async fn do_revoke_token() -> anyhow::Result<()> {
    let refresh_token = tokio::task::spawn_blocking(move || {
        Text::new("Please enter refresh token:")
            .with_render_config(render_config())
            .with_validator(required!("refresh token is required"))
            .with_validator(min_length!(5))
            .with_help_message("OpenAI account refresh token, Esc to quit")
            .prompt_skippable()
    })
    .await??;

    if let Some(refresh_token) = refresh_token {
        let pb = new_spinner("Waiting...");
        let _ = Context::get_auth_client()
            .await
            .do_revoke_token(&refresh_token)
            .await;
        pb.finish_with_message("Done")
    }
    Ok(())
}
