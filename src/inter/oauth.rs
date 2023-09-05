use inquire::{min_length, required, Select, Text};
use openai::auth::AuthHandle;

use crate::util;

use super::{
    context::{login_prompt, AUTH_CLIENT},
    enums::OAuth,
    render_config,
};

use colored_json::prelude::*;

pub(super) async fn oauth_prompt() -> anyhow::Result<()> {
    loop {
        let wizard = Select::new("OAuth Wizard ›", OAuth::OAUTH_VARS.to_vec())
            .with_render_config(render_config())
            .with_formatter(&|i| format!("${i}"))
            .with_vim_mode(true)
            .prompt_skippable()?;

        if let Some(wizard) = wizard {
            match wizard {
                OAuth::AccessToken => do_access_token().await?,
                OAuth::RefreshToken => do_refresh_token().await?,
                OAuth::RevokeToken => do_revoke_token().await?,
                OAuth::Quit => return Ok(()),
            }
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
        let mut pb = util::long_spinner_progress_bar("Waiting...");
        pb.start();
        match AUTH_CLIENT.do_refresh_token(&refresh_token).await {
            Ok(token) => {
                pb.finish_and_clear().await;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&token)?.to_colored_json_auto()?
                )
            }
            Err(error) => {
                pb.finish_and_clear().await;
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
        let mut pb = util::long_spinner_progress_bar("Waiting...");
        pb.start();
        match AUTH_CLIENT.do_revoke_token(&refresh_token).await {
            Ok(_) => {}
            Err(_) => {}
        }
        pb.finish_and_clear().await;
    }
    Ok(())
}
