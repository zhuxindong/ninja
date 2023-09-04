use inquire::{min_length, required, validator::Validation, Confirm, CustomType, Select, Text};
use openai::auth::{model::AuthStrategy, AuthHandle};

use crate::{
    store::{conf::Conf, Store},
    util,
};

use super::{
    context::{self, login_prompt, ACCOUNT_STORE_HOLDER, CONF_STORE_HOLDER},
    render_config,
};

use colored_json::prelude::*;

pub(super) async fn config_prompt() -> anyhow::Result<()> {
    let valid_url = |s: &str| {
        if !s.is_empty() {
            if let Some(err) = util::parse_url(s).err() {
                Ok(Validation::Invalid(
                    inquire::validator::ErrorMessage::Custom(err.to_string()),
                ))
            } else {
                Ok(Validation::Valid)
            }
        } else {
            Ok(Validation::Valid)
        }
    };
    let store = CONF_STORE_HOLDER.get_instance();
    let mut conf = store.get(Conf::default())?.unwrap_or(Conf::default());
    let mut official_api = Text::new("Official API prefix ›")
        .with_render_config(render_config())
        .with_help_message("Example: https://example.com")
        .with_validator(valid_url);
    if let Some(content) = conf.official_api.as_deref() {
        if !content.is_empty() {
            official_api = official_api.with_initial_value(content)
        }
    }

    let mut unofficial_api = Text::new("Unofficial API prefix ›")
        .with_render_config(render_config())
        .with_help_message("Example: https://example.com")
        .with_validator(valid_url);
    if let Some(content) = conf.unofficial_api.as_deref() {
        if !content.is_empty() {
            unofficial_api = unofficial_api.with_initial_value(content)
        }
    };

    let mut proxy = Text::new("Client proxy ›")
        .with_render_config(render_config())
        .with_help_message("Example: https://example.com")
        .with_validator(valid_url);
    if let Some(content) = conf.proxy.as_deref() {
        if !content.is_empty() {
            proxy = proxy.with_initial_value(content)
        }
    };

    let mut arkose_token_endpoint = Text::new("Arkose token endpoint ›")
        .with_render_config(render_config())
        .with_help_message("Example: https://example.com")
        .with_validator(valid_url);
    if let Some(content) = conf.arkose_token_endpoint.as_deref() {
        arkose_token_endpoint = arkose_token_endpoint.with_initial_value(content)
    };

    let mut arkose_har_path = Text::new("Arkose HAR path ›")
        .with_render_config(render_config())
        .with_help_message("About the browser HAR file path requested by ArkoseLabs");
    if let Some(content) = conf.arkose_har_path.as_deref() {
        arkose_har_path = arkose_har_path.with_initial_value(content)
    };

    let mut arkose_yescaptcha_key = Text::new("Arkose YesCaptcha key ›")
        .with_render_config(render_config())
        .with_help_message("About the YesCaptcha platform client key solved by ArkoseLabs");
    if let Some(content) = conf.arkose_yescaptcha_key.as_deref() {
        arkose_yescaptcha_key = arkose_yescaptcha_key.with_initial_value(content)
    };

    conf.official_api = official_api.prompt_skippable()?;
    conf.unofficial_api = unofficial_api.prompt_skippable()?;
    conf.proxy = proxy.prompt_skippable()?;
    conf.arkose_token_endpoint = arkose_token_endpoint.prompt_skippable()?;
    conf.arkose_har_path = arkose_har_path.prompt_skippable()?;
    conf.arkose_yescaptcha_key = arkose_yescaptcha_key.prompt_skippable()?;

    let timeout = CustomType::<usize>::new("Client timeout (seconds) ›")
        .with_render_config(render_config())
        .with_formatter(&|i| format!("${i:.2}"))
        .with_error_message("Please type a valid number")
        .with_default(conf.timeout)
        .prompt_skippable()?;

    let connect_timeout = CustomType::<usize>::new("Client connect timeout (seconds) ›")
        .with_render_config(render_config())
        .with_formatter(&|i| format!("${i:.2}"))
        .with_error_message("Please type a valid number")
        .with_default(conf.connect_timeout)
        .prompt_skippable()?;

    let tcp_keepalive = CustomType::<usize>::new("TCP keepalive (seconds) ›")
        .with_render_config(render_config())
        .with_formatter(&|i| format!("${i:.2}"))
        .with_error_message("Please type a valid number")
        .with_default(conf.tcp_keepalive)
        .prompt_skippable()?;

    if let Some(timeout) = timeout {
        conf.timeout = timeout;
    }

    if let Some(connect_timeout) = connect_timeout {
        conf.connect_timeout = connect_timeout;
    }

    if let Some(tcp_keepalive) = tcp_keepalive {
        conf.tcp_keepalive = tcp_keepalive;
    }

    store.add(conf)?;

    Ok(())
}

pub(super) async fn oauth_prompt() -> anyhow::Result<()> {
    let wizard = Select::new(
        "OAuth Wizard ›",
        vec!["token", "revoke_token", "refresh_token"],
    )
    .with_render_config(render_config())
    .with_formatter(&|i| format!("${i}"))
    .with_vim_mode(true)
    .prompt_skippable()?;

    if let Some(wizard) = wizard {
        match wizard {
            "token" => do_access_token().await?,
            "revoke_token" => do_revoke_token().await?,
            "refresh_token" => do_refresh_token().await?,
            _ => {}
        }
    }
    Ok(())
}

pub(super) async fn dashboard_prompt() -> anyhow::Result<()> {
    let store = ACCOUNT_STORE_HOLDER.get_instance();
    match store.list() {
        Ok(account_list) => {
            if account_list.is_empty() {
                let ans = Confirm::new("Do you need to login to continue?")
                    .with_render_config(render_config())
                    .with_default(false)
                    .with_help_message("You need to log in to your account to continue")
                    .prompt();

                match ans {
                    Ok(true) => context::login_store_prompt(AuthStrategy::Platform).await,
                    _ => {}
                }
            } else {
                for account in account_list {
                    if let Some(_authenticate_token) = account.state().get(&AuthStrategy::Platform)
                    {
                        println!("{_authenticate_token:#?}")
                    }
                }
            }
        }
        Err(err) => {
            eprintln!("Error: {err}")
        }
    }
    Ok(())
}

async fn do_access_token() -> anyhow::Result<()> {
    match login_prompt(None).await {
        Ok(token) => {
            println!(
                "\n{}",
                serde_json::to_string_pretty(&token)?.to_colored_json_auto()?
            )
        }
        Err(_) => println!("Login failed!"),
    }
    Ok(())
}

async fn do_refresh_token() -> anyhow::Result<()> {
    let auth = context::AUTH_CLIENT_HOLDER.get_instance();
    let refresh_token = Text::new("Please enter refresh token:")
        .with_render_config(render_config())
        .with_validator(required!("refresh token is required"))
        .with_validator(min_length!(5))
        .with_help_message("OpenAI account refresh token, Esc to quit")
        .prompt_skippable()?;

    if let Some(refresh_token) = refresh_token {
        let mut pb = util::long_spinner_progress_bar("Waiting...");
        pb.start();
        match auth.do_refresh_token(&refresh_token).await {
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
    let auth = context::AUTH_CLIENT_HOLDER.get_instance();
    let refresh_token = Text::new("Please enter refresh token:")
        .with_render_config(render_config())
        .with_validator(required!("refresh token is required"))
        .with_validator(min_length!(5))
        .with_help_message("OpenAI account refresh token, Esc to quit")
        .prompt_skippable()?;
    if let Some(refresh_token) = refresh_token {
        let mut pb = util::long_spinner_progress_bar("Waiting...");
        pb.start();
        match auth.do_revoke_token(&refresh_token).await {
            Ok(_) => {}
            Err(_) => {}
        }
        pb.finish_and_clear().await;
    }
    Ok(())
}
