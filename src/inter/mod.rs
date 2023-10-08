mod authorize;
mod config;
mod context;
mod conversation;
mod dashboard;
mod standard;
mod valid;

use crate::{
    inter::conversation::{api, chatgpt},
    store::Store,
};
use indicatif::{ProgressBar, ProgressStyle};
use inquire::{
    ui::{
        Attributes, Color, ErrorMessageRenderConfig, IndexPrefix, RenderConfig, StyleSheet, Styled,
    },
    Select,
};
use openai::arkose::{funcaptcha, ArkoseToken, Type};
use openai::{
    auth::{model::AuthStrategy, provide::AuthProvider},
    model::AuthenticateToken,
};
use serde::Serialize;
use serde_json::json;
use standard::Usage;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task;

use self::context::Context;

pub async fn prompt() -> anyhow::Result<()> {
    Context::init_openai_context().await?;
    check_authorization().await?;
    print_boot_message().await;

    loop {
        let choice = task::spawn_blocking(move || {
            Select::new("Usage Wizard ›", Usage::USAGE_VARS.to_vec())
                .with_render_config(render_config())
                .with_formatter(&|i| format!("${i:.2}"))
                .with_help_message("↑↓ to move, enter to select, type to filter, Esc to quit")
                .prompt_skippable()
        })
        .await??;

        if let Some(choice) = choice {
            match choice {
                Usage::TurboAPI => api::prompt().await?,
                Usage::ChatGPT => chatgpt::prompt().await?,
                Usage::Dashboard => dashboard::prompt().await?,
                Usage::Authorize => authorize::prompt().await?,
                Usage::Config => config::prompt().await?,
            }
        } else {
            // Esc to quit
            break;
        }
    }
    Ok(())
}

async fn print_boot_message() {
    let logo = r"
    ____  _____  _              _         
    |_   \|_   _|(_)            (_)        
      |   \ | |  __  _ .--.     __  ,--.   
      | |\ \| | [  |[ `.-. |   [  |`'_\ :  
     _| |_\   |_ | | | | | | _  | |// | |, 
    |_____|\____[___|___||__| \_| |\'-;__/ 
                             \____/                            
   ";

    let welcome = "Welcome to Ninja terminal!";
    let enjoy = "You can enjoy professional GPT services";
    let repo = "Repository: https://github.com/gngpp/ninja\n";
    println!("\x1B[1m{logo}\x1B[1m");
    println!("\x1B[1m{welcome}\x1B[1m");
    println!("\x1B[1m{enjoy}\x1B[1m");
    if let Some(current_user) = Context::current_user().await {
        print!("\x1B[1m{repo}\x1B[1m");
        println!("\x1B[1mCurrent User: {current_user}\x1B[1m\n");
    } else {
        println!("\x1B[1m{repo}\x1B[1m");
    }
}

pub async fn check_authorization() -> anyhow::Result<()> {
    let store = Context::get_account_store().await;
    let client = Context::get_auth_client().await;
    let current_time = get_duration_since_epoch()?;

    for mut account in store.list()? {
        let mut change = false;

        let state = account.state_mut();
        // Remove expired token state
        state.retain(|_, token| {
            let expired = token.is_expired();
            if expired {
                change = true;
            }
            !expired
        });

        // Refresh if it is less than two weeks old
        for (k, token) in state.iter_mut() {
            if let AuthStrategy::Platform | AuthStrategy::Apple = k {
                let time_left = token.expires() - current_time;
                let difference = token.expires_in() / 10;
                if time_left < difference {
                    if let Some(refresh_token) = token.refresh_token() {
                        let pb = new_spinner("Initializing login...");
                        match client.do_refresh_token(refresh_token).await {
                            Ok(refresh_token) => {
                                let new_token = AuthenticateToken::try_from(refresh_token)?;
                                *token = new_token;
                                change = true;
                                pb.finish_and_clear();
                                tokio::time::sleep(Duration::from_secs(3)).await;
                            }
                            Err(_) => {
                                pb.finish_and_clear();
                            }
                        };
                    }
                }
            }
        }

        if change {
            store.store(account)?;
        }
    }

    Ok(())
}

fn get_duration_since_epoch() -> anyhow::Result<i64> {
    let duration_since_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(duration_since_epoch.as_secs() as i64)
}

pub fn render_config() -> RenderConfig {
    RenderConfig {
        prompt_prefix: Styled::new("?").with_fg(Color::DarkYellow),
        answered_prompt_prefix: Styled::new("❯").with_fg(Color::LightGreen),
        prompt: StyleSheet::new().with_attr(Attributes::BOLD),
        default_value: StyleSheet::new().with_fg(Color::DarkGrey),
        placeholder: StyleSheet::new().with_fg(Color::DarkGrey),
        help_message: StyleSheet::empty().with_fg(Color::LightCyan),
        text_input: StyleSheet::new().with_fg(Color::DarkYellow),
        error_message: ErrorMessageRenderConfig::default_colored(),
        password_mask: '*',
        answer: StyleSheet::empty().with_fg(Color::LightCyan),
        canceled_prompt_indicator: Styled::new("<canceled>").with_fg(Color::DarkRed),
        highlighted_option_prefix: Styled::new("❯")
            .with_fg(Color::DarkBlue)
            .with_attr(Attributes::BOLD),
        scroll_up_prefix: Styled::new("^").with_attr(Attributes::BOLD),
        scroll_down_prefix: Styled::new("v").with_attr(Attributes::BOLD),
        selected_checkbox: Styled::new("[x]")
            .with_fg(Color::LightGreen)
            .with_attr(Attributes::BOLD),
        unselected_checkbox: Styled::new("[ ]").with_attr(Attributes::BOLD),
        option_index_prefix: IndexPrefix::None,
        option: StyleSheet::new().with_fg(Color::LightYellow),
        selected_option: Some(StyleSheet::new().with_fg(Color::LightCyan)),
    }
}

pub fn new_spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(120));
    pb.set_style(
        ProgressStyle::with_template("{spinner:.green} {msg}")
            .unwrap()
            // For more spinners check out the cli-spinners project:
            // https://github.com/sindresorhus/cli-spinners/blob/master/spinners.json
            .tick_strings(&[
                "▹▹▹▹▹",
                "▸▹▹▹▹",
                "▹▸▹▹▹",
                "▹▹▸▹▹",
                "▹▹▹▸▹",
                "▹▹▹▹▸",
                "▪▪▪▪▪",
            ]),
    );
    pb.set_message(msg.to_owned());
    pb
}

pub fn json_to_table<T: Serialize>(header: &str, value: T) {
    use tabled::settings::{style::BorderColor, Color, Panel, Style, Width};
    let json = json!(value);
    let mut table = json_to_table::json_to_table(&json).into_table();
    table
        .with(Style::extended())
        .with(Panel::header(header))
        .with(Width::increase(15))
        .with(BorderColor::filled(Color::FG_CYAN));
    println!("{table}");
}

#[allow(dead_code)]
async fn get_chat_arkose_token(har_file: Option<&String>) -> anyhow::Result<ArkoseToken> {
    match har_file {
        None => {
            let arkose_token = ArkoseToken::new_from_context(Type::Chat).await?;
            arkose_challenge(&arkose_token).await;
            Ok(arkose_token)
        }
        Some(har_file) => ArkoseToken::new_from_har(har_file).await,
    }
}
async fn get_platform_arkose_token(har_file: Option<&String>) -> anyhow::Result<ArkoseToken> {
    match har_file {
        None => {
            let arkose_token = ArkoseToken::new_from_context(Type::Platform).await?;
            arkose_challenge(&arkose_token).await;
            Ok(arkose_token)
        }
        Some(har_file) => ArkoseToken::new_from_har(har_file).await,
    }
}

#[allow(dead_code)]
async fn arkose_challenge(arkose_token: &ArkoseToken) {
    if arkose_token.success() {
        match funcaptcha::start_challenge(arkose_token.value()).await {
            Ok(session) => {
                if let Some(funs) = session.funcaptcha() {
                    let max_cap = funs.len();
                    // Wait for all tasks to complete
                    let answers = Vec::with_capacity(max_cap);
                    if let Some(err) = session.submit_answer(answers).await.err() {
                        eprintln!("Error submitting answer: {}", err);
                    }
                }
            }
            Err(error) => {
                eprintln!("Error creating session: {}", error);
            }
        }
    }
}
