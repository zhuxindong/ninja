mod configure;
mod context;
mod conversation;
mod dash;
mod enums;
mod oauth;
mod valid;

use crate::inter::conversation::{api, chatgpt};
use enums::Usage;
use inquire::{
    ui::{
        Attributes, Color, ErrorMessageRenderConfig, IndexPrefix, RenderConfig, StyleSheet, Styled,
    },
    Select,
};
use std::cell::RefCell;
use std::thread;
use std::time::Duration;
use tokio::{io::AsyncWriteExt, task};

pub async fn prompt() -> anyhow::Result<()> {
    print_boot_message();

    loop {
        let choice = task::spawn_blocking(move || {
            Select::new("Usage Wizard ›", Usage::USAGE_VARS.to_vec())
                .with_render_config(render_config())
                .with_formatter(&|i| format!("${i:.2}"))
                .prompt()
        })
        .await??;

        match choice {
            Usage::OpenAI => api::api_prompt().await?,
            Usage::ChatGPT => chatgpt::chatgpt_prompt().await?,
            Usage::Dashboard => dash::dashboard_prompt().await?,
            Usage::OAuth => oauth::oauth_prompt().await?,
            Usage::Configuration => configure::config_prompt().await?,
            Usage::Quit => break,
        }
    }
    Ok(())
}

fn print_boot_message() {
    let logo = r"
    ___                    ____ ____ _____ 
    / _ \ _ __   ___ _ __  / ___|  _ \_   _|
   | | | | '_ \ / _ \ '_ \| |  _| |_) || |  
   | |_| | |_) |  __/ | | | |_| |  __/ | |  
    \___/| .__/ \___|_| |_|\____|_|    |_|  
         |_|                                   
   ";

    let welcome = "Welcome to OpenGPT terminal!";
    let enjoy = "You can enjoy professional GPT services";
    let repo = "Repository: https://github.com/gngpp/opengpt\n";
    println!("\x1B[1m{logo}\x1B[1m");
    println!("\x1B[1m{welcome}\x1B[1m");
    println!("\x1B[1m{enjoy}\x1B[1m");
    println!("\x1B[1m{repo}\x1B[1m");
}

pub(super) fn render_config() -> RenderConfig {
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

pub struct ProgressBar<'a> {
    message: &'a str,
    task: RefCell<Option<tokio::task::JoinHandle<()>>>,
}

impl ProgressBar<'_> {
    pub fn new(msg: &str) -> ProgressBar<'_> {
        ProgressBar {
            message: msg,
            task: RefCell::new(None),
        }
    }

    pub fn start(&self) {
        let msg = self.message.to_owned();
        let mut task = self.task.borrow_mut();
        *task = Some(tokio::spawn(async move {
            let progress_chars = &["▹▹▹▹▹", "▸▹▹▹▹", "▹▸▹▹▹", "▹▹▸▹▹", "▹▹▹▸▹", "▹▹▹▹▸"];
            let mut out = tokio::io::stdout();
            loop {
                for chars in progress_chars {
                    out.write_all(format!("\r\x1B[34m{chars}\x1B[0m {msg}").as_bytes())
                        .await
                        .unwrap();
                    out.flush().await.unwrap();
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }));
    }

    pub async fn finish(self) {
        if let Some(join) = self.task.into_inner() {
            join.abort();
            println!("\r");
        }
    }
}
