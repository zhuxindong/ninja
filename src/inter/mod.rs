pub mod context;
mod conversation;
pub mod enums;
pub mod settings;

use crate::inter::conversation::{api, chatgpt};
use enums::Usage;
use inquire::{
    ui::{
        Attributes, Color, ErrorMessageRenderConfig, IndexPrefix, RenderConfig, StyleSheet, Styled,
    },
    Select,
};

#[tokio::main(flavor = "current_thread")]
pub async fn prompt() -> anyhow::Result<()> {
    print_boot_message();

    loop {
        let choice = Select::new("Usage Wizard ›", enums::Usage::USAGE_VARS.to_vec())
            .with_render_config(render_config())
            .with_formatter(&|i| format!("${i:.2}"))
            .prompt()?;

        match choice {
            Usage::API => api::api_prompt().await?,
            Usage::ChatGPT => chatgpt::chatgpt_prompt().await?,
            Usage::Dashboard => settings::dashboard_prompt().await?,
            Usage::OAuth => settings::oauth_prompt().await?,
            Usage::Configuration => settings::config_prompt().await?,
            Usage::Quit => return Ok(()),
        }
    }
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
        editor_prompt: StyleSheet::new().with_fg(Color::DarkCyan),
    }
}
