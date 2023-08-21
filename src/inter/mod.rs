use anyhow::Context;
use inquire::{min_length, required, Password, PasswordDisplayMode, Select, Text};

pub mod api;
pub mod chatgpt;
pub mod usage_type;

use openai::auth::model::{AuthAccount, AuthStrategy};
use usage_type::Usage;

#[tokio::main(flavor = "current_thread")]
pub async fn prompt() -> anyhow::Result<()> {
    print_boot_message();

    let choice = Select::new("Usage:", usage_type::Usage::VARIANTS.to_vec())
        .with_formatter(&|i| format!("${i:.2}"))
        .prompt()?;

    match choice {
        Usage::ChatGPT => chatgpt::handle_prompt().await?,
        Usage::API => api::handle_prompt().await?,
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
    println!("{logo}");
    eprintln!("Welcome to OpenGPT terminal!\n");
    eprintln!("You can enjoy professional GPT services\n");
    eprintln!("Repository: https://github.com/gngpp/opengpt\n");
}

#[allow(warnings)]
pub(super) fn account_prompt() -> anyhow::Result<AuthAccount> {
    let auth_strategy = Select::new(
        "Authentication Strategy:",
        [AuthStrategy::Web, AuthStrategy::Apple].to_vec(),
    )
    .with_formatter(&|i| format!("${i:.2}"))
    .prompt()?;

    let username = Text::new("Email:")
        .with_validator(required!("email is required"))
        .with_validator(min_length!(5))
        .with_help_message("OpenAI account email, Format: example@gmail.com")
        .prompt()?;

    let password = Password::new("Password:")
        .with_display_toggle_enabled()
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_validator(required!("password is required"))
        .with_validator(min_length!(5))
        .with_formatter(&|_| String::from("Input received"))
        .with_help_message("OpenAI account password")
        .without_confirmation()
        .prompt()
        .context("An error happened when asking for your account, try again later.")?;

    let mfa_res = Text::new("MFA Code:")
        .with_help_message("OpenAI account MFA Code, If it is empty, please enter directly.")
        .prompt();

    match mfa_res {
        Ok(mfa_code) => {
            if !mfa_code.is_empty() {
                return Ok(AuthAccount {
                    username,
                    password,
                    mfa: Some(mfa_code),
                    option: auth_strategy,
                    cf_turnstile_response: None,
                });
            }
        }
        Err(_) => println!("An error happened when asking for your mfa code, try again later."),
    }

    Ok(AuthAccount {
        username,
        password: password,
        mfa: None,
        option: auth_strategy,
        cf_turnstile_response: None,
    })
}
