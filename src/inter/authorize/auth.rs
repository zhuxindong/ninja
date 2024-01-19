use std::time::Duration;

use inquire::{min_length, required, MultiSelect, Password, PasswordDisplayMode, Select, Text};
use openai::auth::model::{AuthAccount, AuthStrategy};
use openai::auth::provide::AuthProvider;
use openai::token::model::Token;

use crate::inter::standard::Auth;
use crate::inter::{json_to_table, new_spinner, render_config};
use crate::store::account::Account;
use crate::store::StoreId;
use crate::{inter::context::Context, store::Store};

pub async fn sign_in_prompt() -> anyhow::Result<()> {
    loop {
        let wizard = tokio::task::spawn_blocking(move || {
            Select::new("SignIn Wizard ›", Auth::SIGN_IN_VARS.to_vec())
                .with_render_config(render_config())
                .with_formatter(&|i| format!("${i}"))
                .with_vim_mode(true)
                .with_help_message("↑↓ to move, enter to select, type to filter, Esc to quit")
                .prompt_skippable()
        })
        .await??;
        if let Some(wizard) = wizard {
            match wizard {
                Auth::User => using().await?,
                Auth::State => state().await?,
                Auth::Login => sign_in().await?,
                Auth::Logout => sign_out().await?,
            }
        } else {
            // Esc to quit
            return Ok(());
        }
    }
}

async fn sign_in() -> anyhow::Result<()> {
    let multi_strategy = tokio::task::spawn_blocking(move || {
        MultiSelect::new(
            "Please choose the authentication strategy ›",
            vec![
                AuthStrategy::Web,
                AuthStrategy::Apple,
                AuthStrategy::Platform,
            ],
        )
        .prompt_skippable()
    })
    .await??;

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

    let store = Context::get_account_store().await;
    let client = Context::get_auth_client().await;

    if let Some(multi_strategy) = multi_strategy {
        for auth_strategy in multi_strategy {
            let pb = new_spinner("Authenticating...");

            let auth_account = AuthAccount::builder()
                .username(username.clone())
                .password(password.clone())
                .mfa(mfa_code.clone())
                .option(auth_strategy.clone())
                .build();

            match client.do_access_token(&auth_account).await {
                Ok(access_token) => {
                    pb.finish_and_clear();
                    println!("{} Login Success", auth_strategy);
                    let token = Token::try_from(access_token)?;
                    let mut account = store
                        .read(Account::new(token.email()))?
                        .unwrap_or(Account::new(token.email()));
                    Context::set_using_user(Some(token.email().to_owned())).await?;
                    account.push_state(auth_strategy, token);
                    store.store(account)?;
                }
                Err(err) => {
                    pb.finish_and_clear();
                    println!("{auth_strategy} Error: {}", err);
                }
            }

            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    Ok(())
}

async fn sign_out() -> anyhow::Result<()> {
    let store = Context::get_account_store().await;
    let ves = store
        .list()?
        .into_iter()
        .map(|v| v.id())
        .collect::<Vec<String>>();
    if ves.is_empty() {
        println!("No account found");
        return Ok(());
    }
    let switch = tokio::task::spawn_blocking(|| {
        Select::new("Sign-out account", ves)
            .with_help_message("↑↓ to move, enter to select, type to filter, Esc to quit")
            .prompt_skippable()
    })
    .await??;

    if let Some(email) = switch {
        if let Some(mut account) = store.read(Account::new(&email))? {
            let client = Context::get_auth_client().await;
            let pb = new_spinner("Signing out...");
            for (k, v) in account.state_mut() {
                if let AuthStrategy::Platform | AuthStrategy::Apple = k {
                    if let Some(refresh_token) = v.refresh_token() {
                        client.do_revoke_token(refresh_token).await?;
                        store.remove(Account::new(&email))?;
                        if let Some(using_user) = Context::current_user().await {
                            if using_user.eq(&email) {
                                Context::set_using_user(None).await?;
                            }
                        }
                    }
                }
            }
            pb.finish_and_clear();
        }
    }
    Ok(())
}

async fn using() -> anyhow::Result<()> {
    let store = Context::get_account_store().await;

    let using_user = Context::current_user().await;

    let mut ids = store
        .list()?
        .into_iter()
        .map(|v| v.id())
        .collect::<Vec<String>>();

    ids.sort();

    if ids.is_empty() {
        println!("No account found");
        return Ok(());
    }

    let select = ids
        .iter()
        .position(|select| {
            if let Some(user) = &using_user {
                return select.eq(user);
            }
            false
        })
        .unwrap_or(0);

    let opt_switch = tokio::task::spawn_blocking(move || {
        Select::new("Using Account", ids)
            .with_help_message("↑↓ to move, enter to select, type to filter, Esc to quit")
            .with_starting_cursor(select)
            .prompt_skippable()
    })
    .await??;
    if let Some(using) = opt_switch {
        println!("Using Account: {}", using);
        Context::set_using_user(Some(using)).await?;
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct AccountState {
    email: String,
    state: Vec<State>,
}

#[derive(serde::Serialize)]
struct State {
    #[serde(rename = "type")]
    _type: AuthStrategy,
    expires: String,
}

async fn state() -> anyhow::Result<()> {
    let store = Context::get_account_store().await;
    let account_list = store.list()?;

    if account_list.is_empty() {
        println!("No account found");
        return Ok(());
    }

    let mut list = Vec::with_capacity(account_list.len());

    for mut account in account_list {
        let states = account
            .state_mut()
            .iter_mut()
            .map(|(k, v)| State {
                _type: k.to_owned(),
                expires: openai::format_time_to_rfc3399(v.expires())
                    .expect("Failed to format time"),
            })
            .collect::<Vec<State>>();
        list.push(AccountState {
            email: account.id(),
            state: states,
        });
    }

    json_to_table("Login State", list);
    Ok(())
}
