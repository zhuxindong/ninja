use std::{sync::Once, time};

use crate::{
    store::{
        account::{Account, AccountFileStore},
        conf::ConfFileStore,
        Store,
    },
    util,
};

static mut ACCOUNT_STORE: Option<AccountFileStore> = None;
static mut CONF_STORE: Option<ConfFileStore> = None;
static mut AUTH_CLIENT: Option<AuthClient> = None;

pub static ACCOUNT_STORE_HOLDER: AccountStoreHolder = AccountStoreHolder(Once::new());
pub static CONF_STORE_HOLDER: ConfStoreHolder = ConfStoreHolder(Once::new());
pub static AUTH_CLIENT_HOLDER: AuthClientHolder = AuthClientHolder(Once::new());

pub struct AccountStoreHolder(Once);

impl AccountStoreHolder {
    pub fn get_instance(&self) -> &AccountFileStore {
        // Use Once to guarantee initialization only once
        self.0
            .call_once(|| unsafe { ACCOUNT_STORE = Some(AccountFileStore::new(None).unwrap()) });
        unsafe {
            ACCOUNT_STORE
                .as_ref()
                .expect("Runtime AccountFileStore component is not initialized")
        }
    }
}

pub struct ConfStoreHolder(Once);

impl ConfStoreHolder {
    pub fn get_instance(&self) -> &ConfFileStore {
        // Use Once to guarantee initialization only once
        self.0
            .call_once(|| unsafe { CONF_STORE = Some(ConfFileStore::new(None).unwrap()) });
        unsafe {
            CONF_STORE
                .as_ref()
                .expect("Runtime ConfFileStore component is not initialized")
        }
    }
}

pub struct AuthClientHolder(Once);

impl AuthClientHolder {
    pub fn get_instance(&self) -> &AuthClient {
        // Use Once to guarantee initialization only once
        self.0.call_once(|| unsafe {
            let conf_store = CONF_STORE_HOLDER.get_instance();
            let conf = conf_store.get(Conf::default()).unwrap();
            if let Some(conf) = conf {
                openai::auth::AuthClientBuilder::builder()
                    .proxy(conf.proxy)
                    .timeout(time::Duration::from_secs(conf.timeout as u64))
                    .connect_timeout(time::Duration::from_secs(conf.connect_timeout as u64))
                    .tcp_keepalive(time::Duration::from_secs(conf.tcp_keepalive as u64))
                    .cookie_store(true)
                    .build();
            }
            let auth_client = openai::auth::AuthClientBuilder::builder()
                .timeout(time::Duration::from_secs(600))
                .connect_timeout(time::Duration::from_secs(60))
                .cookie_store(true)
                .build();
            AUTH_CLIENT = Some(auth_client);
        });
        unsafe {
            AUTH_CLIENT
                .as_ref()
                .expect("Runtime AccountFileStore component is not initialized")
        }
    }
}

use crate::inter::render_config;
use crate::store::conf::Conf;
use anyhow::Context;
use inquire::{min_length, required, Password, PasswordDisplayMode, Select, Text};
use openai::auth::AuthClient;
use openai::{
    auth::{
        model::{AccessToken, AuthAccount, AuthStrategy},
        AuthHandle,
    },
    model::AuthenticateToken,
};

pub async fn login_prompt(auth_strategy: Option<AuthStrategy>) -> anyhow::Result<AccessToken> {
    let auth_strategy = if let Some(auth_strategy) = auth_strategy {
        auth_strategy
    } else {
        Select::new(
            "Please choose the authentication method ›",
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
        .prompt()
        .context("An error happened when asking for your account, try again later.")?;

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

    let auth_client = AUTH_CLIENT_HOLDER.get_instance();

    let auth_account = AuthAccount {
        username,
        password,
        mfa: mfa_code,
        option: auth_strategy.into(),
        cf_turnstile_response: None,
    };

    let mut pb = util::long_spinner_progress_bar("Logging...");
    pb.start();
    let result = auth_client.do_access_token(&auth_account).await;
    pb.finish_and_clear().await;
    result
}

pub async fn login_store_prompt(auth_strategy: AuthStrategy) {
    match login_prompt(Some(auth_strategy.clone())).await {
        Ok(token) => {
            if let Ok(authenticate_token) = AuthenticateToken::try_from(token) {
                let store = ACCOUNT_STORE_HOLDER.get_instance();
                let mut account = Account::new(authenticate_token.email());
                account.push_state(auth_strategy, authenticate_token);
                if let Some(err) = store.add(account).err() {
                    eprintln!("Error: {err}")
                } else {
                    println!("Login success!")
                }
            }
        }
        Err(err) => {
            eprintln!("Login error: {err}")
        }
    }
}
