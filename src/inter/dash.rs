use inquire::Confirm;
use openai::auth::model::AuthStrategy;

use crate::store::Store;

use super::{
    context::{self, ACCOUNT_STORE},
    render_config,
};

pub(super) async fn dashboard_prompt() -> anyhow::Result<()> {
    match ACCOUNT_STORE.list() {
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
