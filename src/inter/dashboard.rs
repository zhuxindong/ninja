use inquire::{MultiSelect, Select, Text};
use openai::arkose::ArkoseToken;
use openai::{
    auth::{ApiKeyAction, ApiKeyDataBuilder, AuthClient},
    model::AuthenticateToken,
};

use crate::store::{account::Account, Store};

use super::{context::Context, enums::Dashboard, json_to_table, new_spinner};

pub async fn prompt() -> anyhow::Result<()> {
    let using_user = Context::using_user().await;

    if using_user.is_none() {
        println!("No account found");
        return Ok(());
    }

    if let Some(user) = using_user {
        let client = Context::get_auth_client().await;
        let account_store = Context::get_account_store().await;

        let mut account = account_store
            .get(Account::new(&user))?
            .ok_or(anyhow::anyhow!("No account found"))?;

        let state = account
            .state_mut()
            .iter()
            .filter(|(k, v)| match k {
                openai::auth::model::AuthStrategy::Apple => !v.is_expired(),
                openai::auth::model::AuthStrategy::Platform => !v.is_expired(),
                _ => false,
            })
            .map(|(_, v)| v)
            .collect::<Vec<&AuthenticateToken>>();

        if let Some(auth_token) = state.first() {
            let pb = new_spinner("Login to Dashboard...");
            match client.do_dashboard_login(auth_token.access_token()).await {
                Ok(session) => {
                    pb.finish_and_clear();
                    loop {
                        let select = tokio::task::spawn_blocking(|| {
                            Select::new("Operate ›", Dashboard::DASHBOARD_VARS.to_vec())
                                .with_help_message(
                                    "↑↓ to move, enter to select, type to filter, Esc to quit",
                                )
                                .prompt_skippable()
                        })
                        .await??;

                        if let Some(sel) = select {
                            match sel {
                                Dashboard::List => {
                                    list_api_key(&client, session.sensitive_id()).await?
                                }
                                Dashboard::Create => {
                                    create_api_key(&client, session.sensitive_id()).await?
                                }
                                Dashboard::Delete => {
                                    delete_api_key(&client, session.sensitive_id()).await?
                                }
                                Dashboard::Billing => {
                                    billing(&client, session.sensitive_id()).await?
                                }
                            }
                        } else {
                            break;
                        }
                    }
                }
                Err(err) => println!("Error: {}", err),
            }
        }
    }

    Ok(())
}

async fn get_arkose_token(har_file: Option<&String>) -> anyhow::Result<ArkoseToken> {
    match har_file {
        None => ArkoseToken::new_platform().await,
        Some(har_file) => ArkoseToken::new_form_har(har_file).await,
    }
}

async fn billing(client: &AuthClient, token: &str) -> anyhow::Result<()> {
    match client.billing_credit_grants(token).await {
        Ok(credit_grants) => json_to_table("Billing", credit_grants),
        Err(err) => {
            println!("Error: {}", err);
        }
    }
    Ok(())
}

async fn list_api_key(client: &AuthClient, token: &str) -> anyhow::Result<()> {
    match client.do_get_api_key_list(token).await {
        Ok(api_key_list) => {
            if !api_key_list.data.is_empty() {
                json_to_table("API KEY LIST", api_key_list.data);
            }
        }
        Err(err) => {
            println!("Error: {}", err);
        }
    }
    Ok(())
}

async fn create_api_key(client: &AuthClient, token: &str) -> anyhow::Result<()> {
    let conf = Context::get_conf().await?;

    let opt_name = tokio::task::spawn_blocking(|| {
        Text::new("API key name ›")
            .with_help_message("Enter a name for the API key")
            .prompt_skippable()
    })
    .await??;

    if let Some(name) = opt_name {
        match get_arkose_token(conf.arkose_platform_har_file.as_ref()).await {
            Ok(arkose_token) => {
                let data = ApiKeyDataBuilder::default()
                    .action(ApiKeyAction::Create)
                    .name(name.as_str())
                    .arkose_token(&arkose_token)
                    .build()?;

                match client.do_api_key(token, data).await {
                    Ok(api_key) => {
                        json_to_table("Field", api_key.key);
                    }
                    Err(err) => {
                        println!("Error: {}", err);
                    }
                }
            }
            Err(err) => println!("Error: {}", err),
        }
    }

    Ok(())
}

async fn delete_api_key(client: &AuthClient, token: &str) -> anyhow::Result<()> {
    let conf = Context::get_conf().await?;

    match client.do_get_api_key_list(token).await {
        Ok(api_key_list) => {
            if api_key_list.data.is_empty() {
                return Ok(());
            }
            let select_list = api_key_list
                .data
                .iter()
                .map(|k| k.sensitive_id.clone())
                .collect::<Vec<String>>();

            if let Some(select) = tokio::task::spawn_blocking(move || {
                MultiSelect::new("Select API Key ›", select_list)
                    .with_help_message("↑↓ to move, enter to select, type to filter, Esc to quit")
                    .prompt_skippable()
            })
            .await??
            {
                for s in select {
                    if let Some(key) = api_key_list.data.iter().find(|k| k.sensitive_id.eq(&s)) {
                        match get_arkose_token(conf.arkose_platform_har_file.as_ref()).await {
                            Ok(arkose_token) => {
                                let data = ApiKeyDataBuilder::default()
                                    .action(ApiKeyAction::Delete)
                                    .created_at(key.created as u64)
                                    .redacted_key(key.sensitive_id.as_str())
                                    .arkose_token(&arkose_token)
                                    .build()?;

                                if let Err(err) = client.do_api_key(token, data).await {
                                    println!("Error: {}", err);
                                }
                            }
                            Err(err) => println!("Error: {}", err),
                        }
                    }
                }
            }
        }
        Err(err) => {
            println!("Error: {}", err);
        }
    }

    Ok(())
}
