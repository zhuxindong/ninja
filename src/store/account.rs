use std::{collections::HashMap, ops::Not, path::PathBuf};

use openai::{auth::model::AuthStrategy, model::AuthenticateToken};

use crate::homedir::home_dir;

use super::{Store, StoreId, StoreResult};

pub struct AccountFileStore(PathBuf);

impl AccountFileStore {
    pub fn new() -> Self {
        let path = match home_dir() {
            Some(home_dir) => home_dir.join(".opengpt-accounts"),
            None => PathBuf::from(".opengpt-accounts"),
        };
        if let Some(parent) = path.parent() {
            if path.exists().not() {
                std::fs::create_dir_all(parent)
                    .expect("Unable to create default file Account storage file")
            }
        }
        if path.exists().not() {
            std::fs::File::create(&path)
                .expect(&format!("Unable to create file: {}", path.display()));
        }
        AccountFileStore(path)
    }
}

impl Store<Account> for AccountFileStore {
    fn add(&self, account: Account) -> StoreResult<Option<Account>> {
        let bytes = std::fs::read(&self.0)?;
        let mut data: HashMap<String, Account> = if bytes.is_empty() {
            HashMap::new()
        } else {
            serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!(e))?
        };
        let v = data.insert(account.email.to_string(), account);
        let json = serde_json::to_string_pretty(&data)?;
        std::fs::write(&self.0, json.as_bytes())?;
        Ok(v)
    }

    fn get(&self, account: Account) -> StoreResult<Option<Account>> {
        let bytes = std::fs::read(&self.0)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        let data: HashMap<String, Account> =
            serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!(e))?;
        Ok(data.get(&account.id()).cloned())
    }

    fn remove(&self, account: Account) -> StoreResult<Option<Account>> {
        let bytes = std::fs::read(&self.0)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        let mut data: HashMap<String, Account> =
            serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!(e))?;
        let v = data.remove(&account.id());
        let json = serde_json::to_string_pretty(&data)?;
        std::fs::write(&self.0, json)?;
        Ok(v)
    }

    fn list(&self) -> StoreResult<Vec<Account>> {
        let bytes = std::fs::read(&self.0)?;
        if bytes.is_empty() {
            return Ok(vec![]);
        }
        let data: HashMap<String, Account> =
            serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!(e))?;
        Ok(data.into_values().collect::<Vec<Account>>())
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Account {
    email: String,
    state: HashMap<AuthStrategy, AuthenticateToken>,
}

impl Account {
    pub fn new(email: &str) -> Self {
        Self {
            email: email.to_owned(),
            state: HashMap::default(),
        }
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn state(&self) -> &HashMap<AuthStrategy, AuthenticateToken> {
        &self.state
    }

    pub fn push_state(&mut self, auth_strategy: AuthStrategy, token: AuthenticateToken) {
        self.state.insert(auth_strategy, token);
    }
}

impl StoreId for Account {
    fn id(&self) -> String {
        self.email.to_owned()
    }
}
