use crate::store::conf::Conf;
use crate::store::{account::AccountStore, conf::ConfFileStore, Store};
use openai::auth::{AuthClient, AuthClientBuilder};
use std::time;
use tokio::sync::OnceCell;

static CONF_STORE: OnceCell<ConfFileStore> = OnceCell::const_new();
static ACCOUNT_STORE: OnceCell<AccountStore> = OnceCell::const_new();
static AUTH_CLIENT: OnceCell<AuthClient> = OnceCell::const_new();

pub struct Context;

impl Context {
    pub async fn get_conf_store() -> &'static ConfFileStore {
        CONF_STORE
            .get_or_init(|| async { ConfFileStore::new() })
            .await
    }

    pub async fn get_account_store() -> &'static AccountStore {
        ACCOUNT_STORE
            .get_or_init(|| async { AccountStore::new() })
            .await
    }

    pub async fn get_auth_client() -> &'static AuthClient {
        AUTH_CLIENT
            .get_or_init(|| async {
                match Self::get_conf_store()
                    .await
                    .get(Conf::default())
                    .expect("Failed to read configuration")
                {
                    Some(conf) => AuthClientBuilder::builder()
                        .proxy(conf.proxy)
                        .timeout(time::Duration::from_secs(conf.timeout as u64))
                        .connect_timeout(time::Duration::from_secs(conf.connect_timeout as u64))
                        .tcp_keepalive(time::Duration::from_secs(conf.tcp_keepalive as u64))
                        .cookie_store(true)
                        .build(),
                    None => AuthClientBuilder::builder()
                        .timeout(time::Duration::from_secs(600))
                        .connect_timeout(time::Duration::from_secs(60))
                        .cookie_store(true)
                        .build(),
                }
            })
            .await
    }
}
