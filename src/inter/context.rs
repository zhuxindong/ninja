use crate::store::conf::Conf;
use crate::store::{account::AccountStore, conf::ConfFileStore, Store};
use anyhow::anyhow;
use openai::arkose::funcaptcha::ArkoseSolver;
use openai::auth::{AuthClient, AuthClientBuilder};
use std::path::PathBuf;
use std::time;
use tokio::sync::OnceCell;

static CONF_STORE: OnceCell<ConfFileStore> = OnceCell::const_new();
static ACCOUNT_STORE: OnceCell<AccountStore> = OnceCell::const_new();
static AUTH_CLIENT: OnceCell<AuthClient> = OnceCell::const_new();

pub struct Context;

impl Context {
    pub async fn init_openai_context() -> anyhow::Result<()> {
        let conf = Self::get_conf().await?;

        let arkose_har_file = conf
            .arkose_har_file
            .map(|f| Some(PathBuf::from(f)))
            .unwrap_or(None);

        let arkose_solver = conf
            .arkose_solver_key
            .map(|k| Some(ArkoseSolver::new(conf.arkose_solver, k)))
            .unwrap_or(None);

        let proxies = conf.proxy.map(|p| vec![p]).unwrap_or(vec![]);

        let args = openai::context::ContextArgsBuilder::default()
            .arkose_endpoint(conf.arkose_token_endpoint)
            .arkose_har_file(arkose_har_file)
            .arkose_solver(arkose_solver)
            .timeout(conf.timeout)
            .connect_timeout(conf.connect_timeout)
            .tcp_keepalive(conf.tcp_keepalive)
            .proxies(proxies)
            .build()?;
        openai::context::Context::init(args);
        Ok(())
    }
    pub async fn using_user() -> Option<String> {
        Self::get_conf_store()
            .await
            .get(Conf::default())
            .expect("Failed to read configuration")
            .and_then(|conf| conf.using_user)
    }

    pub async fn set_using_user(user: Option<String>) -> anyhow::Result<()> {
        let conf_store = Self::get_conf_store().await;
        let mut conf = Self::get_conf().await?;
        conf.using_user = user;
        let _ = conf_store
            .add(conf)?
            .ok_or(anyhow!("Failed to write configuration"));
        Ok(())
    }

    pub async fn get_conf() -> anyhow::Result<Conf> {
        Self::get_conf_store()
            .await
            .get(Conf::default())?
            .ok_or(anyhow!("Failed to read configuration"))
    }

    pub async fn get_conf_store() -> &'static ConfFileStore {
        CONF_STORE
            .get_or_init(|| async {
                let store = ConfFileStore::new();
                if store
                    .list()
                    .expect("Failed to read configuration")
                    .is_empty()
                {
                    store
                        .add(Conf::default())
                        .expect("Failed to write configuration");
                }
                store
            })
            .await
    }

    pub async fn get_account_store() -> &'static AccountStore {
        ACCOUNT_STORE
            .get_or_init(|| async { AccountStore::new() })
            .await
    }

    pub async fn get_auth_client() -> AuthClient {
        AUTH_CLIENT
            .get_or_init(|| async {
                let conf = Self::get_conf()
                    .await
                    .expect("Failed to read configuration");
                AuthClientBuilder::builder()
                    .proxy(conf.proxy)
                    .timeout(time::Duration::from_secs(conf.timeout as u64))
                    .connect_timeout(time::Duration::from_secs(conf.connect_timeout as u64))
                    .tcp_keepalive(time::Duration::from_secs(conf.tcp_keepalive as u64))
                    .cookie_store(true)
                    .build()
            })
            .await
            .clone()
    }
}
