use std::path::PathBuf;

use crate::{
    arkose::{self, funcaptcha::ArkoseSolver},
    auth::AuthClient,
    balancer::ClientLoadBalancer,
    error, info, warn,
};
use derive_builder::Builder;
use reqwest::Client;
use tokio::sync::{OnceCell, RwLock};

use hotwatch::{Event, EventKind, Hotwatch};

#[derive(Builder, Clone, Default)]
pub struct ContextArgs {
    /// Server proxies
    #[builder(setter(into), default)]
    pub proxies: Vec<String>,
    /// Disable direct connection
    #[builder(default = "false")]
    pub disable_direct: bool,
    /// TCP keepalive (second)
    #[builder(setter(into), default = "75")]
    pub tcp_keepalive: usize,
    /// Client timeout
    #[builder(setter(into), default = "600")]
    pub timeout: usize,
    /// Client connect timeout
    #[builder(setter(into), default = "60")]
    pub connect_timeout: usize,
    /// Web UI api prefix
    #[builder(setter(into), default)]
    pub api_prefix: Option<String>,
    /// Arkose endpoint
    #[builder(setter(into), default)]
    pub arkose_endpoint: Option<String>,
    /// Arkoselabs HAR record file path
    #[builder(setter(into), default)]
    pub arkose_har_file: Option<PathBuf>,
    /// HAR file upload authenticate key
    #[builder(setter(into), default)]
    pub arkose_har_upload_key: Option<String>,
    /// get arkose-token endpoint
    #[builder(setter(into), default)]
    pub arkose_token_endpoint: Option<String>,
    /// arkoselabs solver
    #[builder(setter(into), default)]
    pub arkose_solver: Option<ArkoseSolver>,
    /// Account Plus puid cookie value
    #[builder(setter(into), default)]
    pub puid: Option<String>,
}

// Program context
static CTX: OnceCell<Context> = OnceCell::const_new();

pub struct Context {
    client_load: Option<ClientLoadBalancer<Client>>,
    auth_client_load: Option<ClientLoadBalancer<AuthClient>>,
    share_puid: RwLock<String>,
    arkose_token_endpoint: Option<String>,
    arkose_har_file: Option<PathBuf>,
    arkose_har_upload_key: Option<String>,
    arkose_solver: Option<ArkoseSolver>,
    hotwatch: Option<hotwatch::Hotwatch>,
}

impl Context {
    /// Use Once to guarantee initialization only once
    pub fn init(args: ContextArgs) {
        if let Some(err) = CTX.set(Context::new(args)).err() {
            error!("Error: {err}")
        }
    }

    pub async fn get_instance() -> &'static Context {
        CTX.get_or_init(|| async {
            Context::new(
                ContextArgsBuilder::default()
                    .build()
                    .expect("Context arguments initialization build failed"),
            )
        })
        .await
    }

    fn new(args: ContextArgs) -> Self {
        let hotwatch = args.arkose_har_file.clone().map(|path| {
            let mut hotwatch = Hotwatch::new().expect("hotwatch failed to initialize!");
            hotwatch
                .watch(path.clone(), move |event: Event| {
                    if let EventKind::Modify(_) = event.kind {
                        info!("HAR file changes observed: {}", path.display());
                        arkose::har::clear_cache();
                    }
                })
                .expect("failed to watch file!");
            hotwatch
        });

        Context {
            client_load: Some(
                ClientLoadBalancer::<Client>::new_client(&args)
                    .expect("Failed to initialize the requesting client"),
            ),
            auth_client_load: Some(
                ClientLoadBalancer::<AuthClient>::new_auth_client(&args)
                    .expect("Failed to initialize the requesting oauth client"),
            ),
            arkose_token_endpoint: args.arkose_token_endpoint,
            arkose_solver: args.arkose_solver,
            arkose_har_file: args.arkose_har_file,
            arkose_har_upload_key: args.arkose_har_upload_key,
            share_puid: RwLock::new(args.puid.unwrap_or_default()),
            hotwatch,
        }
    }

    pub fn load_client(&self) -> Client {
        self.client_load
            .as_ref()
            .expect("The load balancer client is not initialized")
            .next()
    }

    pub fn load_auth_client(&self) -> AuthClient {
        self.auth_client_load
            .as_ref()
            .expect("The load balancer auth client is not initialized")
            .next()
    }

    pub async fn get_share_puid(&self) -> tokio::sync::RwLockReadGuard<'_, String> {
        self.share_puid.read().await
    }

    pub async fn set_share_puid(&self, puid: &str) {
        let mut lock = self.share_puid.write().await;
        lock.clear();
        lock.push_str(puid);
        drop(lock)
    }

    pub fn arkose_har_file(&self) -> Option<&PathBuf> {
        self.arkose_har_file.as_ref()
    }

    pub fn arkose_har_upload_key(&self) -> Option<&String> {
        self.arkose_har_upload_key.as_ref()
    }

    pub fn arkose_token_endpoint(&self) -> Option<&String> {
        self.arkose_token_endpoint.as_ref()
    }

    pub fn arkose_solver(&self) -> Option<&ArkoseSolver> {
        self.arkose_solver.as_ref()
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        self.hotwatch
            .as_mut()
            .and_then(|hotwatch| self.arkose_har_file.as_ref().map(|path| (hotwatch, path)))
            .and_then(|(hotwatch, path)| hotwatch.unwatch(path).err())
            .map(|err| warn!("unwatch path error: {err}"));
    }
}
