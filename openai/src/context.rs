use std::{path::PathBuf, sync::Once};

use crate::{arkose, auth::AuthClient, balancer::ClientLoadBalancer, info, warn};
use derive_builder::Builder;
use reqwest::Client;

use hotwatch::{Event, EventKind, Hotwatch};

#[derive(Builder, Clone, Default)]
pub struct Args {
    /// Server proxies
    #[builder(setter(into), default)]
    pub proxies: Vec<String>,
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
    pub arkose_har_path: Option<PathBuf>,
    /// get arkose-token endpoint
    #[builder(setter(into), default)]
    pub arkose_token_endpoint: Option<String>,
    /// yescaptcha client key
    #[builder(setter(into), default)]
    pub yescaptcha_client_key: Option<String>,
    /// Account Plus puid cookie value
    #[builder(setter(into), default)]
    pub puid: Option<String>,
}

// Program context
static mut CONTEXT_ENV: Option<Context> = None;
static INIT: Once = Once::new();

pub struct Context {
    client_load: Option<ClientLoadBalancer<Client>>,
    auth_client_load: Option<ClientLoadBalancer<AuthClient>>,
    share_puid: Option<String>,
    arkose_token_endpoint: Option<String>,
    arkose_har_file_path: Option<PathBuf>,
    yescaptcha_client_key: Option<String>,
    hotwatch: Option<hotwatch::Hotwatch>,
}

impl Context {
    /// Use Once to guarantee initialization only once
    pub fn init(args: Args) {
        INIT.call_once(|| unsafe { CONTEXT_ENV = Some(Context::new(args)) });
    }

    pub fn get_instance() -> &'static mut Context {
        unsafe {
            if CONTEXT_ENV.is_none() {
                Self::init(Args::default())
            }
            CONTEXT_ENV
                .as_mut()
                .expect("Runtime Env component is not initialized")
        }
    }

    fn new(args: Args) -> Self {
        let hotwatch = args.arkose_har_path.clone().map(|path| {
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

        let share_puid = args.puid.as_ref().map(|puid| {
            info!("Using PUID: {puid}");
            puid
        });

        Context {
            client_load: Some(
                ClientLoadBalancer::<Client>::new_api_client(&args)
                    .expect("Failed to initialize the requesting client"),
            ),
            auth_client_load: Some(
                ClientLoadBalancer::<AuthClient>::new_auth_client(&args)
                    .expect("Failed to initialize the requesting oauth client"),
            ),
            share_puid: share_puid.cloned(),
            arkose_token_endpoint: args.arkose_token_endpoint,
            yescaptcha_client_key: args.yescaptcha_client_key,
            arkose_har_file_path: args.arkose_har_path,
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

    pub fn get_share_puid(&self) -> Option<&str> {
        self.share_puid.as_deref()
    }

    pub fn set_share_puid(&mut self, puid: Option<String>) {
        self.share_puid = puid;
    }

    pub fn arkose_har_file_path(&self) -> Option<&PathBuf> {
        self.arkose_har_file_path.as_ref()
    }

    pub fn arkose_token_endpoint(&self) -> Option<&String> {
        self.arkose_token_endpoint.as_ref()
    }

    pub fn yescaptcha_client_key(&self) -> Option<&String> {
        self.yescaptcha_client_key.as_ref()
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        self.hotwatch
            .as_mut()
            .and_then(|hotwatch| {
                self.arkose_har_file_path
                    .as_ref()
                    .map(|path| (hotwatch, path))
            })
            .and_then(|(hotwatch, path)| hotwatch.unwatch(path).err())
            .map(|err| warn!("unwatch path error: {err}"));
    }
}
