use std::{collections::HashMap, path::PathBuf, sync::OnceLock};

use crate::{
    arkose::{self, funcaptcha::ArkoseSolver},
    auth::AuthClient,
    balancer::ClientLoadBalancer,
    error,
    homedir::home_dir,
    info,
    serve::middleware::tokenbucket,
    warn,
};
use derive_builder::Builder;
use reqwest::Client;
use std::sync::RwLock;

use hotwatch::{Event, EventKind, Hotwatch};

/// Use Once to guarantee initialization only once
pub fn init(args: ContextArgs) {
    if let Some(_) = CTX.set(Context::new(args)).err() {
        error!("Failed to initialize context");
    };
}

/// Get the program context
pub fn get_instance() -> &'static Context {
    CTX.get_or_init(|| {
        Context::new(
            ContextArgsBuilder::default()
                .build()
                .expect("Context arguments initialization build failed"),
        )
    })
}

#[derive(Builder, Clone, Default)]
pub struct ContextArgs {
    /// Listen addres
    #[builder(setter(into), default = "String::from(\"0.0.0.0\")")]
    pub(crate) host: String,

    /// Listen port
    #[builder(setter(into), default = "7999")]
    pub(crate) port: u16,

    /// Machine worker pool
    #[builder(setter(into), default = "1")]
    pub(crate) workers: usize,

    /// Concurrent limit (Enforces a limit on the concurrent number of requests the underlying)
    #[builder(setter(into), default = "65535")]
    pub(crate) concurrent_limit: usize,

    /// Disable direct connection
    #[builder(default = "false")]
    pub(crate) disable_direct: bool,

    /// Enabled Cookie Store
    #[builder(default = "false")]
    pub(crate) cookie_store: bool,

    /// TCP keepalive (second)
    #[builder(setter(into), default = "75")]
    pub(crate) tcp_keepalive: usize,

    /// Set an optional timeout for idle sockets being kept-alive
    #[builder(setter(into), default = "90")]
    pub(crate) pool_idle_timeout: usize,

    /// Client timeout
    #[builder(setter(into), default = "600")]
    pub(crate) timeout: usize,

    /// Client connect timeout
    #[builder(setter(into), default = "60")]
    pub(crate) connect_timeout: usize,

    /// Server proxies
    #[builder(setter(into), default)]
    pub(crate) proxies: Vec<String>,

    /// Bind address for outgoing connections
    #[builder(setter(into), default)]
    pub(crate) interface: Option<std::net::IpAddr>,

    /// Ipv6 Subnet
    #[builder(setter(into), default)]
    pub(crate) ipv6_subnet: Option<(std::net::Ipv6Addr, u8)>,

    /// Web UI api prefix
    #[builder(setter(into), default)]
    pub(crate) api_prefix: Option<String>,

    /// PreAuth Cookie API URL
    #[builder(setter(into), default)]
    pub(crate) preauth_api: Option<String>,

    /// TLS keypair
    #[builder(setter(into), default)]
    pub(crate) tls_keypair: Option<(PathBuf, PathBuf)>,

    /// Login auth key
    #[builder(setter(into), default)]
    auth_key: Option<String>,

    /// Disable web ui
    #[builder(setter(into), default = "false")]
    pub(crate) disable_ui: bool,

    /// Cloudflare captcha site key
    #[builder(setter(into), default)]
    pub(crate) cf_site_key: Option<String>,

    /// Cloudflare captcha secret key
    #[builder(setter(into), default)]
    pub(crate) cf_secret_key: Option<String>,

    /// Arkose endpoint
    #[builder(setter(into), default)]
    pub(crate) arkose_endpoint: Option<String>,

    /// ChatGPT Arkoselabs HAR record file path
    #[builder(setter(into), default)]
    pub(crate) arkose_chat_har_file: Option<PathBuf>,

    /// Auth Arkoselabs HAR record file path
    #[builder(setter(into), default)]
    pub(crate) arkose_auth_har_file: Option<PathBuf>,

    /// Platform Arkoselabs HAR record file path
    #[builder(setter(into), default)]
    pub(crate) arkose_platform_har_file: Option<PathBuf>,

    /// HAR file upload authenticate key
    #[builder(setter(into), default)]
    pub(crate) arkose_har_upload_key: Option<String>,

    /// get arkose-token endpoint
    #[builder(setter(into), default)]
    pub(crate) arkose_token_endpoint: Option<String>,

    /// arkoselabs solver
    #[builder(setter(into), default)]
    pub(crate) arkose_solver: Option<ArkoseSolver>,

    /// Enable Tokenbucket
    #[cfg(feature = "limit")]
    #[builder(setter(into), default = "false")]
    pub(crate) tb_enable: bool,

    /// Tokenbucket store strategy
    #[cfg(feature = "limit")]
    #[builder(
        setter(into),
        default = "crate::serve::middleware::tokenbucket::Strategy::Mem"
    )]
    pub(crate) tb_store_strategy: tokenbucket::Strategy,

    /// Tokenbucket redis url
    #[cfg(feature = "limit")]
    #[builder(setter(into), default = "String::from(\"redis://127.0.0.1:6379\")")]
    pub(crate) tb_redis_url: String,

    /// Tokenbucket capacity
    #[cfg(feature = "limit")]
    #[builder(setter(into), default = "60")]
    pub(crate) tb_capacity: u32,

    /// Tokenbucket fill rate
    #[cfg(feature = "limit")]
    #[builder(setter(into), default = "1")]
    pub(crate) tb_fill_rate: u32,

    /// Tokenbucket expired (second)
    #[cfg(feature = "limit")]
    #[builder(setter(into), default = "86400")]
    pub(crate) tb_expired: u32,
}

#[derive(Debug)]
pub struct Har {
    /// HAR file path
    path: PathBuf,
    /// HAR file state (file changed)
    state: bool,
    /// File Hotwatch
    hotwatch: Hotwatch,
}

impl Drop for Har {
    fn drop(&mut self) {
        if let Some(err) = self.hotwatch.unwatch(self.path.as_path()).err() {
            warn!("hotwatch stop error: {err}")
        }
    }
}

pub struct CfTurnstile {
    pub site_key: String,
    pub secret_key: String,
}

// Program context
static CTX: OnceLock<Context> = OnceLock::new();
static HAR: OnceLock<RwLock<HashMap<arkose::Type, Har>>> = OnceLock::new();

pub struct Context {
    client_load: Option<ClientLoadBalancer>,
    auth_client_load: Option<ClientLoadBalancer>,
    /// arkoselabs solver
    arkose_solver: Option<ArkoseSolver>,
    /// get arkose-token endpoint
    arkose_token_endpoint: Option<String>,
    /// HAR file upload authenticate key
    arkose_har_upload_key: Option<String>,
    /// Login auth key
    auth_key: Option<String>,
    /// Cloudflare Turnstile
    cf_turnstile: Option<CfTurnstile>,
    /// Web UI api prefix
    api_prefix: Option<String>,
    /// Arkose endpoint
    arkose_endpoint: Option<String>,
}

impl Context {
    fn new(args: ContextArgs) -> Self {
        let chat_har = init_har(
            arkose::Type::Chat,
            &args.arkose_chat_har_file,
            ".chat.openai.com.har",
        );
        let auth_har = init_har(
            arkose::Type::Auth0,
            &args.arkose_auth_har_file,
            ".auth.openai.com.har",
        );
        let platform_har = init_har(
            arkose::Type::Platform,
            &args.arkose_platform_har_file,
            ".platform.openai.com.har",
        );

        let mut har_map = HashMap::with_capacity(3);
        har_map.insert(arkose::Type::Chat, chat_har);
        har_map.insert(arkose::Type::Auth0, auth_har);
        har_map.insert(arkose::Type::Platform, platform_har);
        HAR.set(std::sync::RwLock::new(har_map))
            .expect("Failed to set har map");

        Context {
            client_load: Some(
                ClientLoadBalancer::new_client(&args)
                    .expect("Failed to initialize the requesting client"),
            ),
            auth_client_load: Some(
                ClientLoadBalancer::new_auth_client(&args)
                    .expect("Failed to initialize the requesting oauth client"),
            ),
            arkose_endpoint: args.arkose_endpoint,
            arkose_solver: args.arkose_solver,
            arkose_token_endpoint: args.arkose_token_endpoint,
            arkose_har_upload_key: args.arkose_har_upload_key,
            cf_turnstile: args.cf_site_key.and_then(|site_key| {
                args.cf_secret_key.map(|secret_key| CfTurnstile {
                    site_key,
                    secret_key,
                })
            }),
            api_prefix: args.api_prefix,
            auth_key: args.auth_key,
        }
    }

    /// Get the reqwest client
    pub fn client(&self) -> Client {
        self.client_load
            .as_ref()
            .expect("The load balancer client is not initialized")
            .next()
            .into()
    }

    /// Get the reqwest auth client
    pub fn auth_client(&self) -> AuthClient {
        self.auth_client_load
            .as_ref()
            .expect("The load balancer auth client is not initialized")
            .next()
            .into()
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

    pub fn arkose_har_path(&self, _type: &arkose::Type) -> (bool, PathBuf) {
        let har_lock = HAR
            .get()
            .expect("Failed to get har lock")
            .read()
            .expect("Failed to get har map");
        har_lock
            .get(_type)
            .map(|h| (h.state, h.path.clone()))
            .expect("Failed to get har path")
    }

    pub fn cf_turnstile(&self) -> Option<&CfTurnstile> {
        self.cf_turnstile.as_ref()
    }

    pub fn api_prefix(&self) -> Option<&String> {
        self.api_prefix.as_ref()
    }

    pub fn arkose_endpoint(&self) -> Option<&String> {
        self.arkose_endpoint.as_ref()
    }

    pub fn auth_key(&self) -> Option<&String> {
        self.auth_key.as_ref()
    }
}

fn init_har(_type: arkose::Type, path: &Option<PathBuf>, default_filename: &str) -> Har {
    if let Some(file_path) = path {
        return Har {
            path: file_path.to_owned(),
            state: true,
            hotwatch: watch_har_file(_type, &file_path),
        };
    }

    let default_path = home_dir()
        .expect("Failed to get home directory")
        .join(default_filename);

    let state = match default_path.is_file() {
        true => {
            let har_data = std::fs::read(&default_path).expect("Failed to read har file");
            !har_data.is_empty()
        }
        false => {
            info!("Create default HAR empty file: {}", default_path.display());
            let har_file = std::fs::File::create(&default_path).expect("Failed to create har file");
            drop(har_file);
            false
        }
    };

    Har {
        hotwatch: watch_har_file(_type, &default_path),
        path: default_path,
        state,
    }
}

fn watch_har_file(_type: arkose::Type, path: &PathBuf) -> Hotwatch {
    let watch_path = path.display();
    let mut hotwatch = Hotwatch::new().expect("hotwatch failed to initialize!");
    hotwatch
        .watch(watch_path.to_string(), {
            let _type = _type;
            move |event: Event| {
                if let EventKind::Modify(_) = event.kind {
                    event.paths.iter().for_each(|path| {
                        info!("HAR file changes observed: {}", path.display());
                        let lock = HAR.get().expect("Failed to get har lock");
                        let mut har_map = lock.write().expect("Failed to get har map");
                        if let Some(har) = har_map.get_mut(&_type) {
                            har.state = true;
                            match path.to_str() {
                                Some(path_str) => arkose::har::clear(path_str),
                                None => warn!("Failed to convert path to string"),
                            }
                        }
                    });
                }
            }
        })
        .expect("failed to watch file!");
    hotwatch
}
