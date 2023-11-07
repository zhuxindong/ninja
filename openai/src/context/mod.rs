mod har;
mod preauth;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::OnceLock,
};

use crate::{
    arkose::{self, funcaptcha::ArkoseSolver},
    auth::AuthClient,
    balancer::ClientRoundRobinBalancer,
    error,
};
use reqwest::Client;
use typed_builder::TypedBuilder;

use self::{
    har::{HarPath, HarProvider, HAR},
    preauth::PreauthCookieProvider,
};

/// Use Once to guarantee initialization only once
pub fn init(args: ContextArgs) {
    if let Some(_) = CTX.set(Context::new(args)).err() {
        error!("Failed to initialize context");
    };
}

/// Get the program context
pub fn get_instance() -> &'static Context {
    CTX.get_or_init(|| Context::new(ContextArgs::builder().build()))
}

#[derive(TypedBuilder, Clone, Default)]
pub struct ContextArgs {
    /// Server bind address
    #[builder(setter(into), default = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 7999)))]
    pub(crate) bind: Option<SocketAddr>,

    /// Machine worker pool
    #[builder(setter(into), default = 1)]
    pub(crate) workers: usize,

    /// Concurrent limit (Enforces a limit on the concurrent number of requests the underlying)
    #[builder(setter(into), default = 65535)]
    pub(crate) concurrent_limit: usize,

    /// Disable direct connection
    #[builder(default = false)]
    pub(crate) disable_direct: bool,

    /// Enabled Cookie Store
    #[builder(default = false)]
    pub(crate) cookie_store: bool,

    /// TCP keepalive (second)
    #[builder(setter(into), default = 75)]
    pub(crate) tcp_keepalive: usize,

    /// Set an optional timeout for idle sockets being kept-alive
    #[builder(setter(into), default = 90)]
    pub(crate) pool_idle_timeout: usize,

    /// Client timeout
    #[builder(setter(into), default = 600)]
    pub(crate) timeout: usize,

    /// Client connect timeout
    #[builder(setter(into), default = 60)]
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

    /// TLS cert
    #[builder(setter(into), default)]
    pub(crate) tls_cert: Option<PathBuf>,

    /// TLS key
    #[builder(setter(into), default)]
    pub(crate) tls_key: Option<PathBuf>,

    /// Login auth key
    #[builder(setter(into), default)]
    auth_key: Option<String>,

    /// Disable web ui
    #[builder(setter(into), default = false)]
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

    /// ChatGPT GPT-3.5 Arkoselabs HAR record file path
    #[builder(setter(into), default)]
    pub(crate) arkose_gpt3_har_dir: Option<PathBuf>,

    /// ChatGPT GPT-4 Arkoselabs HAR record file path
    #[builder(setter(into), default)]
    pub(crate) arkose_gpt4_har_dir: Option<PathBuf>,

    /// Auth Arkoselabs HAR record file path
    #[builder(setter(into), default)]
    pub(crate) arkose_auth_har_dir: Option<PathBuf>,

    /// Platform Arkoselabs HAR record file path
    #[builder(setter(into), default)]
    pub(crate) arkose_platform_har_dir: Option<PathBuf>,

    /// HAR file upload authenticate key
    #[builder(setter(into), default)]
    pub(crate) arkose_har_upload_key: Option<String>,

    /// arkoselabs solver
    #[builder(setter(into), default)]
    pub(crate) arkose_solver: Option<ArkoseSolver>,

    /// Enable Tokenbucket
    #[cfg(feature = "limit")]
    #[builder(setter(into), default = false)]
    pub(crate) tb_enable: bool,

    /// Tokenbucket store strategy
    #[cfg(feature = "limit")]
    #[builder(setter(into), default = "mem".to_string())]
    pub(crate) tb_store_strategy: String,

    /// Tokenbucket redis url
    #[cfg(feature = "limit")]
    #[builder(setter(into), default = "redis://127.0.0.1:6379".to_string())]
    pub(crate) tb_redis_url: String,

    /// Tokenbucket capacity
    #[cfg(feature = "limit")]
    #[builder(setter(into), default = 60)]
    pub(crate) tb_capacity: u32,

    /// Tokenbucket fill rate
    #[cfg(feature = "limit")]
    #[builder(setter(into), default = 1)]
    pub(crate) tb_fill_rate: u32,

    /// Tokenbucket expired (second)
    #[cfg(feature = "limit")]
    #[builder(setter(into), default = 86400)]
    pub(crate) tb_expired: u32,

    /// Preauth MITM server bind address
    #[cfg(feature = "preauth")]
    #[builder(setter(into), default)]
    pub(crate) pbind: Option<std::net::SocketAddr>,

    /// Preauth MITM server upstream proxy
    #[cfg(feature = "preauth")]
    #[builder(setter(into), default)]
    pub(crate) pupstream: Option<String>,

    /// crate MITM server CA certificate file path
    #[cfg(feature = "preauth")]
    #[builder(setter(into), default)]
    pub(super) pcert: PathBuf,

    /// Preauth MITM server CA private key file path
    #[cfg(feature = "preauth")]
    #[builder(setter(into), default)]
    pub(crate) pkey: PathBuf,
}

pub struct CfTurnstile {
    pub site_key: String,
    pub secret_key: String,
}

// Program context
static CTX: OnceLock<Context> = OnceLock::new();

pub struct Context {
    /// Requesting client
    client_load: Option<ClientRoundRobinBalancer>,
    /// Requesting oauth client
    auth_client_load: Option<ClientRoundRobinBalancer>,
    /// arkoselabs solver
    arkose_solver: Option<ArkoseSolver>,
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
    /// PreAuth cookie cache
    preauth_provider: Option<PreauthCookieProvider>,
}

impl Context {
    fn new(args: ContextArgs) -> Self {
        let gpt3_har_provider = HarProvider::new(
            arkose::Type::GPT3,
            args.arkose_gpt3_har_dir.as_ref(),
            ".gpt3",
        );
        let gpt4_har_provider = HarProvider::new(
            arkose::Type::GPT4,
            args.arkose_gpt4_har_dir.as_ref(),
            ".gpt4",
        );
        let auth_har_provider = HarProvider::new(
            arkose::Type::Auth,
            args.arkose_auth_har_dir.as_ref(),
            ".auth",
        );
        let platform_har_provider = HarProvider::new(
            arkose::Type::Platform,
            args.arkose_platform_har_dir.as_ref(),
            ".platform",
        );

        let mut har_map = HashMap::with_capacity(4);
        har_map.insert(arkose::Type::GPT3, gpt3_har_provider);
        har_map.insert(arkose::Type::GPT4, gpt4_har_provider);
        har_map.insert(arkose::Type::Auth, auth_har_provider);
        har_map.insert(arkose::Type::Platform, platform_har_provider);
        HAR.set(std::sync::RwLock::new(har_map))
            .expect("Failed to set har map");

        Context {
            client_load: Some(
                ClientRoundRobinBalancer::new_client(&args)
                    .expect("Failed to initialize the requesting client"),
            ),
            auth_client_load: Some(
                ClientRoundRobinBalancer::new_auth_client(&args)
                    .expect("Failed to initialize the requesting oauth client"),
            ),
            arkose_endpoint: args.arkose_endpoint,
            arkose_solver: args.arkose_solver,
            arkose_har_upload_key: args.arkose_har_upload_key,
            api_prefix: args.api_prefix,
            auth_key: args.auth_key,
            cf_turnstile: args.cf_site_key.and_then(|site_key| {
                args.cf_secret_key.map(|secret_key| CfTurnstile {
                    site_key,
                    secret_key,
                })
            }),
            preauth_provider: args.pbind.is_some().then(|| PreauthCookieProvider::new()),
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

    /// Get the arkoselabs har file upload authenticate key
    pub fn arkose_har_upload_key(&self) -> Option<&String> {
        self.arkose_har_upload_key.as_ref()
    }

    /// Get the arkoselabs solver
    pub fn arkose_solver(&self) -> Option<&ArkoseSolver> {
        self.arkose_solver.as_ref()
    }

    /// Get the arkose har file path
    pub fn arkose_har_path(&self, _type: &arkose::Type) -> HarPath {
        let har_lock = HAR
            .get()
            .expect("Failed to get har lock")
            .read()
            .expect("Failed to get har map");
        har_lock
            .get(_type)
            .map(|h| h.pool())
            .expect("Failed to get har pool")
    }

    /// Cloudflare Turnstile config
    pub fn cf_turnstile(&self) -> Option<&CfTurnstile> {
        self.cf_turnstile.as_ref()
    }

    /// WebUI api prefix
    pub fn api_prefix(&self) -> Option<&String> {
        self.api_prefix.as_ref()
    }

    /// Arkoselabs endpoint
    pub fn arkose_endpoint(&self) -> Option<&String> {
        self.arkose_endpoint.as_ref()
    }

    /// Login auth key
    pub fn auth_key(&self) -> Option<&String> {
        self.auth_key.as_ref()
    }

    /// Push a preauth cookie
    #[cfg(feature = "preauth")]
    pub fn push_preauth_cookie(&self, value: &str) {
        self.preauth_provider.as_ref().map(|p| p.push(value));
    }

    /// Pop a preauth cookie
    #[cfg(feature = "preauth")]
    pub fn pop_preauth_cookie(&self) -> Option<String> {
        self.preauth_provider.as_ref().map(|p| p.get()).flatten()
    }
}
