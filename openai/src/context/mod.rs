pub mod args;
mod har;
mod preauth;

use self::{
    args::Args,
    har::{HarPath, HarProvider, HAR},
    preauth::PreauthCookieProvider,
};
use crate::{
    arkose::{self, funcaptcha::ArkoseSolver},
    auth::AuthClient,
    client::ClientRoundRobinBalancer,
    error,
};
use reqwest::Client;
use std::{collections::HashMap, sync::OnceLock};

#[macro_export]
macro_rules! with_context {
    ($method:ident) => {{
        crate::context::get_instance().$method()
    }};
    ($method:ident, $($arg:expr),*) => {{
        crate::context::get_instance().$method($($arg),*)
    }};
    () => {
        crate::context::get_instance()
    };
}

/// Use Once to guarantee initialization only once
pub fn init(args: Args) {
    if let Some(_) = CTX.set(Context::new(args)).err() {
        error!("Failed to initialize context");
    };
}

/// Get the program context
pub fn get_instance() -> &'static Context {
    CTX.get_or_init(|| Context::new(Args::builder().build()))
}

pub struct CfTurnstile {
    pub site_key: String,
    pub secret_key: String,
}

// Program context
static CTX: OnceLock<Context> = OnceLock::new();

pub struct Context {
    /// Requesting client
    api_client: ClientRoundRobinBalancer,
    /// Requesting oauth client
    auth_client: ClientRoundRobinBalancer,
    /// Requesting arkose client
    arkose_client: ClientRoundRobinBalancer,
    /// arkoselabs solver
    arkose_solver: Option<ArkoseSolver>,
    /// HAR file upload authenticate key
    arkose_har_upload_key: Option<String>,
    /// Enable files proxy
    enable_file_proxy: bool,
    /// Login auth key
    auth_key: Option<String>,
    /// visitor_email_whitelist
    visitor_email_whitelist: Option<Vec<String>>,
    /// Cloudflare Turnstile
    cf_turnstile: Option<CfTurnstile>,
    /// Arkose endpoint
    arkose_endpoint: Option<String>,
    /// Enable Arkose GPT-3.5 experiment
    arkose_gpt3_experiment: bool,
    /// Enable Arkose GPT-3.5 experiment solver
    arkose_gpt3_experiment_solver: bool,
    /// PreAuth cookie cache
    preauth_provider: Option<PreauthCookieProvider>,
}

impl Context {
    fn new(args: Args) -> Self {
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

        // Set the har map
        HAR.set(std::sync::RwLock::new(har_map))
            .expect("Failed to set har map");

        Context {
            api_client: ClientRoundRobinBalancer::new_client(&args)
                .expect("Failed to initialize the requesting client"),
            auth_client: ClientRoundRobinBalancer::new_auth_client(&args)
                .expect("Failed to initialize the requesting oauth client"),
            arkose_client: ClientRoundRobinBalancer::new_arkose_client(&args)
                .expect("Failed to initialize the requesting arkose client"),
            arkose_endpoint: args.arkose_endpoint,
            arkose_solver: args.arkose_solver,
            arkose_har_upload_key: args.arkose_har_upload_key,
            arkose_gpt3_experiment: args.arkose_gpt3_experiment,
            arkose_gpt3_experiment_solver: args.arkose_gpt3_experiment_solver,
            enable_file_proxy: args.enable_file_proxy,
            auth_key: args.auth_key,
            visitor_email_whitelist: args.visitor_email_whitelist,
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
    pub fn api_client(&self) -> Client {
        self.api_client.next().into()
    }

    /// Get the reqwest auth client
    pub fn auth_client(&self) -> AuthClient {
        self.auth_client.next().into()
    }

    /// Get the reqwest arkose client
    pub fn arkose_client(&self) -> Client {
        self.arkose_client.next().into()
    }

    /// Get the arkoselabs har file upload authenticate key
    pub fn arkose_har_upload_key(&self) -> Option<&str> {
        self.arkose_har_upload_key.as_deref()
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

    /// Arkoselabs endpoint
    pub fn arkose_endpoint(&self) -> Option<&str> {
        self.arkose_endpoint.as_deref()
    }

    /// Login auth key
    pub fn auth_key(&self) -> Option<&str> {
        self.auth_key.as_deref()
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

    /// Get the arkose gpt3 experiment
    pub fn arkose_gpt3_experiment(&self) -> bool {
        self.arkose_gpt3_experiment
    }

    /// Enable file proxy
    pub fn enable_file_proxy(&self) -> bool {
        self.enable_file_proxy
    }

    /// Get the visitor email whitelist
    pub fn visitor_email_whitelist(&self) -> Option<&[String]> {
        self.visitor_email_whitelist.as_deref()
    }

    /// Get the arkose gpt3 experiment solver
    pub fn arkose_gpt3_experiment_solver(&self) -> bool {
        self.arkose_gpt3_experiment_solver
    }
}
