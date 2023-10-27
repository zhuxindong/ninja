use crate::parse;
use clap::{Args, Subcommand};
use openai::{arkose::funcaptcha::Solver, serve::middleware::tokenbucket::Strategy};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(all(feature = "serve", not(feature = "terminal")))]
pub mod cmd {
    use super::ServeSubcommand;
    use clap::Parser;

    #[derive(Parser)]
    #[clap(author, version, about, arg_required_else_help = true)]
    pub struct Opt {
        #[clap(subcommand)]
        pub command: Option<ServeSubcommand>,
    }
}

#[cfg(all(feature = "serve", feature = "terminal"))]
pub mod cmd {
    use super::{ServeSubcommand, Subcommand};
    use clap::Parser;
    #[derive(Parser)]
    #[clap(author, version, about, arg_required_else_help = true)]
    pub struct Opt {
        #[clap(subcommand)]
        pub command: Option<SubCommands>,
    }

    #[allow(clippy::large_enum_variant)]
    #[derive(Subcommand)]
    pub enum SubCommands {
        /// Start the http server
        #[clap(subcommand)]
        Serve(ServeSubcommand),
        /// Terminal interaction
        Terminal,
    }
}

#[derive(Subcommand)]
pub enum ServeSubcommand {
    /// Run the HTTP server
    Run(ServeArgs),
    /// Stop the HTTP server daemon
    #[cfg(target_family = "unix")]
    Stop,
    /// Start the HTTP server daemon
    #[cfg(target_family = "unix")]
    Start(ServeArgs),
    /// Restart the HTTP server daemon
    #[cfg(target_family = "unix")]
    Restart(ServeArgs),
    /// Status of the Http server daemon process
    #[cfg(target_family = "unix")]
    Status,
    /// Show the Http server daemon log
    #[cfg(target_family = "unix")]
    Log,
    /// Generate MITM CA certificate
    Genca,
    /// Generate config template file (toml format file)
    GT {
        /// Configuration template output to file (toml format file)
        #[clap(short, long, group = "gt")]
        out: Option<PathBuf>,
    },
}

#[derive(Args, Debug, Default, Serialize, Deserialize)]
pub struct ServeArgs {
    /// Log level (info/debug/warn/trace/error)
    #[clap(short = 'L', long, global = true, env = "LOG", default_value = "info")]
    pub(super) level: String,

    /// Configuration file path (toml format file)
    #[clap(short = 'C', long, env = "CONFIG", value_parser = parse::parse_file_path)]
    pub(super) config: Option<PathBuf>,

    /// Server bind address
    #[clap(short, long, env = "BIND", default_value = "0.0.0.0:7999", value_parser = parse::parse_socket_addr)]
    pub(super) bind: Option<std::net::SocketAddr>,

    /// Server worker-pool size (Recommended number of CPU cores)
    #[clap(short = 'W', long, default_value = "1")]
    pub(super) workers: usize,

    /// Enforces a limit on the concurrent number of requests the underlying
    #[clap(long, default_value = "65535")]
    pub(super) concurrent_limit: usize,

    /// Server proxies pool, Example: protocol://user:pass@ip:port
    #[clap(short = 'x',long, env = "PROXIES", value_parser = parse::parse_proxies_url, group = "proxy")]
    pub(super) proxies: Option<std::vec::Vec<String>>,

    /// Bind address for outgoing connections (or IPv6 subnet fallback to Ipv4)
    #[clap(short = 'i', long, env = "INTERFACE", value_parser = parse::parse_host)]
    pub(super) interface: Option<std::net::IpAddr>,

    /// IPv6 subnet, Example: 2001:19f0:6001:48e4::/64
    #[clap(long, short = 'I', env = "IPV4_SUBNET", value_parser = parse::parse_ipv6_subnet, group = "proxy")]
    pub(super) ipv6_subnet: Option<(std::net::Ipv6Addr, u8)>,

    /// Disable direct connection
    #[clap(long, env = "DISABLE_DIRECT")]
    pub(super) disable_direct: bool,

    /// Enabled Cookie Store
    #[clap(long, env = "COOKIE_STORE")]
    pub(super) cookie_store: bool,

    /// Client timeout (seconds)
    #[clap(long, default_value = "600")]
    pub(super) timeout: usize,

    /// Client connect timeout (seconds)
    #[clap(long, default_value = "60")]
    pub(super) connect_timeout: usize,

    /// TCP keepalive (seconds)
    #[clap(long, default_value = "60")]
    pub(super) tcp_keepalive: usize,

    /// Set an optional timeout for idle sockets being kept-alive
    #[clap(long, default_value = "90")]
    pub(super) pool_idle_timeout: usize,

    /// TLS certificate file path
    #[clap(long, env = "TLS_CERT", requires = "tls_key")]
    pub(super) tls_cert: Option<PathBuf>,

    /// TLS private key file path (EC/PKCS8/RSA)
    #[clap(long, env = "TLS_KEY", requires = "tls_cert")]
    pub(super) tls_key: Option<PathBuf>,

    /// Login Authentication Key
    #[clap(short = 'A', long, env = "AUTH_KEY")]
    pub(super) auth_key: Option<String>,

    /// WebUI api prefix
    #[clap(long, env = "API_PREFIX", value_parser = parse::parse_url)]
    pub(super) api_prefix: Option<String>,

    /// PreAuth Cookie API URL
    #[clap(long, env = "PREAUTH_API", value_parser = parse::parse_url)]
    pub(super) preauth_api: Option<String>,

    /// Disable WebUI
    #[clap(short = 'D', long, env = "DISABLE_WEBUI")]
    pub(super) disable_webui: bool,

    /// Cloudflare turnstile captcha site key
    #[clap(long, env = "CF_SECRET_KEY", requires = "cf_secret_key")]
    pub(super) cf_site_key: Option<String>,

    /// Cloudflare turnstile captcha secret key
    #[clap(long, env = "CF_SITE_KEY", requires = "cf_site_key")]
    pub(super) cf_secret_key: Option<String>,

    /// Arkose endpoint, Example: https://client-api.arkoselabs.com
    #[clap(long, value_parser = parse::parse_url)]
    pub(super) arkose_endpoint: Option<String>,

    /// About the browser HAR file path requested by ChatGPT GPT-3.5 ArkoseLabs
    #[clap(long, value_parser = parse::parse_file_path)]
    pub(super) arkose_chat3_har_file: Option<PathBuf>,

    /// About the browser HAR file path requested by ChatGPT GPT-4 ArkoseLabs
    #[clap(long, value_parser = parse::parse_file_path)]
    pub(super) arkose_chat4_har_file: Option<PathBuf>,

    /// About the browser HAR file path requested by Auth ArkoseLabs
    #[clap(long, value_parser = parse::parse_file_path)]
    pub(super) arkose_auth_har_file: Option<PathBuf>,

    /// About the browser HAR file path requested by Platform ArkoseLabs
    #[clap(long, value_parser = parse::parse_file_path)]
    pub(super) arkose_platform_har_file: Option<PathBuf>,

    /// HAR file upload authenticate key
    #[clap(short = 'K', long)]
    pub(super) arkose_har_upload_key: Option<String>,

    /// About ArkoseLabs solver platform
    #[clap(
        short = 's',
        long,
        default_value = "yescaptcha",
        requires = "arkose_solver_key"
    )]
    pub(super) arkose_solver: Solver,

    #[clap(short = 'k', long)]
    /// About the solver client key by ArkoseLabs
    pub(super) arkose_solver_key: Option<String>,

    /// Enable token bucket flow limitation
    #[clap(short = 'T', long)]
    #[cfg(feature = "limit")]
    pub(super) tb_enable: bool,

    /// Token bucket store strategy (mem/redis)
    #[clap(long, default_value = "mem", requires = "tb_enable")]
    #[cfg(feature = "limit")]
    pub(super) tb_store_strategy: Strategy,

    /// Token bucket redis connection url
    #[clap(long, default_value = "redis://127.0.0.1:6379", requires = "tb_enable", value_parser = parse::parse_url)]
    #[cfg(feature = "limit")]
    pub(super) tb_redis_url: String,

    /// Token bucket capacity
    #[clap(long, default_value = "60", requires = "tb_enable")]
    #[cfg(feature = "limit")]
    pub(super) tb_capacity: u32,

    /// Token bucket fill rate
    #[clap(long, default_value = "1", requires = "tb_enable")]
    #[cfg(feature = "limit")]
    pub(super) tb_fill_rate: u32,

    /// Token bucket expired (seconds)
    #[clap(long, default_value = "86400", requires = "tb_enable")]
    #[cfg(feature = "limit")]
    pub(super) tb_expired: u32,

    /// Preauth MITM server bind address
    #[clap(
        short = 'B',
        long,
        env = "PREAUTH_BIND",
        default_value = "0.0.0.0:8000",
        value_parser = parse::parse_socket_addr
    )]
    pub(super) preauth_bind: Option<std::net::SocketAddr>,

    /// Preauth MITM server upstream proxy
    #[clap(
        short = 'X',
        long,
        env = "PREAUTH_UPSTREAM",
        value_parser = parse::parse_url
    )]
    pub(super) preauth_upstream: Option<String>,

    /// Preauth MITM server CA certificate file path
    #[clap(long, default_value = "ca/cert.crt")]
    pub(super) preauth_cert: Option<String>,

    /// Preauth MITM server CA private key file path
    #[clap(long, default_value = "ca/key.pem")]
    pub(super) preauth_key: Option<String>,
}
