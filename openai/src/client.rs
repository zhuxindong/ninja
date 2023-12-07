use crate::auth::{self};
use crate::context::args::Args;
use crate::dns::{self, TrustDnsResolver};
use crate::{
    auth::AuthClient,
    proxy::{self, Ipv6CidrExt},
};
use moka::sync::Cache;
use reqwest::{impersonate::Impersonate, Client};
use std::sync::{Arc, OnceLock};
use std::{
    net::IpAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use trust_dns_resolver::config::LookupIpStrategy;
use url::Url;

/// Client type
#[derive(Clone)]
pub enum ClientAgent {
    Api(Client),
    Arkose(Client),
    Auth(AuthClient),
}

impl Into<AuthClient> for ClientAgent {
    fn into(self) -> AuthClient {
        match self {
            ClientAgent::Auth(client) => client,
            _ => panic!("Attempted to convert a non-Auth client into AuthClient"),
        }
    }
}

impl Into<Client> for ClientAgent {
    fn into(self) -> Client {
        match self {
            ClientAgent::Api(client) => client,
            ClientAgent::Arkose(client) => client,
            _ => panic!("Attempted to convert a non-Regular client into Client"),
        }
    }
}

#[derive(Hash, PartialEq, Eq)]
enum LookupIpStrategyExt {
    /// Only query for A (Ipv4) records
    Ipv4Only,
    /// Only query for AAAA (Ipv6) records
    Ipv6Only,
    /// Query for A and AAAA in parallel
    Ipv4AndIpv6,
    /// Query for Ipv6 if that fails, query for Ipv4
    Ipv6thenIpv4,
    /// Query for Ipv4 if that fails, query for Ipv6 (default)
    Ipv4thenIpv6,
}

impl LookupIpStrategyExt {
    fn from_strategy(strategy: LookupIpStrategy) -> Self {
        match strategy {
            LookupIpStrategy::Ipv4Only => Self::Ipv4Only,
            LookupIpStrategy::Ipv6Only => Self::Ipv6Only,
            LookupIpStrategy::Ipv4AndIpv6 => Self::Ipv4AndIpv6,
            LookupIpStrategy::Ipv6thenIpv4 => Self::Ipv6thenIpv4,
            LookupIpStrategy::Ipv4thenIpv6 => Self::Ipv4thenIpv6,
        }
    }
}

static DNS_RESOLVER: OnceLock<Cache<LookupIpStrategyExt, Arc<TrustDnsResolver>>> = OnceLock::new();

struct Config {
    /// Enable cookie store.
    cookie_store: bool,
    /// Timeout for each request.
    timeout: u64,
    /// Timeout for each connect.
    connect_timeout: u64,
    /// Timeout for each connection in the pool.
    pool_idle_timeout: u64,
    /// TCP keepalive interval.
    tcp_keepalive: u64,
    /// Random User-Agent
    impersonate_uas: Option<Vec<Impersonate>>,

    index_for_interfaces: AtomicUsize,
    /// Interfaces to bind to.
    interfaces: Vec<IpAddr>,

    index_for_ipv6_subnets: AtomicUsize,
    /// IPv6 subnets to bind to.
    ipv6_subnets: Vec<cidr::Ipv6Cidr>,
}

impl Config {
    // get next interface
    fn get_next_interface(&self) -> Option<IpAddr> {
        if self.interfaces.is_empty() {
            return None;
        }
        let len = self.interfaces.len();
        let new = get_next_index(len, &self.index_for_interfaces);
        Some(self.interfaces[new])
    }

    // get next ipv6
    fn get_next_ipv6(&self) -> Option<IpAddr> {
        if self.ipv6_subnets.is_empty() {
            return None;
        }
        let len = self.ipv6_subnets.len();
        let new = get_next_index(len, &self.index_for_ipv6_subnets);
        Some(self.ipv6_subnets[new].random_ipv6())
    }
}

/// Client round robin balancer
pub struct ClientRoundRobinBalancer {
    pool: Vec<ClientAgent>,
    index: AtomicUsize,
    config: Config,
}

impl ClientRoundRobinBalancer {
    pub fn new_client(args: &Args) -> anyhow::Result<Self> {
        let p: Vec<proxy::InnerProxy> = args
            .proxies
            .clone()
            .into_iter()
            .flat_map(|ele| match ele {
                proxy::Proxy::All(v) => Some(v),
                proxy::Proxy::Api(v) => Some(v),
                _ => None,
            })
            .collect();
        Self::new_client_generic(args, ClientAgent::Api, p, build_client)
    }

    pub fn new_auth_client(args: &Args) -> anyhow::Result<Self> {
        let p: Vec<proxy::InnerProxy> = args
            .proxies
            .clone()
            .into_iter()
            .flat_map(|ele| match ele {
                proxy::Proxy::All(v) => Some(v),
                proxy::Proxy::Auth(v) => Some(v),
                _ => None,
            })
            .collect();
        Self::new_client_generic(args, ClientAgent::Auth, p, build_auth_client)
    }

    pub fn new_arkose_client(args: &Args) -> anyhow::Result<Self> {
        let p: Vec<proxy::InnerProxy> = args
            .proxies
            .clone()
            .into_iter()
            .flat_map(|ele| match ele {
                proxy::Proxy::All(v) => Some(v),
                proxy::Proxy::Arkose(v) => Some(v),
                _ => None,
            })
            .collect();
        Self::new_client_generic(args, ClientAgent::Arkose, p, build_client)
    }

    fn new_client_generic<F, T>(
        args: &Args,
        client_type: fn(T) -> ClientAgent,
        proxy: Vec<proxy::InnerProxy>,
        build_fn: F,
    ) -> anyhow::Result<Self>
    where
        F: Fn(&Config, Option<IpAddr>, Option<IpAddr>, Option<Url>, bool) -> T,
    {
        // split proxy
        let (interfaces, proxies, ipv6_subnets): (Vec<_>, Vec<_>, Vec<_>) = proxy.into_iter().fold(
            (vec![], vec![], vec![]),
            |(mut interfaces, mut proxies, mut ipv6_subnets), p| {
                match p {
                    proxy::InnerProxy::Proxy(v) => proxies.push(v),
                    proxy::InnerProxy::Interface(v) => interfaces.push(v),
                    proxy::InnerProxy::IPv6Subnet(v) => ipv6_subnets.push(v),
                }
                (interfaces, proxies, ipv6_subnets)
            },
        );

        // init config
        let config = Config {
            cookie_store: args.cookie_store,
            timeout: args.timeout as u64,
            connect_timeout: args.connect_timeout as u64,
            pool_idle_timeout: args.pool_idle_timeout as u64,
            tcp_keepalive: args.tcp_keepalive as u64,
            interfaces,
            ipv6_subnets,
            index_for_interfaces: AtomicUsize::new(0),
            index_for_ipv6_subnets: AtomicUsize::new(0),
            impersonate_uas: args.impersonate_uas.clone(),
        };

        // init client pool
        let mut pool = Vec::with_capacity(proxies.len() + 1);

        // Helper function to join client to the pool
        let mut join_client = |bind: Option<IpAddr>, proxy: Option<Url>| {
            let client = build_fn(&config, bind, None, proxy, args.no_keepalive);
            pool.push(client_type(client));
        };

        // Join direct connection clients to pool
        if args.enable_direct {
            if config.interfaces.is_empty() {
                // if no interface is specified, join a client with no bind address
                join_client(None, None);
            } else {
                // join a client for each interface
                config
                    .interfaces
                    .iter()
                    .for_each(|i| join_client(Some(*i), None));
            }
        }

        // Join proxy clients to pool
        proxies.into_iter().for_each(|proxy| {
            // if no interface is specified, join a client with no bind address
            join_client(config.get_next_interface(), Some(proxy));
        });

        // Join a default client to the pool if it's still empty
        if pool.is_empty() {
            pool.push(client_type(build_fn(
                &config,
                None,
                None,
                None,
                args.no_keepalive,
            )));
        }

        Ok(Self {
            pool,
            config,
            index: AtomicUsize::new(0),
        })
    }
}

impl ClientRoundRobinBalancer {
    /// rebuild client with ipv6
    fn rebuild_client_with_ipv6(&self, client: &ClientAgent) -> ClientAgent {
        let bind_addr = self.config.get_next_ipv6();
        // if interface is not specified, use fallback bind address
        let fallback_bind_addr = self.config.get_next_interface();
        match client {
            ClientAgent::Auth(_) => ClientAgent::Auth(build_auth_client(
                &self.config,
                bind_addr,
                fallback_bind_addr,
                None,
                true,
            )),
            ClientAgent::Api(_) => ClientAgent::Api(build_client(
                &self.config,
                bind_addr,
                fallback_bind_addr,
                None,
                true,
            )),
            ClientAgent::Arkose(_) => ClientAgent::Arkose(build_client(
                &self.config,
                bind_addr,
                fallback_bind_addr,
                None,
                true,
            )),
        }
    }

    /// Get next client
    pub fn next(&self) -> ClientAgent {
        // if there is only one client, return it
        if self.pool.len() == 1 {
            let client = self.pool.first().expect("Init client failed");
            if !self.config.ipv6_subnets.is_empty() {
                return self.rebuild_client_with_ipv6(client);
            }
            return client.clone();
        }

        let new = get_next_index(self.pool.len(), &self.index);
        self.pool[new].clone()
    }
}

/// Build a client
fn build_client(
    config: &Config,
    preferred_addrs: Option<IpAddr>,
    fallback_addrs: Option<IpAddr>,
    proxy: Option<Url>,
    disable_keep_alive: bool,
) -> Client {
    let mut builder = Client::builder();

    // set proxy
    if let Some(url) = proxy {
        let proxy = reqwest::Proxy::all(url).expect("Failed to build proxy");
        builder = builder.proxy(proxy)
    }

    // enable cookie store
    if config.cookie_store {
        builder = builder.cookie_store(true);
    }

    // disable keep alive
    if disable_keep_alive {
        builder = builder.tcp_keepalive(None);
    } else {
        builder = builder
            .tcp_keepalive(Duration::from_secs(config.tcp_keepalive))
            .pool_idle_timeout(Duration::from_secs(config.pool_idle_timeout));
    }

    // return lookup ip strategy
    let ip_s = match (preferred_addrs, fallback_addrs) {
        (None, Some(ip_addr)) | (Some(ip_addr), None) => {
            builder = builder.local_address(ip_addr);
            if ip_addr.is_ipv4() {
                LookupIpStrategy::Ipv4Only
            } else {
                LookupIpStrategy::Ipv6Only
            }
        }
        (Some(IpAddr::V4(v4)), Some(IpAddr::V6(v6)))
        | (Some(IpAddr::V6(v6)), Some(IpAddr::V4(v4))) => {
            builder = builder.local_addresses(v4, v6);
            LookupIpStrategy::Ipv6thenIpv4
        }
        _ => LookupIpStrategy::Ipv4AndIpv6,
    };

    // init dns resolver
    let trust_dns_resolver = get_or_init_dns_resolver(ip_s);

    builder
        .impersonate(random_impersonate(config.impersonate_uas.as_ref()))
        .danger_accept_invalid_certs(true)
        .permute_extensions(true)
        .enable_ech_grease(true)
        .connect_timeout(Duration::from_secs(config.connect_timeout))
        .timeout(Duration::from_secs(config.timeout))
        .dns_resolver(trust_dns_resolver)
        .build()
        .expect("Failed to build API client")
}

/// Build an authenticated client.
fn build_auth_client(
    config: &Config,
    preferred_addrs: Option<IpAddr>,
    fallback_addrs: Option<IpAddr>,
    proxy: Option<Url>,
    disable_keep_alive: bool,
) -> AuthClient {
    let mut builder = auth::AuthClientBuilder::builder();

    // disable keep alive
    if disable_keep_alive {
        builder = builder.tcp_keepalive(None);
    } else {
        builder = builder
            .tcp_keepalive(Duration::from_secs(config.tcp_keepalive))
            .pool_idle_timeout(Duration::from_secs(config.pool_idle_timeout));
    }

    // return lookup ip strategy
    let ip_s = match (preferred_addrs, fallback_addrs) {
        (None, Some(ip_addr)) | (Some(ip_addr), None) => {
            builder = builder.local_address(ip_addr);
            if ip_addr.is_ipv4() {
                LookupIpStrategy::Ipv4Only
            } else {
                LookupIpStrategy::Ipv6Only
            }
        }
        (Some(IpAddr::V4(v4)), Some(IpAddr::V6(v6)))
        | (Some(IpAddr::V6(v6)), Some(IpAddr::V4(v4))) => {
            builder = builder.local_addresses(v4, v6);
            LookupIpStrategy::Ipv6thenIpv4
        }
        _ => LookupIpStrategy::Ipv4AndIpv6,
    };

    // init dns resolver
    let trust_dns_resolver = get_or_init_dns_resolver(ip_s);

    builder
        .impersonate(random_impersonate(config.impersonate_uas.as_ref()))
        .danger_accept_invalid_certs(true)
        .permute_extensions(true)
        .enable_ech_grease(true)
        .timeout(Duration::from_secs(config.timeout))
        .connect_timeout(Duration::from_secs(config.connect_timeout))
        .dns_resolver(trust_dns_resolver)
        .proxy(proxy)
        .build()
}

// get next index for round robin
fn get_next_index(len: usize, counter: &AtomicUsize) -> usize {
    let mut old = counter.load(Ordering::Relaxed);
    let mut new;
    loop {
        new = (old + 1) % len;
        match counter.compare_exchange_weak(old, new, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => break,
            Err(x) => old = x,
        }
    }
    new
}

/// Create a DNS resolver
fn get_or_init_dns_resolver(ip_strategy: LookupIpStrategy) -> Arc<dns::TrustDnsResolver> {
    // maybe DNS_RESOLVER is not initialized
    let cache = DNS_RESOLVER.get_or_init(|| {
        let cache: Cache<LookupIpStrategyExt, Arc<TrustDnsResolver>> =
            Cache::builder().max_capacity(5).build();
        cache
    });
    // init dns resolver cache
    cache.get_with(LookupIpStrategyExt::from_strategy(ip_strategy), || {
        Arc::new(dns::TrustDnsResolver::new(ip_strategy))
    })
}

const IMPERSONATE_UAS: [Impersonate; 21] = [
    Impersonate::OkHttp3_9,
    Impersonate::OkHttp3_11,
    Impersonate::OkHttp3_13,
    Impersonate::OkHttp3_14,
    Impersonate::OkHttp4_9,
    Impersonate::OkHttp4_10,
    Impersonate::OkHttp5,
    Impersonate::Chrome99,
    Impersonate::Chrome104,
    Impersonate::Chrome105,
    Impersonate::Chrome106,
    Impersonate::Chrome107,
    Impersonate::Chrome108,
    Impersonate::Chrome109,
    Impersonate::Chrome114,
    Impersonate::Chrome116,
    Impersonate::Chrome118,
    Impersonate::Chrome119,
    Impersonate::Safari12,
    Impersonate::Safari15_3,
    Impersonate::Safari15_5,
];

/// Randomly select a user agent from a list of known user agents.
fn random_impersonate(impersonate_uas: Option<&Vec<Impersonate>>) -> Impersonate {
    use rand::seq::IteratorRandom;

    let mut rng = rand::thread_rng();
    // if user has specified a list of user agents, randomly select one from the list
    if let Some(impersonate_uas) = impersonate_uas {
        if !impersonate_uas.is_empty() {
            return impersonate_uas
                .iter()
                .choose(&mut rng)
                .unwrap_or(&Impersonate::OkHttp4_9)
                .clone();
        }
    }

    // otherwise, randomly select one from the default list
    IMPERSONATE_UAS
        .iter()
        .choose(&mut rng)
        .unwrap_or(&Impersonate::Chrome119)
        .clone()
}
