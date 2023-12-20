//! DNS resolution via the [trust_dns_resolver](https://github.com/bluejekyll/trust-dns) crate
pub mod fast;

use hyper::client::connect::dns::Name;
use reqwest::dns::{Addrs, Resolve, Resolving};
use tokio::sync::OnceCell;
use trust_dns_resolver::config::{LookupIpStrategy, NameServerConfigGroup};
pub use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::{lookup_ip::LookupIpIntoIter, system_conf, TokioAsyncResolver};

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

/// Wrapper around an `AsyncResolver`, which implements the `Resolve` trait.
#[derive(Debug, Clone)]
pub(crate) struct TrustDnsResolver {
    /// Since we might not have been called in the context of a
    /// Tokio Runtime in initialization, so we must delay the actual
    /// construction of the resolver.
    state: Arc<OnceCell<TokioAsyncResolver>>,
    /// The DNS strategy to use when resolving addresses.
    ip_strategy: LookupIpStrategy,
    /// Use fastest DNS resolver
    fastest_dns: bool,
}

impl TrustDnsResolver {
    /// Create a new `TrustDnsResolver` with the default configuration,
    /// which reads from `/etc/resolve.conf`.
    pub(crate) fn new(ip_strategy: LookupIpStrategy, fastest_dns: bool) -> Self {
        Self {
            state: Arc::new(OnceCell::new()),
            ip_strategy,
            fastest_dns,
        }
    }
}

struct SocketAddrs {
    iter: LookupIpIntoIter,
}

impl Resolve for TrustDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();
        Box::pin(async move {
            let resolver = resolver
                .state
                .get_or_try_init(|| async {
                    new_resolver(resolver.ip_strategy, resolver.fastest_dns)
                })
                .await?;
            let lookup = resolver.lookup_ip(name.as_str()).await?;
            let addrs: Addrs = Box::new(SocketAddrs {
                iter: lookup.into_iter(),
            });
            Ok(addrs)
        })
    }
}

impl Iterator for SocketAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|ip_addr| SocketAddr::new(ip_addr, 0))
    }
}

/// Create a new resolver with the default configuration,
/// which reads from `/etc/resolve.conf`.
fn new_resolver(
    ip_strategy: LookupIpStrategy,
    fastest_dns: bool,
) -> io::Result<TokioAsyncResolver> {
    // If we can't read the system conf, just use the defaults.
    let (mut config, mut opts) = match system_conf::read_system_conf() {
        Ok((config, opts)) => (config, opts),
        Err(err) => {
            tracing::warn!("Error reading DNS system conf: {}", err);
            // Use Google DNS, Cloudflare DNS and Quad9 DNS
            let mut group = NameServerConfigGroup::new();

            // Google DNS
            group.extend(NameServerConfigGroup::google().into_inner());

            // Cloudflare DNS
            group.extend(NameServerConfigGroup::cloudflare().into_inner());

            // Quad9 DNS
            group.extend(NameServerConfigGroup::quad9().into_inner());

            let config = ResolverConfig::from_parts(None, vec![], group);
            (config, ResolverOpts::default())
        }
    };

    // Use built-in fastest DNS group
    if fastest_dns {
        config = fast::FASTEST_DNS_CONFIG
            .get()
            .cloned()
            .unwrap_or_else(|| config)
    }

    // Check /ect/hosts file before dns requery (only works for unix like OS)
    opts.use_hosts_file = true;
    // The ip_strategy for the Resolver to use when lookup Ipv4 or Ipv6 addresses
    opts.ip_strategy = ip_strategy;

    Ok(TokioAsyncResolver::tokio(config, opts))
}
