//! DNS resolution via the [trust_dns_resolver](https://github.com/bluejekyll/trust-dns) crate
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
}

impl TrustDnsResolver {
    /// Create a new `TrustDnsResolver` with the default configuration,
    /// which reads from `/etc/resolve.conf`.
    pub(crate) fn new(ip_strategy: LookupIpStrategy) -> Self {
        Self {
            state: Arc::new(OnceCell::new()),
            ip_strategy,
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
                .get_or_try_init(|| async { new_resolver(resolver.ip_strategy) })
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
fn new_resolver(ip_strategy: LookupIpStrategy) -> io::Result<TokioAsyncResolver> {
    let (mut config, mut opts) = system_conf::read_system_conf().map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("error reading DNS system conf: {}", e),
        )
    })?;

    opts.use_hosts_file = true;
    opts.ip_strategy = ip_strategy;

    // Google DNS Server
    let google_group = NameServerConfigGroup::google();
    for ns in google_group.into_inner() {
        config.add_name_server(ns)
    }

    // CloudFlare DNS Server
    let cf_group = NameServerConfigGroup::cloudflare();
    for ns in cf_group.into_inner() {
        config.add_name_server(ns);
    }

    Ok(TokioAsyncResolver::tokio(config, opts))
}
