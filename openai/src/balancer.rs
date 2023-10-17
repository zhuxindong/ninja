use rand::Rng;
use reqwest::{impersonate::Impersonate, Client};
use std::{
    net::IpAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use crate::{auth, info, HEADER_UA};
use crate::{auth::AuthClient, context};

#[derive(Clone)]
pub enum ClientType {
    Auth(AuthClient),
    Regular(Client),
}

impl Into<AuthClient> for ClientType {
    fn into(self) -> AuthClient {
        match self {
            ClientType::Auth(client) => client,
            _ => panic!("Attempted to convert a non-Auth client into AuthClient"),
        }
    }
}

impl Into<Client> for ClientType {
    fn into(self) -> Client {
        match self {
            ClientType::Regular(client) => client,
            _ => panic!("Attempted to convert a non-Regular client into Client"),
        }
    }
}

struct Ipv6Subnet {
    pub ipv6: u128,
    pub prefix_len: u8,
}

impl Ipv6Subnet {
    fn get_random_ipv6(&self) -> IpAddr {
        let rand: u128 = rand::thread_rng().gen();
        let net_part = (self.ipv6 >> (128 - self.prefix_len)) << (128 - self.prefix_len);
        let host_part = (rand << self.prefix_len) >> self.prefix_len;
        IpAddr::V6((net_part | host_part).into())
    }
}

struct Inner {
    disable_direct: bool,
    cookie_store: bool,
    timeout: Duration,
    connect_timeout: Duration,
    pool_idle_timeout: Duration,
    tcp_keepalive: Option<Duration>,
    preauth_api: Option<String>,
    proxies: Vec<String>,
    ipv6_subnet: Option<Ipv6Subnet>,
}

impl From<&context::ContextArgs> for Inner {
    fn from(args: &context::ContextArgs) -> Self {
        let ipv6_subnet = args.ipv6_subnet.map(|(ipv6, prefix_len)| Ipv6Subnet {
            ipv6: ipv6.into(),
            prefix_len,
        });

        Inner {
            disable_direct: args.disable_direct,
            cookie_store: args.cookie_store,
            timeout: Duration::from_secs(args.timeout as u64),
            connect_timeout: Duration::from_secs(args.connect_timeout as u64),
            tcp_keepalive: Some(Duration::from_secs(args.tcp_keepalive as u64)),
            pool_idle_timeout: Duration::from_secs(args.pool_idle_timeout as u64),
            preauth_api: args.preauth_api.clone(),
            proxies: args.proxies.clone(),
            ipv6_subnet,
        }
    }
}

pub struct ClientLoadBalancer {
    clients: Vec<ClientType>,
    index: AtomicUsize,
    inner: Inner,
}

impl ClientLoadBalancer {
    fn new_client_generic<F, T>(
        args: &context::ContextArgs,
        client_type: fn(T) -> ClientType,
        build_fn: F,
    ) -> anyhow::Result<Self>
    where
        F: Fn(&Inner, Option<IpAddr>, Option<&String>) -> T,
    {
        let inner = Inner::from(args);
        let mut clients = Vec::with_capacity(inner.proxies.len() + 1);

        let mut add_client = |proxy: Option<&String>| {
            let client = build_fn(&inner, args.interface, proxy);
            clients.push(client_type(client));
        };

        if inner.proxies.is_empty() || inner.ipv6_subnet.is_some() {
            add_client(None);
        } else {
            if !inner.disable_direct {
                add_client(None);
            }
            for proxy in &inner.proxies {
                add_client(Some(proxy));
            }
        }

        Ok(Self {
            clients,
            index: AtomicUsize::new(0),
            inner,
        })
    }

    pub fn new_auth_client(args: &context::ContextArgs) -> anyhow::Result<Self> {
        Self::new_client_generic(args, ClientType::Auth, build_auth_client)
    }

    pub fn new_client(args: &context::ContextArgs) -> anyhow::Result<Self> {
        Self::new_client_generic(args, ClientType::Regular, build_client)
    }
}

impl ClientLoadBalancer {
    fn rebuild_client_with_ipv6(&self, client: &ClientType) -> ClientType {
        let bind_addr = self.inner.ipv6_subnet.as_ref().unwrap().get_random_ipv6();
        match client {
            ClientType::Auth(_) => {
                ClientType::Auth(build_auth_client(&self.inner, Some(bind_addr), None))
            }
            ClientType::Regular(_) => {
                ClientType::Regular(build_client(&self.inner, Some(bind_addr), None))
            }
        }
    }

    pub fn next(&self) -> ClientType {
        match self.clients.len() {
            1 => {
                let client = self.clients.first().expect("Init client failed");
                if self.inner.ipv6_subnet.is_some() {
                    return self.rebuild_client_with_ipv6(client);
                }
                client.clone()
            }
            _ => {
                let len = self.clients.len();
                let mut old = self.index.load(Ordering::Relaxed);
                let mut new;
                loop {
                    new = (old + 1) % len;
                    match self.index.compare_exchange_weak(
                        old,
                        new,
                        Ordering::SeqCst,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(x) => old = x,
                    }
                }
                self.clients[old].clone()
            }
        }
    }
}

fn build_client(inner: &Inner, bind_addr: Option<IpAddr>, proxy_url: Option<&String>) -> Client {
    let mut client_builder = Client::builder();
    if let Some(url) = proxy_url {
        info!("[Client] Add proxy: {url}");
        let proxy = reqwest::Proxy::all(url).expect("Failed to build proxy");
        client_builder = client_builder.proxy(proxy)
    }

    if inner.cookie_store {
        client_builder = client_builder.cookie_store(true);
    }

    // api client
    let client = client_builder
        .user_agent(HEADER_UA)
        .impersonate(Impersonate::OkHttpAndroid13)
        .tcp_keepalive(inner.tcp_keepalive.clone())
        .pool_idle_timeout(inner.pool_idle_timeout.clone())
        .timeout(inner.timeout.clone())
        .connect_timeout(inner.connect_timeout.clone())
        .local_address(bind_addr)
        .build()
        .expect("Failed to build API client");
    client
}

fn build_auth_client(
    inner: &Inner,
    bind_addr: Option<IpAddr>,
    proxy_url: Option<&String>,
) -> AuthClient {
    proxy_url.map(|url| info!("[AuthClient] Add proxy: {url}"));
    auth::AuthClientBuilder::builder()
        .user_agent(HEADER_UA)
        .impersonate(Impersonate::OkHttpAndroid13)
        .tcp_keepalive(inner.tcp_keepalive.clone())
        .pool_idle_timeout(inner.pool_idle_timeout.clone())
        .timeout(inner.timeout.clone())
        .connect_timeout(inner.connect_timeout.clone())
        .proxy(proxy_url.cloned())
        .local_address(bind_addr)
        .preauth_api(inner.preauth_api.clone())
        .build()
}
