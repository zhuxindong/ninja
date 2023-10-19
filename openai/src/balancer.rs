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
    timeout: u64,
    connect_timeout: u64,
    pool_idle_timeout: u64,
    tcp_keepalive: u64,
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
            timeout: args.timeout as u64,
            connect_timeout: args.connect_timeout as u64,
            tcp_keepalive: args.tcp_keepalive as u64,
            pool_idle_timeout: args.pool_idle_timeout as u64,
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
        F: Fn(&Inner, Option<IpAddr>, Option<&String>, bool) -> T,
    {
        let inner = Inner::from(args);
        let mut clients = Vec::with_capacity(inner.proxies.len() + 1);

        let mut add_client = |proxy: Option<&String>| {
            let client = build_fn(&inner, args.interface, proxy, false);
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
                ClientType::Auth(build_auth_client(&self.inner, Some(bind_addr), None, true))
            }
            ClientType::Regular(_) => {
                ClientType::Regular(build_client(&self.inner, Some(bind_addr), None, true))
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

fn build_client(
    inner: &Inner,
    bind_addr: Option<IpAddr>,
    proxy_url: Option<&String>,
    disable_keep_alive: bool,
) -> Client {
    let mut builder = Client::builder();
    if let Some(url) = proxy_url {
        info!("[Client] Add proxy: {url}");
        let proxy = reqwest::Proxy::all(url).expect("Failed to build proxy");
        builder = builder.proxy(proxy)
    }

    if inner.cookie_store {
        builder = builder.cookie_store(true);
    }

    if disable_keep_alive {
        builder = builder.tcp_keepalive(None);
    } else {
        builder = builder
            .tcp_keepalive(Duration::from_secs(inner.tcp_keepalive))
            .pool_idle_timeout(Duration::from_secs(inner.pool_idle_timeout));
    }

    let client = builder
        .user_agent(HEADER_UA)
        .impersonate(Impersonate::OkHttpAndroid13)
        .connect_timeout(Duration::from_secs(inner.connect_timeout))
        .timeout(Duration::from_secs(inner.timeout))
        .local_address(bind_addr)
        .build()
        .expect("Failed to build API client");
    client
}

fn build_auth_client(
    inner: &Inner,
    bind_addr: Option<IpAddr>,
    proxy_url: Option<&String>,
    disable_keep_alive: bool,
) -> AuthClient {
    proxy_url.map(|url| info!("[AuthClient] Add proxy: {url}"));

    let mut builder = auth::AuthClientBuilder::builder();

    if disable_keep_alive {
        builder = builder.tcp_keepalive(None);
    } else {
        builder = builder
            .tcp_keepalive(Duration::from_secs(inner.tcp_keepalive))
            .pool_idle_timeout(Duration::from_secs(inner.pool_idle_timeout));
    }

    builder
        .user_agent(HEADER_UA)
        .impersonate(Impersonate::OkHttpAndroid13)
        .timeout(Duration::from_secs(inner.timeout))
        .connect_timeout(Duration::from_secs(inner.connect_timeout))
        .proxy(proxy_url.cloned())
        .local_address(bind_addr)
        .preauth_api(inner.preauth_api.clone())
        .build()
}
