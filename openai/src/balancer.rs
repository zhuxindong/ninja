use reqwest::{impersonate::Impersonate, Client};
use std::{
    net::IpAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use crate::{auth, info, HEADER_UA};
use crate::{auth::AuthClient, context};

struct Inner {
    disable_direct: bool,
    cookie_store: bool,
    timeout: Duration,
    connect_timeout: Duration,
    pool_idle_timeout: Duration,
    tcp_keepalive: Option<Duration>,
    preauth_api: Option<String>,
    proxies: Vec<String>,
}

impl From<&context::ContextArgs> for Inner {
    fn from(args: &context::ContextArgs) -> Self {
        Inner {
            disable_direct: args.disable_direct,
            cookie_store: args.cookie_store,
            timeout: Duration::from_secs(args.timeout as u64),
            connect_timeout: Duration::from_secs(args.connect_timeout as u64),
            tcp_keepalive: Some(Duration::from_secs(args.tcp_keepalive as u64)),
            pool_idle_timeout: Duration::from_secs(args.pool_idle_timeout as u64),
            preauth_api: args.preauth_api.clone(),
            proxies: args.proxies.clone(),
        }
    }
}

pub struct ClientLoadBalancer<T: Clone> {
    clients: Vec<T>,
    index: AtomicUsize,
}

impl<T: Clone> ClientLoadBalancer<T> {
    pub fn new_auth_client(
        args: &context::ContextArgs,
    ) -> anyhow::Result<ClientLoadBalancer<AuthClient>> {
        let inner = Inner::from(args);

        Ok(ClientLoadBalancer {
            clients: build_auth_client(&inner, args.interface),
            index: AtomicUsize::new(0),
        })
    }

    pub fn new_client(args: &context::ContextArgs) -> anyhow::Result<ClientLoadBalancer<Client>> {
        let inner = Inner::from(args);
        let load = ClientLoadBalancer {
            clients: build_client(&inner, args.interface),
            index: AtomicUsize::new(0),
        };
        Ok(load)
    }

    pub fn next(&self) -> T {
        if self.clients.len() == 1 {
            return self.clients.first().cloned().expect("Init client failed");
        }
        let len = self.clients.len();
        let mut old = self.index.load(Ordering::Relaxed);
        let mut new;
        loop {
            new = (old + 1) % len;
            match self
                .index
                .compare_exchange_weak(old, new, Ordering::SeqCst, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(x) => old = x,
            }
        }
        self.clients[old].clone()
    }
}

fn build_client(inner: &Inner, bind_addr: Option<IpAddr>) -> Vec<Client> {
    let build = |proxy_url: Option<String>| -> reqwest::Client {
        let mut client_builder = reqwest::Client::builder();
        if let Some(url) = proxy_url {
            info!("[Client] Add {url} to proxy");
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
    };

    let mut clients = Vec::new();

    if inner.proxies.is_empty() {
        clients.push(build(None));
    } else {
        if !inner.disable_direct {
            clients.push(build(None));
        }
        for proxy in inner.proxies.clone() {
            clients.push(build(Some(proxy)));
        }
    }
    clients
}

fn build_auth_client(inner: &Inner, bind_addr: Option<IpAddr>) -> Vec<AuthClient> {
    let build = |proxy_url: Option<String>| -> AuthClient {
        if proxy_url.is_some() {
            info!(
                "[AuthClient] Add {url} to proxy",
                url = proxy_url.as_ref().unwrap()
            );
        }
        auth::AuthClientBuilder::builder()
            .user_agent(HEADER_UA)
            .impersonate(Impersonate::OkHttpAndroid13)
            .tcp_keepalive(inner.tcp_keepalive.clone())
            .pool_idle_timeout(inner.pool_idle_timeout.clone())
            .timeout(inner.timeout.clone())
            .connect_timeout(inner.connect_timeout.clone())
            .proxy(proxy_url)
            .local_address(bind_addr)
            .preauth_api(inner.preauth_api.clone())
            .build()
    };

    let mut clients = Vec::new();
    if inner.proxies.is_empty() {
        clients.push(build(None));
    } else {
        if !inner.disable_direct {
            clients.push(build(None));
        }
        for proxy in inner.proxies.clone() {
            clients.push(build(Some(proxy)));
        }
    }

    clients
}
