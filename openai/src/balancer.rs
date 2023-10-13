use reqwest::{impersonate::Impersonate, Client};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use crate::{auth, info, HEADER_UA};
use crate::{auth::AuthClient, context};

pub struct ClientLoadBalancer<T: Clone> {
    clients: Vec<T>,
    index: AtomicUsize,
}

impl<T: Clone> ClientLoadBalancer<T> {
    pub(super) fn new_auth_client(
        args: &context::ContextArgs,
    ) -> anyhow::Result<ClientLoadBalancer<AuthClient>> {
        let build = |proxy_url: Option<String>| -> AuthClient {
            if let Some(ref url) = proxy_url {
                info!("[AuthClient] Add {url} to proxy pool");
            }
            // auth client
            let auth_client = auth::AuthClientBuilder::builder()
                .user_agent(HEADER_UA)
                .impersonate(Impersonate::OkHttpAndroid13)
                .tcp_keepalive(Some(Duration::from_secs((args.tcp_keepalive + 1) as u64)))
                .pool_idle_timeout(Duration::from_secs((args.pool_idle_timeout + 1) as u64))
                .timeout(Duration::from_secs((args.timeout + 1) as u64))
                .connect_timeout(Duration::from_secs((args.connect_timeout + 1) as u64))
                .proxy(proxy_url)
                .preauth_api(args.preauth_api.clone())
                .build();
            auth_client
        };

        let mut clients = Vec::new();

        if args.proxies.is_empty() {
            clients.push(build(None));
        } else {
            if !args.disable_direct {
                clients.push(build(None));
            }
            for proxy in args.proxies.clone() {
                clients.push(build(Some(proxy)));
            }
        }

        Ok(ClientLoadBalancer {
            clients,
            index: AtomicUsize::new(0),
        })
    }

    pub(super) fn new_client(
        args: &context::ContextArgs,
    ) -> anyhow::Result<ClientLoadBalancer<Client>> {
        let build = |proxy_url: Option<String>| -> reqwest::Client {
            let mut client_builder = reqwest::Client::builder();
            if let Some(url) = proxy_url {
                info!("[Client] Add {url} to proxy pool");
                let proxy = reqwest::Proxy::all(url).expect("Failed to build proxy");
                client_builder = client_builder.proxy(proxy)
            }

            if args.cookie_store {
                client_builder = client_builder.cookie_store(true);
            }

            // api client
            let client = client_builder
                .user_agent(HEADER_UA)
                .impersonate(Impersonate::OkHttpAndroid13)
                .tcp_keepalive(Some(Duration::from_secs((args.tcp_keepalive + 1) as u64)))
                .pool_idle_timeout(Duration::from_secs((args.pool_idle_timeout + 1) as u64))
                .timeout(Duration::from_secs((args.timeout + 1) as u64))
                .connect_timeout(Duration::from_secs((args.connect_timeout + 1) as u64))
                .build()
                .expect("Failed to build API client");
            client
        };

        let mut clients = Vec::new();

        if args.proxies.is_empty() {
            clients.push(build(None));
        } else {
            if !args.disable_direct {
                clients.push(build(None));
            }
            for proxy in args.proxies.clone() {
                clients.push(build(Some(proxy)));
            }
        }
        let load = ClientLoadBalancer {
            clients,
            index: AtomicUsize::new(0),
        };
        Ok(load)
    }

    pub(super) fn next(&self) -> T {
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
