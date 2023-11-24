use anyhow::{format_err, Error};
use cidr::Ipv6Cidr;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use url::Url;

pub trait RandomIpv6 {
    fn random_ipv6(&self) -> IpAddr;
}

impl RandomIpv6 for cidr::Ipv6Cidr {
    fn random_ipv6(&self) -> IpAddr {
        let ipv6: u128 = self.first_address().into();
        let prefix_len = self.network_length();
        let rand: u128 = rand::thread_rng().gen();
        let net_part = (ipv6 >> (128 - prefix_len)) << (128 - prefix_len);
        let host_part = (rand << prefix_len) >> prefix_len;
        IpAddr::V6((net_part | host_part).into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InnerProxy {
    Interface(IpAddr),
    Proxy(Url),
    IPv6Subnet(Ipv6Cidr),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proxy {
    All(InnerProxy),
    Api(InnerProxy),
    Auth(InnerProxy),
    Arkose(InnerProxy),
}

const UNSUPPORTED_PROTOCOL: &str = "Unsupported protocol";

fn unsupported_protocol(proto: &str) -> Error {
    format_err!("{}: {}", UNSUPPORTED_PROTOCOL, proto)
}

fn make_proxy(inner_proxy: InnerProxy, proto: &str) -> Result<Proxy, Error> {
    match proto {
        "all" => Ok(Proxy::All(inner_proxy)),
        "api" => Ok(Proxy::Api(inner_proxy)),
        "auth" => Ok(Proxy::Auth(inner_proxy)),
        "arkose" => Ok(Proxy::Arkose(inner_proxy)),
        _ => Err(unsupported_protocol(proto)),
    }
}

impl TryFrom<(&str, IpAddr)> for Proxy {
    type Error = anyhow::Error;

    fn try_from((proto, ip_addr): (&str, IpAddr)) -> Result<Self, Error> {
        let inner_proxy = InnerProxy::Interface(ip_addr);
        make_proxy(inner_proxy, proto)
    }
}

impl TryFrom<(&str, Url)> for Proxy {
    type Error = anyhow::Error;

    fn try_from((proto, url): (&str, Url)) -> Result<Self, Error> {
        match url.scheme() {
            "http" | "https" | "socks5" => {
                let inner_proxy = InnerProxy::Proxy(url);
                make_proxy(inner_proxy, proto)
            }
            _ => Err(unsupported_protocol(url.scheme())),
        }
    }
}

impl TryFrom<(&str, cidr::Ipv6Cidr)> for Proxy {
    type Error = anyhow::Error;

    fn try_from((proto, cidr): (&str, cidr::Ipv6Cidr)) -> Result<Self, Error> {
        let inner_proxy = InnerProxy::IPv6Subnet(cidr);
        make_proxy(inner_proxy, proto)
    }
}

impl Proxy {
    pub fn proto(&self) -> &'static str {
        match self {
            Proxy::All(_) => "All",
            Proxy::Api(_) => "Api",
            Proxy::Auth(_) => "Auth",
            Proxy::Arkose(_) => "Arkose",
        }
    }
}
