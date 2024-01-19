use anyhow::{format_err, Error};
use cidr::Ipv6Cidr;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use url::Url;

/// RandomIpv6 trait
pub trait Ipv6CidrExt {
    fn random_ipv6(&self) -> IpAddr;
}

impl Ipv6CidrExt for Ipv6Cidr {
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
    /// Upstream proxy, supports http, https, socks5
    Proxy(Url),
    /// Bind to interface, supports ipv4, ipv6
    Interface(IpAddr),
    /// Bind to ipv6 subnet, ramdomly generate ipv6 address
    IPv6Subnet(Ipv6Cidr),
}

/// Proxy configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proxy {
    All(InnerProxy),
    Api(InnerProxy),
    Auth(InnerProxy),
    Arkose(InnerProxy),
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
            "http" | "https" | "socks5" | "socks5h" => {
                let inner_proxy = InnerProxy::Proxy(url);
                make_proxy(inner_proxy, proto)
            }
            _ => Err(unsupported_protocol(url.scheme())),
        }
    }
}

impl TryFrom<(&str, &str)> for Proxy {
    type Error = anyhow::Error;

    fn try_from((proto, url): (&str, &str)) -> Result<Self, Error> {
        let url = Url::parse(url)?;
        Self::try_from((proto, url))
    }
}

impl TryFrom<(&str, cidr::Ipv6Cidr)> for Proxy {
    type Error = anyhow::Error;

    fn try_from((proto, cidr): (&str, cidr::Ipv6Cidr)) -> Result<Self, Error> {
        let inner_proxy = InnerProxy::IPv6Subnet(cidr);
        make_proxy(inner_proxy, proto)
    }
}
