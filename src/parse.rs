use anyhow::Context;
use std::path::PathBuf;
use std::str::FromStr;

// parse socket address
pub fn parse_socket_addr(s: &str) -> anyhow::Result<std::net::SocketAddr> {
    let addr = s
        .parse::<std::net::SocketAddr>()
        .map_err(|_| anyhow::anyhow!(format!("`{}` isn't a socket address", s)))?;
    Ok(addr)
}

// address parse
pub fn parse_host(s: &str) -> anyhow::Result<std::net::IpAddr> {
    let addr = s
        .parse::<std::net::IpAddr>()
        .map_err(|_| anyhow::anyhow!(format!("`{}` isn't a ip address", s)))?;
    Ok(addr)
}

// url parse
pub fn parse_url(s: &str) -> anyhow::Result<String> {
    let url = url::Url::parse(s)
        .context("The Proxy Url format must be `protocol://user:pass@ip:port`")?;
    let protocol = url.scheme().to_string();
    match protocol.as_str() {
        "http" | "https" | "socks5" | "redis" | "rediss" => Ok(s.to_string()),
        _ => anyhow::bail!("Unsupported protocol: {}", protocol),
    }
}

pub fn parse_ipv6_subnet(s: &str) -> anyhow::Result<(std::net::Ipv6Addr, u8)> {
    match s.parse::<cidr::Ipv6Cidr>() {
        Ok(cidr) => Ok((cidr.first_address(), cidr.network_length())),
        Err(_) => {
            anyhow::bail!(format!("`{}` isn't a ipv6 subnet", s))
        }
    }
}

// proxy proto
pub fn parse_proxies_url(s: &str) -> anyhow::Result<Vec<String>> {
    let split = s.split(',');
    let mut proxies: Vec<_> = vec![];
    for ele in split {
        let url = url::Url::parse(ele)
            .context("The Proxy Url format must be `protocol://user:pass@ip:port`")?;
        let protocol = url.scheme().to_string();
        match protocol.as_str() {
            "http" | "https" | "socks5" | "redis" | "rediss" => proxies.push(ele.to_string()),
            _ => anyhow::bail!("Unsupported protocol: {}", protocol),
        };
    }
    Ok(proxies)
}

/// parse file path
pub fn parse_file_path(s: &str) -> anyhow::Result<PathBuf> {
    let path =
        PathBuf::from_str(s).map_err(|_| anyhow::anyhow!(format!("`{}` isn't a path", s)))?;

    if !path.exists() {
        anyhow::bail!(format!("Path {} not exists", path.display()))
    }

    if !path.is_file() {
        anyhow::bail!(format!("{} not a file", path.display()))
    }

    Ok(path)
}

// parse directory path
pub fn parse_dir_path(s: &str) -> anyhow::Result<PathBuf> {
    let path =
        PathBuf::from_str(s).map_err(|_| anyhow::anyhow!(format!("`{}` isn't a path", s)))?;

    if !path.exists() {
        anyhow::bail!(format!("Path {} not exists", path.display()))
    }

    if !path.is_dir() {
        anyhow::bail!(format!("{} not a directory", path.display()))
    }

    Ok(path)
}
