use anyhow::Context;
use std::path::PathBuf;
use std::str::FromStr;

const PORT_RANGE: std::ops::RangeInclusive<usize> = 1024..=65535;

// port range parse
pub fn parse_port_in_range(s: &str) -> anyhow::Result<u16> {
    let port: usize = s
        .parse()
        .map_err(|_| anyhow::anyhow!(format!("`{}` isn't a port number", s)))?;
    if PORT_RANGE.contains(&port) {
        return Ok(port as u16);
    }
    anyhow::bail!(format!(
        "Port not in range {}-{}",
        PORT_RANGE.start(),
        PORT_RANGE.end()
    ))
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

// file path parse
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

// parse account，support split: ':', '-', '--', '---'....
pub fn parse_puid_user(s: &str) -> anyhow::Result<(String, String, Option<String>)> {
    #[inline]
    fn handle_parts(mut parts: Vec<String>) -> anyhow::Result<(String, String, Option<String>)> {
        parts.reverse();
        match parts.len() {
            2 => Ok((parts.pop().unwrap(), parts.pop().unwrap(), None)),
            3 => Ok((parts.pop().unwrap(), parts.pop().unwrap(), parts.pop())),
            _ => anyhow::bail!("Input format is invalid!"),
        }
    }

    if s.contains(':') {
        let parts = s
            .split(':')
            .map(|part| part.to_string())
            .collect::<Vec<_>>();
        return handle_parts(parts);
    }

    match find_single_consecutive_dashes(s, '-') {
        Ok(targets) => {
            let parts = s
                .split(&targets)
                .map(|part| part.to_string())
                .collect::<Vec<_>>();
            handle_parts(parts)
        }
        Err(_) => anyhow::bail!("Input format is invalid!"),
    }
}

fn find_single_consecutive_dashes(s: &str, target: char) -> Result<String, &'static str> {
    let mut count = 0;
    let mut dashes = String::new();
    let mut found = None;

    for c in s.chars() {
        if c == target {
            count += 1;
            dashes.push(target);
        } else {
            if count > 0 {
                if found.is_some() {
                    return Err("Found more than one group of consecutive dashes");
                }
                found = Some(dashes.clone());
            }
            count = 0;
            dashes.clear();
        }
    }

    // Check at the end, in case the string ends with consecutive
    if count > 0 {
        if found.is_some() {
            return Err("Found more than one group of consecutive dashes");
        }
        found = Some(dashes);
    }

    found.ok_or("No consecutive dashes found")
}
