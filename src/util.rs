use anyhow::Context;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use std::sync::{Arc, RwLock};
use std::thread;

pub struct ProgressBar<'a> {
    message: &'a str,
    active: Arc<RwLock<bool>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl ProgressBar<'_> {
    pub fn new<'a>(msg: &'a str) -> ProgressBar<'_> {
        ProgressBar {
            active: Arc::new(RwLock::new(false)),
            message: msg,
            join: None,
        }
    }

    pub fn start(&mut self) {
        let mut write = self.active.write().unwrap();
        if *write {
            return;
        }

        *write = true;

        let active_clone = self.active.clone();
        let msg = self.message.to_owned();
        self.join = Some(tokio::spawn(async move {
            let progress_chars = &["▹▹▹▹▹", "▸▹▹▹▹", "▹▸▹▹▹", "▹▹▸▹▹", "▹▹▹▸▹", "▹▹▹▹▸"];
            let mut out = tokio::io::stdout();
            loop {
                if *active_clone.read().unwrap() {
                    for chars in progress_chars {
                        out.write_all(format!("\r\x1B[34m{chars}\x1B[0m {msg}").as_bytes())
                            .await
                            .unwrap();
                        out.flush().await.unwrap();
                        if *active_clone.read().unwrap() {
                            thread::sleep(Duration::from_millis(100));
                        } else {
                            return;
                        }
                    }
                } else {
                    break;
                }
            }
        }));
    }

    pub async fn finish_and_clear(&self) {
        let mut write = self.active.write().unwrap();
        *write = false;
        if let Some(join) = &self.join {
            join.abort();
            print!("\r\x1B[K");
        }
    }
}

pub async fn print_stream(
    out: &mut tokio::io::Stdout,
    previous_message: String,
    message: String,
) -> anyhow::Result<String> {
    if message.starts_with(&*previous_message) {
        let new_chars: String = message.chars().skip(previous_message.len()).collect();
        out.write_all(new_chars.as_bytes()).await?;
    } else {
        out.write_all(message.as_bytes()).await?;
    }
    out.flush().await?;
    Ok(message)
}

pub fn long_spinner_progress_bar<'a>(message: &'a str) -> ProgressBar<'a> {
    ProgressBar::new(message)
}

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
        "http" | "https" | "socks5" | "redis" => Ok(s.to_string()),
        _ => anyhow::bail!("Unsupported protocol: {}", protocol),
    }
}

// proxy proto
pub fn parse_proxies_url(s: &str) -> anyhow::Result<Vec<String>> {
    let split = s.split(",");
    let mut proxies: Vec<_> = vec![];
    for ele in split {
        let url = url::Url::parse(ele)
            .context("The Proxy Url format must be `protocol://user:pass@ip:port`")?;
        let protocol = url.scheme().to_string();
        match protocol.as_str() {
            "http" | "https" | "socks5" | "redis" => proxies.push(ele.to_string()),
            _ => anyhow::bail!("Unsupported protocol: {}", protocol),
        };
    }
    Ok(proxies)
}

// config path parse
pub fn parse_config(s: &str) -> anyhow::Result<PathBuf> {
    let path =
        PathBuf::from_str(s).map_err(|_| anyhow::anyhow!(format!("`{}` isn't a path", s)))?;
    match path.exists() {
        true => Ok(path),
        false => {
            if let Some(parent) = path.parent() {
                parent.exists().then(|| ()).ok_or_else(|| {
                    anyhow::anyhow!(format!("Path {} not exists", parent.display()))
                })?;
            }
            Ok(path)
        }
    }
}

pub fn parse_puid_user(s: &str) -> anyhow::Result<(String, String, Option<String>)> {
    let parts: Vec<&str> = s.split(':').collect();

    match parts.len() {
        2 => Ok((parts[0].to_string(), parts[1].to_string(), None)),
        3 => Ok((
            parts[0].to_string(),
            parts[1].to_string(),
            Some(parts[2].to_string()),
        )),
        _ => anyhow::bail!("Input format is invalid!"),
    }
}
