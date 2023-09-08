use crate::arkose::crypto;
use serde::Deserialize;
use std::{path::Path, sync::Mutex};

static LOCK: Mutex<()> = Mutex::new(());
static mut CACHE_REQUEST_ENTRY: Option<RequestEntry> = None;

#[derive(Clone)]
pub struct RequestEntry {
    pub url: String,
    pub method: String,
    pub headers: Vec<Header>,
    pub body: String,
    pub bx: String,
    pub bv: String,
}

fn parse(har: Har) -> anyhow::Result<RequestEntry> {
    if let Some(entry) = har
        .log
        .entries
        .into_iter()
        .find(|e| e.request.url.contains("fc/gt2/public_key"))
    {
        if entry.started_date_time.is_empty() {
            anyhow::bail!("Invalid HAR file");
        }

        let bt = chrono::DateTime::parse_from_rfc3339(&entry.started_date_time)?.timestamp();
        let bw = bt - (bt % 21600);
        let mut bv = String::new();

        if let Some(data) = entry.request.post_data {
            let headers = entry.request.headers;

            if let Some(h) = headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("user-agent"))
            {
                bv.push_str(&h.value);
            }

            if let Some(bda_param) = data
                .params
                .iter()
                .find(|p| p.name.eq_ignore_ascii_case("bda"))
            {
                #[allow(deprecated)]
                let entry = RequestEntry {
                    url: entry.request.url,
                    method: entry.request.method,
                    headers: headers
                        .into_iter()
                        .filter(|h| {
                            let name = &h.name;
                            !name.starts_with(":")
                                && !name.eq_ignore_ascii_case("content-length")
                                && !name.eq_ignore_ascii_case("connection")
                        })
                        .collect::<Vec<Header>>(),
                    body: data
                        .text
                        .split("&")
                        .into_iter()
                        .filter(|s| !s.contains("bda") && !s.contains("rnd"))
                        .collect::<Vec<&str>>()
                        .join("&"),
                    bx: crypto::decrypt(base64::decode(&bda_param.value)?, &format!("{bv}{bw}"))?,
                    bv,
                };

                let lock = LOCK.lock().unwrap();
                unsafe {
                    CACHE_REQUEST_ENTRY = Some(entry);
                    drop(lock);
                    return Ok(CACHE_REQUEST_ENTRY.clone().unwrap());
                }
            }
        }
    }

    anyhow::bail!("Unable to find har related request entry")
}

pub fn check_from_slice(s: &[u8]) -> anyhow::Result<()> {
    let _ = serde_json::from_slice::<Har>(&s)?;
    Ok(())
}

pub fn check_from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<()> {
    let bytes = std::fs::read(path)?;
    check_from_slice(&bytes)
}

pub fn parse_from_slice(s: &[u8]) -> anyhow::Result<RequestEntry> {
    if let Some(entry) = unsafe { CACHE_REQUEST_ENTRY.clone() } {
        return Ok(entry);
    }
    let har = serde_json::from_slice::<Har>(&s)?;
    parse(har)
}

pub fn parse_from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<RequestEntry> {
    if let Some(entry) = unsafe { CACHE_REQUEST_ENTRY.clone() } {
        return Ok(entry);
    }
    let bytes = std::fs::read(path)?;
    let har = serde_json::from_slice::<Har>(&bytes)?;
    drop(bytes);
    parse(har)
}

pub fn clear_cache() {
    let lock = LOCK.lock().unwrap();
    unsafe { CACHE_REQUEST_ENTRY = None }
    drop(lock)
}

#[derive(Debug, Deserialize)]
struct Har {
    log: Log,
}

#[derive(Debug, Deserialize)]
struct Log {
    entries: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    #[serde(rename = "request")]
    request: Request,
    #[serde(rename = "startedDateTime")]
    started_date_time: String,
}

#[derive(Debug, Deserialize)]
struct Request {
    method: String,
    url: String,
    headers: Vec<Header>,
    #[serde(rename = "postData")]
    post_data: Option<PostData>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct PostData {
    #[serde(rename = "mimeType")]
    mime_type: String,
    text: String,
    params: Vec<Param>,
}

#[derive(Debug, Deserialize)]
pub struct Param {
    pub name: String,
    pub value: String,
}
