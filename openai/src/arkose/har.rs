use crate::arkose::crypto;
use crate::arkose::error::ArkoseError;
use crate::urldecoding;
use base64::Engine;
use moka::sync::Cache;
use serde::Deserialize;
use std::path::Path;
use std::sync::OnceLock;
use time::format_description::well_known::Rfc3339;

#[derive(Clone)]
pub struct RequestEntry {
    pub url: String,
    pub method: String,
    pub headers: Vec<Header>,
    pub body: String,
    pub bx: String,
    pub bv: String,
}

pub fn check_from_slice(s: &[u8]) -> anyhow::Result<()> {
    let _ = serde_json::from_slice::<Har>(&s)?;
    Ok(())
}

#[inline]
pub fn check_from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<()> {
    let bytes = std::fs::read(path)?;
    check_from_slice(&bytes)
}

#[inline]
pub fn parse_from_slice(s: &[u8]) -> anyhow::Result<RequestEntry> {
    let har = serde_json::from_slice::<Har>(&s)?;
    parse(har)
}

static CACHE_REQUEST_ENTRY: OnceLock<Cache<String, RequestEntry>> = OnceLock::new();

fn get_or_init_cache() -> &'static Cache<String, RequestEntry> {
    CACHE_REQUEST_ENTRY.get_or_init(|| Cache::new(u64::MAX))
}

pub(crate) fn clear_cache(key: &str) {
    get_or_init_cache().remove(key);
}

#[inline]
pub fn parse_from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<RequestEntry> {
    // Check if the path is a file
    path.as_ref()
        .is_file()
        .then(|| ())
        .ok_or_else(|| ArkoseError::NotAFile(path.as_ref().display().to_string()))?;

    // Get the cache
    let cache = get_or_init_cache();

    // Get the key from the path
    let key = format!("{}", path.as_ref().display());

    // Try to get the value from the cache
    let result = cache.try_get_with(key, || {
        let bytes = std::fs::read(path)?;
        let har = serde_json::from_slice::<Har>(&bytes)?;
        drop(bytes);
        parse(har)
    });

    match result {
        Ok(value) => Ok(value),
        Err(err) => anyhow::bail!(ArkoseError::FailedToGetHarEntry(err)),
    }
}

#[inline]
fn parse(har: Har) -> anyhow::Result<RequestEntry> {
    if let Some(entry) = har
        .log
        .entries
        .into_iter()
        .find(|e| e.request.url.contains("fc/gt2/public_key"))
    {
        if entry.started_date_time.is_empty() {
            anyhow::bail!(ArkoseError::InvalidHarFile);
        }

        let started_date_time = time::OffsetDateTime::parse(&entry.started_date_time, &Rfc3339)?;
        let bt = started_date_time.unix_timestamp();
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
                .unwrap_or_default()
                .iter()
                .find(|p| p.name.eq_ignore_ascii_case("bda"))
            {
                let cow = urldecoding::decode(&bda_param.value)?;
                let bda = base64::engine::general_purpose::STANDARD.decode(cow.into_owned())?;
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
                        .unwrap_or_default()
                        .split("&")
                        .into_iter()
                        .filter(|s| !s.contains("bda") && !s.contains("rnd"))
                        .collect::<Vec<&str>>()
                        .join("&"),
                    bx: crypto::decrypt(bda, &format!("{bv}{bw}"))?,
                    bv,
                };
                return Ok(entry);
            }
        }
    }

    anyhow::bail!(ArkoseError::HarEntryNotFound)
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
    mime_type: Option<String>,
    text: Option<String>,
    params: Option<Vec<Param>>,
}

#[derive(Debug, Deserialize)]
pub struct Param {
    pub name: String,
    pub value: String,
}
