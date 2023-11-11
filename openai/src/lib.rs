#![recursion_limit = "256"]

use std::time::Duration;

use reqwest::impersonate::Impersonate;

pub mod arkose;
pub mod auth;
pub mod balancer;
pub mod chatgpt;
pub mod context;
pub mod error;
pub mod eventsource;
pub mod homedir;
pub mod log;
pub mod platform;
pub mod token;
pub mod unescape;
pub mod urldecoding;
pub mod uuid;

#[cfg(feature = "serve")]
pub mod serve;

pub const HEADER_UA: &str = "okhttp/4.9.1";

pub const URL_CHATGPT_API: &str = "https://chat.openai.com";
pub const URL_PLATFORM_API: &str = "https://api.openai.com";
pub const ORIGIN_CHATGPT: &str = "https://chat.openai.com/chat";
pub const HOST_CHATGPT: &str = "chat.openai.com";

const RANDOM_IMPERSONATE: [Impersonate; 7] = [
    Impersonate::OkHttp3_9,
    Impersonate::OkHttp3_11,
    Impersonate::OkHttp3_13,
    Impersonate::OkHttp3_14,
    Impersonate::OkHttp4_9,
    Impersonate::OkHttp4_10,
    Impersonate::OkHttp5,
];

/// Randomly select a user agent from a list of known user agents.
pub(crate) fn random_impersonate() -> Impersonate {
    use rand::seq::IteratorRandom;

    RANDOM_IMPERSONATE
        .into_iter()
        .choose(&mut rand::thread_rng())
        .unwrap_or(Impersonate::OkHttp5)
}

pub fn now_duration() -> anyhow::Result<Duration> {
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(std::time::UNIX_EPOCH)?;
    Ok(duration)
}

pub fn format_time_to_rfc3399(timestamp: i64) -> anyhow::Result<String> {
    let time = time::OffsetDateTime::from_unix_timestamp(timestamp)?
        .format(&time::format_description::well_known::Rfc3339)?;
    Ok(time)
}

pub fn generate_random_string(len: usize) -> String {
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let rng = thread_rng();
    rng.sample_iter(&Alphanumeric)
        .take(len)
        .map(|x| CHARSET[x as usize % CHARSET.len()] as char)
        .collect()
}
