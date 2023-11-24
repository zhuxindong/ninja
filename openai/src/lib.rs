#![recursion_limit = "256"]
pub mod arkose;
pub mod auth;
pub mod balancer;
pub mod chatgpt;
pub mod context;
pub mod eventsource;
pub mod homedir;
pub mod log;
pub mod platform;
pub mod proxy;
#[cfg(feature = "serve")]
pub mod serve;
pub mod token;
pub mod unescape;
pub mod urldecoding;
pub mod uuid;

use std::time::Duration;

pub const LIB_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const HEADER_UA: &str = "okhttp/4.9.1";
pub const URL_CHATGPT_API: &str = "https://chat.openai.com";
pub const URL_PLATFORM_API: &str = "https://api.openai.com";

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
