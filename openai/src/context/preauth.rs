use crate::{debug, error, homedir::home_dir, info, now_duration, warn};
use moka::sync::Cache;
use std::{path::PathBuf, time::Duration};

pub(super) struct PreauthCookieProvider {
    path: PathBuf,
    cache: Cache<String, String>,
}

impl PreauthCookieProvider {
    pub(super) fn new() -> Self {
        let path = home_dir()
            .unwrap_or(PathBuf::from("."))
            .join(".preauth_cookies");

        // Read from file
        let data = std::fs::read(&path)
            .map(|data| {
                data.split(|&c| c == b'\n')
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .filter(|input| Self::is_invalid(input))
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();

        let cache: Cache<String, String> = Cache::builder()
            .max_capacity(1000)
            .time_to_live(Duration::from_secs(3600 * 24))
            .build();

        // Load from file
        data.iter().for_each(|value| {
            debug!("Load file: {}, PreAuth Cookie: {value}", path.display());
            value.find(":").map(|colon_index| {
                let device_id = &value[..colon_index];
                cache.insert(device_id.to_owned(), value.to_owned())
            });
        });

        if let Some(err) = std::fs::write(&path, data.join("\n").as_bytes()).err() {
            warn!("Failed to write preauth cookie to file: {err}")
        };

        PreauthCookieProvider { cache, path }
    }

    pub(super) fn push(&self, value: &str) {
        value
            .split(";")
            .find(|s| s.contains("_preauth_devicecheck"))
            .map(|value| {
                let preauth_devicecheck = value.replace("_preauth_devicecheck=", "");
                preauth_devicecheck.find(":").map(|colon_index| {
                    let device_id = &preauth_devicecheck[..colon_index];
                    let _ = self.cache.get_with(device_id.to_owned(), || {
                        info!("Push PreAuth Cookie: {preauth_devicecheck}");
                        self.append_preauth_cookie_to_file(&preauth_devicecheck);
                        preauth_devicecheck
                    });
                });
            });
    }

    pub(super) fn get(&self) -> Option<String> {
        use rand::seq::IteratorRandom;
        if let Some((_, v)) = self
            .cache
            .iter()
            .filter(|(_, input)| Self::is_invalid(input))
            .choose(&mut rand::thread_rng())
        {
            return Some(v);
        }
        None
    }

    fn append_preauth_cookie_to_file(&self, value: &str) {
        std::fs::read(&self.path)
            .map(|mut data| {
                data.extend_from_slice(format!("{value}\n").as_bytes());
                data
            })
            .or_else(|_| Ok(format!("{value}\n").as_bytes().to_vec()))
            .and_then(|data| {
                std::fs::write(&self.path, data).map_err(|err| {
                    error!("Failed to write preauth cookie to file: {}", err);
                    err
                })
            })
            .err()
            .map(|err| error!("Failed to append preauth cookie to file: {}", err));
    }

    fn is_invalid(input: &str) -> bool {
        let parts: Vec<&str> = input.split(':').collect();
        if parts.len() == 2 {
            let timestamp_part = parts[1];
            let timestamp_parts: Vec<&str> = timestamp_part.split('-').collect();
            if timestamp_parts.len() == 2 {
                let timestamp = timestamp_parts[0];
                let timestamp = timestamp.parse::<u64>().unwrap_or(0);
                match now_duration() {
                    Ok(duration) => return duration.as_secs() - timestamp < (3600 * 24 - 60),
                    Err(err) => error!("Failed to get now duration: {}", err),
                }
            }
        }
        false
    }
}
