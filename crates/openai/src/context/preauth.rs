use crate::{error, homedir::home_dir, info, now_duration};
use moka::sync::Cache;
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

const SEPARATOR: &str = "---";
const DEFAULT_MAX_AGE: u32 = 3600;
const DEFAULT_MAX_CAPACITY: u64 = 1000;

static LOCK: Mutex<()> = Mutex::new(());
static mut CACHE: Option<Cache<String, String>> = None;

fn get_or_init_cache(max_age: Option<u32>) -> &'static Cache<String, String> {
    unsafe {
        CACHE.is_none().then(|| {
            let cache = Cache::builder()
                .max_capacity(DEFAULT_MAX_CAPACITY)
                .time_to_live(Duration::from_secs(
                    max_age.unwrap_or(DEFAULT_MAX_AGE).into(),
                ))
                .build();
            CACHE = Some(cache);
        });
        CACHE.as_ref().unwrap()
    }
}

fn reload_cache(max_age: Option<u32>) {
    let cache = get_or_init_cache(max_age);

    cache.run_pending_tasks();
    // If cache is empty, return
    if cache.entry_count() == 0 {
        return;
    }

    let new_cache = Cache::builder()
        .max_capacity(DEFAULT_MAX_CAPACITY)
        .time_to_live(Duration::from_secs(
            max_age.unwrap_or(DEFAULT_MAX_AGE).into(),
        ))
        .build();

    cache.iter().for_each(|(k, v)| {
        new_cache.insert(k.to_string(), v);
    });

    // Unsafe: Replace cache
    if let Ok(lock) = LOCK.try_lock() {
        unsafe {
            CACHE = Some(new_cache);
        }
        drop(lock);
    }
}

pub(super) struct PreauthCookieProvider {
    path: PathBuf,
    max_age: Option<u32>,
}

impl PreauthCookieProvider {
    pub fn new() -> Self {
        let path = home_dir()
            .unwrap_or(PathBuf::from("."))
            .join(".preauth_cookies");

        // Read from file
        let data = std::fs::read(&path)
            .map(|data| {
                data.split(|&c| c == b'\n')
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();

        let mut provider = PreauthCookieProvider {
            path,
            max_age: None,
        };

        // Load from file
        data.into_iter().for_each(|value| {
            // split by `---`, example: `max_age---device_id:timestamp-xxxx`
            let group = value
                .split(SEPARATOR)
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<&str>>();

            // If group length is not 2, skip
            if group.len() != 2 {
                return;
            }

            // Parse max_age
            let max_age = group[0].parse::<u32>().unwrap_or(0);
            // Parse value
            let value = group[1];

            provider.max_age = Some(max_age);

            value.find(":").map(|colon_index| {
                let device_id = &value[..colon_index];
                // If is invalid, skip
                if !Self::is_invalid(value, Some(max_age)) {
                    info!("Loading preauth cookie value: {value}",);
                    get_or_init_cache(Some(max_age)).insert(device_id.to_owned(), value.to_owned())
                }
            });
        });

        provider
    }

    /// Push a preauth cookie
    /// Example: `id1:1704031809-xxx`
    pub fn push(&self, value: &str, max_age: Option<u32>) {
        value.find(":").map(|colon_index| {
            let device_id = &value[..colon_index];
            info!("Push PreAuth Cookie: {value}");
            get_or_init_cache(max_age).insert(device_id.to_owned(), value.to_owned());
            self.sync_to_file(&self.path, max_age);
        });
    }

    /// Pop a preauth cookie
    /// Example: `id1:1704031809-xxx`
    pub fn get(&self) -> Option<String> {
        use rand::seq::IteratorRandom;
        if let Some((_, v)) = get_or_init_cache(self.max_age)
            .iter()
            .filter(|(_, input)| Self::is_invalid(input, self.max_age))
            .choose(&mut rand::thread_rng())
        {
            return Some(v);
        }
        None
    }

    /// Check if is invalid
    fn is_invalid(input: &str, max_age: Option<u32>) -> bool {
        let parts: Vec<&str> = input.split(':').collect();
        if parts.len() == 2 {
            let timestamp_part = parts[1];
            let timestamp_parts: Vec<&str> = timestamp_part.split('-').collect();
            if timestamp_parts.len() == 2 {
                let timestamp = timestamp_parts[0];
                let timestamp = timestamp.parse::<u64>().unwrap_or(0);
                match now_duration() {
                    Ok(duration) => {
                        return duration.as_secs() - timestamp
                            < (max_age.unwrap_or(DEFAULT_MAX_AGE) - 60).into()
                    }
                    Err(err) => error!("Failed to get now duration: {}", err),
                }
            }
        }
        false
    }

    /// Sync to file
    /// Only sync valid preauth cookie
    fn sync_to_file(&self, path: impl AsRef<Path>, max_age: Option<u32>) {
        // If upstream max_age is different, reload cache
        if self.max_age.ne(&max_age) {
            reload_cache(max_age)
        }

        let data = get_or_init_cache(max_age)
            .iter()
            .map(|(_, v)| format!("{}{SEPARATOR}{v}", max_age.unwrap_or(DEFAULT_MAX_AGE)))
            .collect::<Vec<String>>()
            .join("\n");
        let _ = std::fs::write(path.as_ref(), data).map_err(|err| {
            error!("Failed to write preauth cookie to file: {}", err);
        });
    }
}
