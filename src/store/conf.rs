use std::{collections::HashMap, ops::Not, path::PathBuf};

use anyhow::Context;

use crate::homedir::home_dir;

use super::{Store, StoreId, StoreResult};
use serde::{Deserialize, Serialize};

const DEFAULT_ID: &str = "999999999999999999";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Conf {
    id: String,
    /// Oofficial API prefix. Format: https://example.com
    pub official_api: Option<String>,
    /// Unofficial API prefix. Format: https://example.com
    pub unofficial_api: Option<String>,
    /// Client proxy. Format: protocol://user:pass@ip:port
    pub proxy: Option<String>,
    /// Get arkose-token endpoint
    pub arkose_token_endpoint: Option<String>,
    /// About the YesCaptcha platform client key solved by ArkoseLabs
    pub arkose_yescaptcha_key: Option<String>,
    /// About the browser HAR file path requested by ArkoseLabs
    pub arkose_har_path: Option<String>,
    /// Client timeout (seconds)
    pub timeout: usize,
    /// Client connect timeout (seconds)
    pub connect_timeout: usize,
    /// TCP keepalive (seconds)
    pub tcp_keepalive: usize,
}

impl StoreId for Conf {
    fn id(&self) -> String {
        self.id.to_owned()
    }
}

impl Default for Conf {
    fn default() -> Self {
        Self {
            official_api: None,
            unofficial_api: None,
            proxy: None,
            arkose_token_endpoint: None,
            timeout: 60,
            connect_timeout: 600,
            tcp_keepalive: 75,
            id: DEFAULT_ID.to_owned(),
            arkose_yescaptcha_key: None,
            arkose_har_path: None,
        }
    }
}

pub struct ConfBuilder {
    official_api: Option<String>,
    unofficial_api: Option<String>,
    proxy: Option<String>,
    arkose_token_endpoint: Option<String>,
    timeout: usize,
    connect_timeout: usize,
    tcp_keepalive: usize,
    arkose_yescaptcha_key: Option<String>,
    arkose_har_path: Option<String>,
}

impl ConfBuilder {
    pub fn builder() -> Self {
        ConfBuilder {
            official_api: None,
            unofficial_api: None,
            proxy: None,
            arkose_token_endpoint: None,
            timeout: 60,
            connect_timeout: 600,
            tcp_keepalive: 75,
            arkose_har_path: None,
            arkose_yescaptcha_key: None,
        }
    }

    pub fn official_api(mut self, official_api: String) -> Self {
        self.official_api = Some(official_api);
        self
    }

    pub fn unofficial_api(mut self, unofficial_api: String) -> Self {
        self.unofficial_api = Some(unofficial_api);
        self
    }

    pub fn proxy(mut self, proxy: String) -> Self {
        self.proxy = Some(proxy);
        self
    }

    pub fn arkose_token_endpoint(mut self, arkose_token_endpoint: String) -> Self {
        self.arkose_token_endpoint = Some(arkose_token_endpoint);
        self
    }

    pub fn timeout(mut self, timeout: usize) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn connect_timeout(mut self, connect_timeout: usize) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    pub fn tcp_keepalive(mut self, tcp_keepalive: usize) -> Self {
        self.tcp_keepalive = tcp_keepalive;
        self
    }

    pub fn build(self) -> Conf {
        Conf {
            id: DEFAULT_ID.to_owned(),
            official_api: self.official_api,
            unofficial_api: self.unofficial_api,
            proxy: self.proxy,
            arkose_token_endpoint: self.arkose_token_endpoint,
            timeout: self.timeout,
            connect_timeout: self.connect_timeout,
            tcp_keepalive: self.tcp_keepalive,
            arkose_yescaptcha_key: self.arkose_yescaptcha_key,
            arkose_har_path: self.arkose_har_path,
        }
    }
}

pub struct ConfFileStore(PathBuf);

impl ConfFileStore {
    pub fn new(path: Option<PathBuf>) -> StoreResult<Self> {
        let path = path.unwrap_or({
            match home_dir() {
                Some(home_dir) => home_dir.join(".opengpt-conf"),
                None => PathBuf::from(".opengpt-conf"),
            }
        });
        if let Some(parent) = path.parent() {
            if path.exists().not() {
                std::fs::create_dir_all(parent)
                    .context("Unable to create default file Account storage file")?
            }
        }
        if path.exists().not() {
            std::fs::File::create(&path)?;
        }
        Ok(ConfFileStore(path))
    }
}

impl Store<Conf> for ConfFileStore {
    fn add(&self, conf: Conf) -> StoreResult<Option<Conf>> {
        let bytes = std::fs::read(&self.0)?;
        let mut data: HashMap<String, Conf> = if bytes.is_empty() {
            HashMap::new()
        } else {
            serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!(e))?
        };
        let v = data.insert(conf.id(), conf);
        let json = serde_json::to_string_pretty(&data)?;
        std::fs::write(&self.0, json.as_bytes())?;
        Ok(v)
    }

    fn get(&self, target: Conf) -> StoreResult<Option<Conf>> {
        let bytes = std::fs::read(&self.0)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        let data: HashMap<String, Conf> =
            serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!(e))?;
        Ok(data.get(&target.id()).cloned())
    }

    fn remove(&self, target: Conf) -> StoreResult<Option<Conf>> {
        let bytes = std::fs::read(&self.0)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        let mut data: HashMap<String, Conf> =
            serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!(e))?;
        let v = data.remove(&target.id());
        let json = serde_json::to_string_pretty(&data)?;
        std::fs::write(&self.0, json)?;
        Ok(v)
    }

    fn list(&self) -> StoreResult<Vec<Conf>> {
        let bytes = std::fs::read(&self.0)?;
        if bytes.is_empty() {
            return Ok(vec![]);
        }
        let data: HashMap<String, Conf> =
            serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!(e))?;
        Ok(data.into_values().collect::<Vec<Conf>>())
    }
}
