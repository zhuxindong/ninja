use moka::sync::Cache;
use redis::RedisResult;
use redis_macros::{FromRedisValue, ToRedisArgs};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_timestamp() -> u64 {
    let now_duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    now_duration.as_secs()
}

#[async_trait::async_trait]
pub trait TokenBucket: Send + Sync {
    async fn acquire(&self, ip: IpAddr) -> anyhow::Result<bool>;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    Mem,
    Redis,
}

impl Default for Strategy {
    fn default() -> Self {
        Self::Mem
    }
}

impl std::str::FromStr for Strategy {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mem" => Ok(Strategy::Mem),
            "redis" => Ok(Strategy::Redis),
            _ => anyhow::bail!("storage policy: {} is not supported", s),
        }
    }
}

#[derive(Serialize, Deserialize, FromRedisValue, ToRedisArgs, Debug, Clone)]
struct BucketState {
    tokens: u32,
    last_time: u64,
}

pub struct MemTokenBucket {
    enable: bool,
    /// token bucket capacity `capacity`
    capacity: u32,
    /// token bucket fill rate `fill_rate`
    fill_rate: u32,
    /// ip -> token backet
    buckets: moka::sync::Cache<IpAddr, BucketState>,
}

impl MemTokenBucket {
    pub fn new(enable: bool, capacity: u32, fill_rate: u32, expired: u32) -> Self {
        let buckets: Cache<IpAddr, BucketState> = Cache::builder()
            .max_capacity(65535)
            .time_to_idle(Duration::from_secs(expired as u64))
            .build();
        Self {
            enable,
            capacity,
            fill_rate,
            buckets,
        }
    }
}

#[async_trait::async_trait]
impl TokenBucket for MemTokenBucket {
    async fn acquire(&self, ip: IpAddr) -> anyhow::Result<bool> {
        if !self.enable {
            return Ok(true);
        }

        let now_timestamp = now_timestamp();

        let mut bucket = self
            .buckets
            .entry(ip)
            .or_insert(BucketState {
                tokens: self.capacity,
                last_time: now_timestamp,
            })
            .into_value();

        let elapsed = now_timestamp - bucket.last_time;
        let tokens_to_add = (elapsed as u32) * self.fill_rate;
        bucket.tokens = (bucket.tokens + tokens_to_add).min(self.capacity);
        bucket.last_time = now_timestamp;

        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            self.buckets.insert(ip, bucket);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[derive(Clone, typed_builder::TypedBuilder)]
pub struct RedisTokenBucket {
    enable: bool,
    /// token bucket capacity `capacity`
    capacity: u32,
    /// token bucket fill rate `fill_rate`
    fill_rate: u32,
    /// token bucket expired
    expired: u32,
    /// redis client
    client: redis::Client,
}

impl RedisTokenBucket {
    pub fn new(
        enable: bool,
        capacity: u32,
        fill_rate: u32,
        expired: u32,
        node: String,
    ) -> RedisResult<Self> {
        // connect to redis
        let client = redis::Client::open(node)?;
        Ok(Self {
            enable,
            capacity,
            fill_rate,
            client,
            expired,
        })
    }
}

#[async_trait::async_trait]
impl TokenBucket for RedisTokenBucket {
    async fn acquire(&self, ip: IpAddr) -> anyhow::Result<bool> {
        use redis::AsyncCommands;
        if !self.enable {
            return Ok(true);
        }
        let mut con = self.client.get_async_connection().await?;
        let now_timestamp = now_timestamp();
        let mut bucket: BucketState = con
            .get_ex(ip.to_string(), redis::Expiry::EX(self.expired as usize))
            .await
            .unwrap_or(BucketState {
                tokens: self.capacity,
                last_time: now_timestamp,
            });

        let elapsed = now_timestamp - bucket.last_time;
        let tokens_to_add = (elapsed as u32) * self.fill_rate;
        bucket.tokens = (bucket.tokens + tokens_to_add).min(self.capacity);
        bucket.last_time = now_timestamp;

        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            con.set_ex(ip.to_string(), bucket, self.expired as usize)
                .await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub struct TokenBucketLimitContext(Box<dyn TokenBucket>);

impl From<(Strategy, bool, u32, u32, u32, String)> for TokenBucketLimitContext {
    fn from(value: (Strategy, bool, u32, u32, u32, String)) -> Self {
        let strategy = match value.0 {
            Strategy::Mem => Self(Box::new(MemTokenBucket::new(
                value.1, value.2, value.3, value.4,
            ))),
            Strategy::Redis => Self(Box::new(
                RedisTokenBucket::new(value.1, value.2, value.3, value.4, value.5)
                    .expect("redis token bucket init failed"),
            )),
        };
        strategy
    }
}

#[async_trait::async_trait]
impl TokenBucket for TokenBucketLimitContext {
    async fn acquire(&self, ip: IpAddr) -> anyhow::Result<bool> {
        Ok(self.0.acquire(ip).await?)
    }
}
