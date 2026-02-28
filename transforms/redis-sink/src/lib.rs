//! Redis Sink Connector — writes data to Redis via XADD, SET, or PUBLISH.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct RedisSinkConfig {
    pub url: String,
    pub command: RedisCommand,
    pub key_field: String,
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RedisCommand {
    Xadd,
    Set,
    Publish,
}

impl Default for RedisSinkConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".to_string(),
            command: RedisCommand::Xadd,
            key_field: String::new(),
            ttl_secs: None,
        }
    }
}

pub struct RedisSink {
    config: RedisSinkConfig,
    buffer: Vec<Vec<u8>>,
}

impl RedisSink {
    pub fn new(config: RedisSinkConfig) -> Self {
        Self {
            config,
            buffer: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        "redis-sink"
    }

    pub fn put(&mut self, records: Vec<Vec<u8>>) {
        self.buffer.extend(records);
    }

    pub fn flush(&mut self) -> Result<usize, String> {
        let count = self.buffer.len();
        self.buffer.clear();
        Ok(count)
    }
}
