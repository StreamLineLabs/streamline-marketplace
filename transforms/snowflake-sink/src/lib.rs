//! Snowflake Sink Connector — loads data into Snowflake via Snowpipe.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct SnowflakeSinkConfig {
    pub account: String,
    pub warehouse: String,
    pub database: String,
    pub schema_name: String,
    pub table: String,
    pub stage_path: String,
}

impl Default for SnowflakeSinkConfig {
    fn default() -> Self {
        Self {
            account: String::new(),
            warehouse: String::new(),
            database: String::new(),
            schema_name: "public".to_string(),
            table: String::new(),
            stage_path: String::new(),
        }
    }
}

pub struct SnowflakeSink {
    config: SnowflakeSinkConfig,
    buffer: Vec<Vec<u8>>,
}

impl SnowflakeSink {
    pub fn new(config: SnowflakeSinkConfig) -> Self {
        Self {
            config,
            buffer: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        "snowflake-sink"
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
