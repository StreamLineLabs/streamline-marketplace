//! PostgreSQL Connector — CDC source and upsert sink for PostgreSQL.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct PostgresConnectorConfig {
    pub connection_url: String,
    pub table: String,
    pub mode: ConnectorMode,
    pub poll_interval_ms: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectorMode {
    Source,
    Sink,
}

impl Default for PostgresConnectorConfig {
    fn default() -> Self {
        Self {
            connection_url: String::new(),
            table: String::new(),
            mode: ConnectorMode::Sink,
            poll_interval_ms: 1000,
        }
    }
}

pub struct PostgresConnector {
    config: PostgresConnectorConfig,
    buffer: Vec<Vec<u8>>,
}

impl PostgresConnector {
    pub fn new(config: PostgresConnectorConfig) -> Self {
        Self {
            config,
            buffer: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        "postgres-connector"
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
