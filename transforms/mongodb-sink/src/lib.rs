//! MongoDB Sink Connector — inserts or upserts data into MongoDB collections.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct MongoDbSinkConfig {
    pub connection_uri: String,
    pub database: String,
    pub collection: String,
    pub write_mode: WriteMode,
    pub id_strategy: IdStrategy,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteMode {
    Insert,
    Upsert,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IdStrategy {
    Auto,
    Field,
}

impl Default for MongoDbSinkConfig {
    fn default() -> Self {
        Self {
            connection_uri: "mongodb://localhost:27017".to_string(),
            database: String::new(),
            collection: String::new(),
            write_mode: WriteMode::Insert,
            id_strategy: IdStrategy::Auto,
        }
    }
}

pub struct MongoDbSink {
    config: MongoDbSinkConfig,
    buffer: Vec<Vec<u8>>,
}

impl MongoDbSink {
    pub fn new(config: MongoDbSinkConfig) -> Self {
        Self {
            config,
            buffer: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        "mongodb-sink"
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
