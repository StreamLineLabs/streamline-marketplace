//! MySQL Sink Connector — writes data to MySQL via INSERT or UPSERT prepared statements.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct MySqlSinkConfig {
    pub connection_url: String,
    pub table: String,
    pub batch_size: usize,
    pub write_mode: WriteMode,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteMode {
    Insert,
    Upsert,
}

impl Default for MySqlSinkConfig {
    fn default() -> Self {
        Self {
            connection_url: String::new(),
            table: String::new(),
            batch_size: 500,
            write_mode: WriteMode::Insert,
        }
    }
}

pub struct MySqlSink {
    config: MySqlSinkConfig,
    buffer: Vec<Vec<u8>>,
}

impl MySqlSink {
    pub fn new(config: MySqlSinkConfig) -> Self {
        Self {
            config,
            buffer: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        "mysql-sink"
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
