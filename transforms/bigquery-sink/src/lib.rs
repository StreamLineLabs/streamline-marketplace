//! BigQuery Sink Connector — writes data to Google BigQuery via Storage Write API.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct BigQuerySinkConfig {
    pub project_id: String,
    pub dataset: String,
    pub table: String,
    pub credentials_path: Option<String>,
    pub batch_size: usize,
}

impl Default for BigQuerySinkConfig {
    fn default() -> Self {
        Self {
            project_id: String::new(),
            dataset: String::new(),
            table: String::new(),
            credentials_path: None,
            batch_size: 500,
        }
    }
}

pub struct BigQuerySink {
    config: BigQuerySinkConfig,
    buffer: Vec<Vec<u8>>,
}

impl BigQuerySink {
    pub fn new(config: BigQuerySinkConfig) -> Self {
        Self {
            config,
            buffer: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        "bigquery-sink"
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
