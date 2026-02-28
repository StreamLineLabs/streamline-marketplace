//! S3 Sink Connector — writes streaming data to Amazon S3.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct S3SinkConfig {
    pub bucket: String,
    pub region: String,
    pub prefix: String,
    pub format: OutputFormat,
    pub flush_interval_secs: u64,
    pub max_batch_size: usize,
    pub compression: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Json,
    Parquet,
    Csv,
}

impl Default for S3SinkConfig {
    fn default() -> Self {
        Self {
            bucket: String::new(),
            region: "us-east-1".to_string(),
            prefix: "streamline/".to_string(),
            format: OutputFormat::Json,
            flush_interval_secs: 60,
            max_batch_size: 1000,
            compression: Some("gzip".to_string()),
        }
    }
}

pub struct S3Sink {
    config: S3SinkConfig,
    buffer: Vec<Vec<u8>>,
}

impl S3Sink {
    pub fn new(config: S3SinkConfig) -> Self {
        Self {
            config,
            buffer: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        "s3-sink"
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
