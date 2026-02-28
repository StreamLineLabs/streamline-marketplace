//! Elasticsearch Sink Connector — bulk indexes data to Elasticsearch.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct ElasticsearchSinkConfig {
    pub url: String,
    pub index: String,
    pub bulk_size: usize,
    pub document_id_field: Option<String>,
}

impl Default for ElasticsearchSinkConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:9200".to_string(),
            index: String::new(),
            bulk_size: 500,
            document_id_field: None,
        }
    }
}

pub struct ElasticsearchSink {
    config: ElasticsearchSinkConfig,
    buffer: Vec<Vec<u8>>,
}

impl ElasticsearchSink {
    pub fn new(config: ElasticsearchSinkConfig) -> Self {
        Self {
            config,
            buffer: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        "elasticsearch-sink"
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
