//! Elasticsearch Sink Connector — bulk indexes data to Elasticsearch.
//!
//! Produces Elasticsearch Bulk API request envelopes. Supports:
//! - Index name templating with `{field}` substitution
//! - Custom document ID extraction from JSON fields
//! - Optional ingest pipeline
//! - Configurable bulk batch sizes

use serde::{Deserialize, Serialize};
use serde_json::Value;

// -- Configuration --

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ElasticsearchSinkConfig {
    /// Elasticsearch cluster URL.
    #[serde(default = "default_url")]
    pub url: String,
    /// Target index name. Supports `{field}` placeholders.
    pub index: String,
    /// Maximum documents per bulk request.
    #[serde(default = "default_bulk_size")]
    pub bulk_size: usize,
    /// JSON field to use as `_id`. None means Elasticsearch auto-generates.
    pub doc_id_field: Option<String>,
    /// Optional ingest pipeline name.
    pub pipeline: Option<String>,
}

fn default_url() -> String { "http://localhost:9200".to_string() }
fn default_bulk_size() -> usize { 500 }

impl Default for ElasticsearchSinkConfig {
    fn default() -> Self {
        Self {
            url: default_url(),
            index: String::new(),
            bulk_size: default_bulk_size(),
            doc_id_field: None,
            pipeline: None,
        }
    }
}

// -- Bulk Request Envelope --

/// An Elasticsearch _bulk API request for the host to execute.
#[derive(Debug, Clone, Serialize)]
pub struct BulkRequest {
    pub url: String,
    /// NDJSON body: alternating action/source lines.
    pub body: String,
    pub record_count: usize,
}

// -- Sink Implementation --

#[derive(Debug)]
pub struct ElasticsearchSink {
    config: ElasticsearchSinkConfig,
    buffer: Vec<Value>,
    total_sent: u64,
}

impl ElasticsearchSink {
    pub fn new(config: ElasticsearchSinkConfig) -> Self {
        Self { config, buffer: Vec::new(), total_sent: 0 }
    }

    pub fn from_config_str(json: &str) -> Result<Self, String> {
        let config: ElasticsearchSinkConfig = serde_json::from_str(json)
            .map_err(|e| format!("Invalid config: {e}"))?;
        if config.index.is_empty() {
            return Err("index is required".to_string());
        }
        Ok(Self::new(config))
    }

    pub fn name(&self) -> &str { "elasticsearch-sink" }

    pub fn put(&mut self, records: Vec<Vec<u8>>) {
        for record in records {
            let value = match serde_json::from_slice::<Value>(&record) {
                Ok(v) => v,
                Err(_) => Value::String(String::from_utf8_lossy(&record).into_owned()),
            };
            self.buffer.push(value);
        }
    }

    pub fn flush(&mut self) -> Result<Vec<BulkRequest>, String> {
        if self.buffer.is_empty() {
            return Ok(Vec::new());
        }

        let mut requests = Vec::new();
        for chunk in self.buffer.chunks(self.config.bulk_size.max(1)) {
            requests.push(self.build_bulk(chunk)?);
        }

        self.total_sent += self.buffer.len() as u64;
        self.buffer.clear();
        Ok(requests)
    }

    pub fn buffered_count(&self) -> usize { self.buffer.len() }
    pub fn total_sent(&self) -> u64 { self.total_sent }
    pub fn should_flush(&self) -> bool { self.buffer.len() >= self.config.bulk_size }

    fn build_bulk(&self, records: &[Value]) -> Result<BulkRequest, String> {
        let mut ndjson = String::new();

        for record in records {
            let index = self.resolve_index(record);
            let doc_id = self.extract_doc_id(record);

            // Action line
            let mut action_meta = serde_json::json!({ "_index": index });
            if let Some(id) = &doc_id {
                action_meta["_id"] = Value::String(id.clone());
            }
            if let Some(ref pipeline) = self.config.pipeline {
                action_meta["pipeline"] = Value::String(pipeline.clone());
            }

            let action_line = serde_json::json!({ "index": action_meta });
            ndjson.push_str(&serde_json::to_string(&action_line)
                .map_err(|e| format!("Serialization error: {e}"))?);
            ndjson.push('\n');

            // Source line
            ndjson.push_str(&serde_json::to_string(record)
                .map_err(|e| format!("Serialization error: {e}"))?);
            ndjson.push('\n');
        }

        Ok(BulkRequest {
            url: format!("{}/_bulk", self.config.url),
            body: ndjson,
            record_count: records.len(),
        })
    }

    fn resolve_index(&self, record: &Value) -> String {
        let mut index = self.config.index.clone();
        if index.contains('{') {
            if let Some(obj) = record.as_object() {
                for (k, v) in obj {
                    let placeholder = format!("{{{k}}}");
                    if index.contains(&placeholder) {
                        let val = match v {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        index = index.replace(&placeholder, &val);
                    }
                }
            }
        }
        index
    }

    fn extract_doc_id(&self, record: &Value) -> Option<String> {
        let field = self.config.doc_id_field.as_deref()?;
        let mut current = record;
        for part in field.split('.') {
            current = current.get(part)?;
        }
        Some(match current {
            Value::String(s) => s.clone(),
            other => other.to_string().trim_matches('"').to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ElasticsearchSinkConfig {
        ElasticsearchSinkConfig { index: "events".to_string(), ..Default::default() }
    }

    #[test]
    fn test_default_config() {
        let c = ElasticsearchSinkConfig::default();
        assert_eq!(c.url, "http://localhost:9200");
        assert!(c.index.is_empty());
        assert_eq!(c.bulk_size, 500);
        assert!(c.doc_id_field.is_none());
        assert!(c.pipeline.is_none());
    }

    #[test]
    fn test_from_config_str_missing_index() {
        assert!(ElasticsearchSink::from_config_str(r#"{}"#).is_err());
    }

    #[test]
    fn test_from_config_str_valid() {
        let json = r#"{"index":"logs","bulk_size":100}"#;
        let sink = ElasticsearchSink::from_config_str(json).unwrap();
        assert_eq!(sink.name(), "elasticsearch-sink");
    }

    #[test]
    fn test_basic_bulk_format() {
        let mut sink = ElasticsearchSink::new(test_config());
        sink.put(vec![br#"{"user":"alice"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs.len(), 1);
        assert!(reqs[0].body.contains(r#""_index":"events""#));
        assert!(reqs[0].body.contains("alice"));
        assert_eq!(reqs[0].record_count, 1);
        // NDJSON: action line + source line
        let lines: Vec<&str> = reqs[0].body.trim().split('\n').collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_doc_id_extraction() {
        let mut config = test_config();
        config.doc_id_field = Some("id".to_string());
        let mut sink = ElasticsearchSink::new(config);
        sink.put(vec![br#"{"id":"doc-1","data":"x"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert!(reqs[0].body.contains(r#""_id":"doc-1""#));
    }

    #[test]
    fn test_no_doc_id() {
        let mut sink = ElasticsearchSink::new(test_config());
        sink.put(vec![br#"{"data":"x"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert!(!reqs[0].body.contains("_id"));
    }

    #[test]
    fn test_index_template() {
        let mut config = test_config();
        config.index = "logs-{level}".to_string();
        let mut sink = ElasticsearchSink::new(config);
        sink.put(vec![br#"{"level":"error","msg":"fail"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert!(reqs[0].body.contains(r#""_index":"logs-error""#));
    }

    #[test]
    fn test_pipeline() {
        let mut config = test_config();
        config.pipeline = Some("my-pipeline".to_string());
        let mut sink = ElasticsearchSink::new(config);
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert!(reqs[0].body.contains("my-pipeline"));
    }

    #[test]
    fn test_bulk_chunking() {
        let mut config = test_config();
        config.bulk_size = 2;
        let mut sink = ElasticsearchSink::new(config);
        sink.put(vec![
            br#"{"a":1}"#.to_vec(),
            br#"{"b":2}"#.to_vec(),
            br#"{"c":3}"#.to_vec(),
        ]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].record_count, 2);
        assert_eq!(reqs[1].record_count, 1);
    }

    #[test]
    fn test_flush_empty() {
        let mut sink = ElasticsearchSink::new(test_config());
        assert!(sink.flush().unwrap().is_empty());
    }

    #[test]
    fn test_url_format() {
        let mut sink = ElasticsearchSink::new(test_config());
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].url, "http://localhost:9200/_bulk");
    }

    #[test]
    fn test_total_sent() {
        let mut sink = ElasticsearchSink::new(test_config());
        sink.put(vec![br#"{"a":1}"#.to_vec(), br#"{"b":2}"#.to_vec()]);
        sink.flush().unwrap();
        assert_eq!(sink.total_sent(), 2);
        assert_eq!(sink.buffered_count(), 0);
    }
}
