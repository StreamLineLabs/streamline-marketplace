//! BigQuery Sink Connector — writes data to Google BigQuery.
//!
//! Produces BigQuery tabledata.insertAll request envelopes. Supports:
//! - Row-level insert ID for deduplication
//! - Column mapping from JSON fields to BigQuery columns
//! - Batch inserts with configurable size

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

// -- Configuration --

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BigQuerySinkConfig {
    /// GCP project ID.
    pub project_id: String,
    /// BigQuery dataset name.
    pub dataset: String,
    /// Target table name.
    pub table: String,
    /// JSON field to use as insertId for deduplication.
    #[serde(default)]
    pub insert_id_field: Option<String>,
    /// Column mapping: JSON field name → BigQuery column name.
    #[serde(default)]
    pub column_mapping: Option<HashMap<String, String>>,
    /// Maximum rows per insertAll request.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

fn default_batch_size() -> usize { 500 }

impl Default for BigQuerySinkConfig {
    fn default() -> Self {
        Self {
            project_id: String::new(),
            dataset: String::new(),
            table: String::new(),
            insert_id_field: None,
            column_mapping: None,
            batch_size: default_batch_size(),
        }
    }
}

// -- BigQuery Insert Request Envelope --

#[derive(Debug, Clone, Serialize)]
pub struct BigQueryInsertRequest {
    pub project_id: String,
    pub dataset: String,
    pub table: String,
    pub rows: Vec<BigQueryRow>,
    pub record_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BigQueryRow {
    pub insert_id: Option<String>,
    pub json: Value,
}

// -- Sink Implementation --

#[derive(Debug)]
pub struct BigQuerySink {
    config: BigQuerySinkConfig,
    buffer: Vec<Value>,
    total_sent: u64,
}

impl BigQuerySink {
    pub fn new(config: BigQuerySinkConfig) -> Self {
        Self { config, buffer: Vec::new(), total_sent: 0 }
    }

    pub fn from_config_str(json: &str) -> Result<Self, String> {
        let config: BigQuerySinkConfig = serde_json::from_str(json)
            .map_err(|e| format!("Invalid config: {e}"))?;
        if config.project_id.is_empty() { return Err("project_id is required".to_string()); }
        if config.dataset.is_empty() { return Err("dataset is required".to_string()); }
        if config.table.is_empty() { return Err("table is required".to_string()); }
        Ok(Self::new(config))
    }

    pub fn name(&self) -> &str { "bigquery-sink" }

    pub fn put(&mut self, records: Vec<Vec<u8>>) {
        for record in records {
            let value = match serde_json::from_slice::<Value>(&record) {
                Ok(v) => v,
                Err(_) => Value::String(String::from_utf8_lossy(&record).into_owned()),
            };
            self.buffer.push(value);
        }
    }

    pub fn flush(&mut self) -> Result<Vec<BigQueryInsertRequest>, String> {
        if self.buffer.is_empty() { return Ok(Vec::new()); }

        let mut requests = Vec::new();
        for chunk in self.buffer.chunks(self.config.batch_size.max(1)) {
            let rows: Vec<BigQueryRow> = chunk.iter().map(|record| {
                let insert_id = self.config.insert_id_field.as_ref().and_then(|field| {
                    extract_field(record, field).map(|v| match v {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                });

                let json = self.apply_column_mapping(record);

                BigQueryRow { insert_id, json }
            }).collect();

            let record_count = rows.len();
            requests.push(BigQueryInsertRequest {
                project_id: self.config.project_id.clone(),
                dataset: self.config.dataset.clone(),
                table: self.config.table.clone(),
                rows,
                record_count,
            });
        }

        self.total_sent += self.buffer.len() as u64;
        self.buffer.clear();
        Ok(requests)
    }

    pub fn buffered_count(&self) -> usize { self.buffer.len() }
    pub fn total_sent(&self) -> u64 { self.total_sent }
    pub fn should_flush(&self) -> bool { self.buffer.len() >= self.config.batch_size }

    fn apply_column_mapping(&self, record: &Value) -> Value {
        match &self.config.column_mapping {
            Some(mapping) if !mapping.is_empty() => {
                let mut mapped = serde_json::Map::new();
                for (json_field, bq_column) in mapping {
                    if let Some(val) = extract_field(record, json_field) {
                        mapped.insert(bq_column.clone(), val.clone());
                    }
                }
                Value::Object(mapped)
            }
            _ => record.clone(),
        }
    }
}

fn extract_field<'a>(record: &'a Value, field: &str) -> Option<&'a Value> {
    let mut current = record;
    for part in field.split('.') { current = current.get(part)?; }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> BigQuerySinkConfig {
        BigQuerySinkConfig {
            project_id: "my-project".to_string(),
            dataset: "analytics".to_string(),
            table: "events".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_config_parsing() {
        let json = r#"{
            "project_id": "my-project",
            "dataset": "analytics",
            "table": "events"
        }"#;
        let sink = BigQuerySink::from_config_str(json).unwrap();
        assert_eq!(sink.name(), "bigquery-sink");
        assert_eq!(sink.config.batch_size, 500);
        assert!(sink.config.insert_id_field.is_none());
        assert!(sink.config.column_mapping.is_none());
    }

    #[test]
    fn test_config_parsing_missing_project() {
        assert!(BigQuerySink::from_config_str(r#"{"dataset":"d","table":"t"}"#).is_err());
    }

    #[test]
    fn test_config_parsing_missing_dataset() {
        assert!(BigQuerySink::from_config_str(r#"{"project_id":"p","table":"t"}"#).is_err());
    }

    #[test]
    fn test_config_parsing_missing_table() {
        assert!(BigQuerySink::from_config_str(r#"{"project_id":"p","dataset":"d"}"#).is_err());
    }

    #[test]
    fn test_insert_id_extraction() {
        let mut config = test_config();
        config.insert_id_field = Some("id".to_string());
        let mut sink = BigQuerySink::new(config);
        sink.put(vec![br#"{"id":"evt-1","data":"x"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].rows[0].insert_id, Some("evt-1".to_string()));
    }

    #[test]
    fn test_insert_id_numeric() {
        let mut config = test_config();
        config.insert_id_field = Some("id".to_string());
        let mut sink = BigQuerySink::new(config);
        sink.put(vec![br#"{"id":42,"data":"x"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].rows[0].insert_id, Some("42".to_string()));
    }

    #[test]
    fn test_insert_id_missing_field() {
        let mut config = test_config();
        config.insert_id_field = Some("id".to_string());
        let mut sink = BigQuerySink::new(config);
        sink.put(vec![br#"{"data":"x"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].rows[0].insert_id, None);
    }

    #[test]
    fn test_no_insert_id() {
        let mut sink = BigQuerySink::new(test_config());
        sink.put(vec![br#"{"event":"click"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].rows[0].insert_id, None);
        assert_eq!(reqs[0].rows[0].json["event"], "click");
    }

    #[test]
    fn test_column_mapping() {
        let mut config = test_config();
        let mut mapping = HashMap::new();
        mapping.insert("user.name".to_string(), "user_name".to_string());
        mapping.insert("event".to_string(), "event_type".to_string());
        config.column_mapping = Some(mapping);
        let mut sink = BigQuerySink::new(config);
        sink.put(vec![br#"{"user":{"name":"Bob"},"event":"click","extra":"ignored"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        let json = &reqs[0].rows[0].json;
        assert_eq!(json["user_name"], "Bob");
        assert_eq!(json["event_type"], "click");
        assert!(json.get("extra").is_none());
    }

    #[test]
    fn test_column_mapping_none() {
        let mut sink = BigQuerySink::new(test_config());
        sink.put(vec![br#"{"event":"click","user":"alice"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].rows[0].json["event"], "click");
        assert_eq!(reqs[0].rows[0].json["user"], "alice");
    }

    #[test]
    fn test_batch_chunking() {
        let mut config = test_config();
        config.batch_size = 2;
        let mut sink = BigQuerySink::new(config);
        sink.put(vec![
            br#"{"a":1}"#.to_vec(),
            br#"{"b":2}"#.to_vec(),
            br#"{"c":3}"#.to_vec(),
        ]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].record_count, 2);
        assert_eq!(reqs[0].rows.len(), 2);
        assert_eq!(reqs[1].record_count, 1);
        assert_eq!(reqs[1].rows.len(), 1);
    }

    #[test]
    fn test_flush_empty() {
        let mut sink = BigQuerySink::new(test_config());
        assert!(sink.flush().unwrap().is_empty());
    }

    #[test]
    fn test_total_sent() {
        let mut sink = BigQuerySink::new(test_config());
        sink.put(vec![br#"{"x":1}"#.to_vec(), br#"{"x":2}"#.to_vec()]);
        sink.flush().unwrap();
        assert_eq!(sink.total_sent(), 2);
    }

    #[test]
    fn test_should_flush() {
        let mut config = test_config();
        config.batch_size = 2;
        let mut sink = BigQuerySink::new(config);
        assert!(!sink.should_flush());
        sink.put(vec![br#"{"a":1}"#.to_vec()]);
        assert!(!sink.should_flush());
        sink.put(vec![br#"{"b":2}"#.to_vec()]);
        assert!(sink.should_flush());
    }

    #[test]
    fn test_request_fields() {
        let mut sink = BigQuerySink::new(test_config());
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].project_id, "my-project");
        assert_eq!(reqs[0].dataset, "analytics");
        assert_eq!(reqs[0].table, "events");
    }
}
