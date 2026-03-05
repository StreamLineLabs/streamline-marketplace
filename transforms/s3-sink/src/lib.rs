//! S3 Sink Connector — writes streaming data to Amazon S3.
//!
//! Produces S3 PutObject request envelopes. Supports:
//! - JSON/NDJSON and CSV output formats
//! - Key partitioning by date or custom field
//! - Gzip compression metadata
//! - Configurable batch size and flush intervals

use serde::{Deserialize, Serialize};
use serde_json::Value;

// -- Configuration --

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct S3SinkConfig {
    /// Target S3 bucket name.
    pub bucket: String,
    /// AWS region.
    #[serde(default = "default_region")]
    pub region: String,
    /// Key prefix (e.g., "streamline/events/").
    #[serde(default = "default_prefix")]
    pub prefix: String,
    /// Output file format.
    #[serde(default)]
    pub format: OutputFormat,
    /// Partition key template. Use `{field}` for substitution or `{date}` for YYYY/MM/DD.
    #[serde(default)]
    pub partition_by: String,
    /// Maximum records per S3 object.
    #[serde(default = "default_batch_size")]
    pub max_batch_size: usize,
    /// Compression type (gzip or none).
    pub compression: Option<String>,
    /// File extension override.
    pub file_extension: Option<String>,
}

fn default_region() -> String { "us-east-1".to_string() }
fn default_prefix() -> String { "streamline/".to_string() }
fn default_batch_size() -> usize { 1000 }

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Json,
    Ndjson,
    Csv,
}

impl Default for OutputFormat {
    fn default() -> Self { OutputFormat::Json }
}

impl Default for S3SinkConfig {
    fn default() -> Self {
        Self {
            bucket: String::new(),
            region: default_region(),
            prefix: default_prefix(),
            format: OutputFormat::Json,
            partition_by: String::new(),
            max_batch_size: default_batch_size(),
            compression: Some("gzip".to_string()),
            file_extension: None,
        }
    }
}

// -- S3 PutObject Envelope --

#[derive(Debug, Clone, Serialize)]
pub struct S3PutRequest {
    pub bucket: String,
    pub key: String,
    pub region: String,
    pub body: String,
    pub content_type: String,
    pub compression: Option<String>,
    pub record_count: usize,
}

// -- Sink Implementation --

#[derive(Debug)]
pub struct S3Sink {
    config: S3SinkConfig,
    buffer: Vec<Value>,
    total_sent: u64,
    file_counter: u64,
}

impl S3Sink {
    pub fn new(config: S3SinkConfig) -> Self {
        Self { config, buffer: Vec::new(), total_sent: 0, file_counter: 0 }
    }

    pub fn from_config_str(json: &str) -> Result<Self, String> {
        let config: S3SinkConfig = serde_json::from_str(json)
            .map_err(|e| format!("Invalid config: {e}"))?;
        if config.bucket.is_empty() { return Err("bucket is required".to_string()); }
        Ok(Self::new(config))
    }

    pub fn name(&self) -> &str { "s3-sink" }

    pub fn put(&mut self, records: Vec<Vec<u8>>) {
        for record in records {
            let value = match serde_json::from_slice::<Value>(&record) {
                Ok(v) => v,
                Err(_) => Value::String(String::from_utf8_lossy(&record).into_owned()),
            };
            self.buffer.push(value);
        }
    }

    pub fn flush(&mut self) -> Result<Vec<S3PutRequest>, String> {
        if self.buffer.is_empty() { return Ok(Vec::new()); }

        let mut requests = Vec::new();
        for chunk in self.buffer.chunks(self.config.max_batch_size.max(1)) {
            self.file_counter += 1;
            let body = self.format_body(chunk)?;
            let key = self.build_key(chunk.first());
            let content_type = match self.config.format {
                OutputFormat::Json => "application/json",
                OutputFormat::Ndjson => "application/x-ndjson",
                OutputFormat::Csv => "text/csv",
            };
            requests.push(S3PutRequest {
                bucket: self.config.bucket.clone(),
                key,
                region: self.config.region.clone(),
                body,
                content_type: content_type.to_string(),
                compression: self.config.compression.clone(),
                record_count: chunk.len(),
            });
        }

        self.total_sent += self.buffer.len() as u64;
        self.buffer.clear();
        Ok(requests)
    }

    pub fn buffered_count(&self) -> usize { self.buffer.len() }
    pub fn total_sent(&self) -> u64 { self.total_sent }
    pub fn should_flush(&self) -> bool { self.buffer.len() >= self.config.max_batch_size }

    fn format_body(&self, records: &[Value]) -> Result<String, String> {
        match self.config.format {
            OutputFormat::Json => serde_json::to_string(&records)
                .map_err(|e| format!("JSON serialization error: {e}")),
            OutputFormat::Ndjson => {
                let mut out = String::new();
                for r in records {
                    out.push_str(&serde_json::to_string(r)
                        .map_err(|e| format!("NDJSON serialization error: {e}"))?);
                    out.push('\n');
                }
                Ok(out)
            }
            OutputFormat::Csv => {
                let mut out = String::new();
                // Header from first record's keys
                if let Some(Value::Object(obj)) = records.first() {
                    let headers: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
                    out.push_str(&headers.join(","));
                    out.push('\n');
                    for r in records {
                        let vals: Vec<String> = headers.iter().map(|h| {
                            r.get(*h).map(|v| match v {
                                Value::String(s) => s.clone(),
                                other => other.to_string(),
                            }).unwrap_or_default()
                        }).collect();
                        out.push_str(&vals.join(","));
                        out.push('\n');
                    }
                }
                Ok(out)
            }
        }
    }

    fn build_key(&self, sample: Option<&Value>) -> String {
        let ext = self.config.file_extension.clone().unwrap_or_else(|| {
            match (&self.config.format, &self.config.compression) {
                (OutputFormat::Json, Some(_)) => "json.gz".to_string(),
                (OutputFormat::Json, None) => "json".to_string(),
                (OutputFormat::Ndjson, Some(_)) => "ndjson.gz".to_string(),
                (OutputFormat::Ndjson, None) => "ndjson".to_string(),
                (OutputFormat::Csv, Some(_)) => "csv.gz".to_string(),
                (OutputFormat::Csv, None) => "csv".to_string(),
            }
        });

        let mut key = self.config.prefix.clone();

        // Apply partition_by template
        if !self.config.partition_by.is_empty() {
            let mut partition = self.config.partition_by.clone();
            if let Some(Value::Object(obj)) = sample {
                for (k, v) in obj {
                    let placeholder = format!("{{{k}}}");
                    if partition.contains(&placeholder) {
                        let val = match v { Value::String(s) => s.clone(), other => other.to_string() };
                        partition = partition.replace(&placeholder, &val);
                    }
                }
            }
            key.push_str(&partition);
            key.push('/');
        }

        key.push_str(&format!("part-{:06}.{}", self.file_counter, ext));
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> S3SinkConfig {
        S3SinkConfig { bucket: "my-bucket".to_string(), ..Default::default() }
    }

    #[test]
    fn test_default_config() {
        let c = S3SinkConfig::default();
        assert_eq!(c.region, "us-east-1");
        assert_eq!(c.prefix, "streamline/");
        assert_eq!(c.format, OutputFormat::Json);
        assert_eq!(c.max_batch_size, 1000);
    }

    #[test]
    fn test_from_config_str_missing_bucket() {
        assert!(S3Sink::from_config_str(r#"{}"#).is_err());
    }

    #[test]
    fn test_json_format() {
        let mut sink = S3Sink::new(test_config());
        sink.put(vec![br#"{"event":"click"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].content_type, "application/json");
        assert!(reqs[0].body.starts_with('['));
    }

    #[test]
    fn test_ndjson_format() {
        let mut config = test_config();
        config.format = OutputFormat::Ndjson;
        let mut sink = S3Sink::new(config);
        sink.put(vec![br#"{"a":1}"#.to_vec(), br#"{"b":2}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].content_type, "application/x-ndjson");
        assert!(reqs[0].body.contains('\n'));
        let lines: Vec<&str> = reqs[0].body.trim().split('\n').collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_csv_format() {
        let mut config = test_config();
        config.format = OutputFormat::Csv;
        let mut sink = S3Sink::new(config);
        sink.put(vec![br#"{"name":"Alice","age":"30"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].content_type, "text/csv");
        assert!(reqs[0].body.contains("Alice"));
    }

    #[test]
    fn test_key_with_prefix() {
        let mut sink = S3Sink::new(test_config());
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert!(reqs[0].key.starts_with("streamline/"));
        assert!(reqs[0].key.contains("part-000001"));
        assert!(reqs[0].key.ends_with(".json.gz"));
    }

    #[test]
    fn test_partition_by_field() {
        let mut config = test_config();
        config.partition_by = "region={region}".to_string();
        let mut sink = S3Sink::new(config);
        sink.put(vec![br#"{"region":"us-east","data":"x"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert!(reqs[0].key.contains("region=us-east/"));
    }

    #[test]
    fn test_batch_chunking() {
        let mut config = test_config();
        config.max_batch_size = 2;
        let mut sink = S3Sink::new(config);
        sink.put(vec![br#"{"a":1}"#.to_vec(), br#"{"b":2}"#.to_vec(), br#"{"c":3}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].record_count, 2);
        assert_eq!(reqs[1].record_count, 1);
    }

    #[test]
    fn test_flush_empty() {
        let mut sink = S3Sink::new(test_config());
        assert!(sink.flush().unwrap().is_empty());
    }

    #[test]
    fn test_no_compression_extension() {
        let mut config = test_config();
        config.compression = None;
        let mut sink = S3Sink::new(config);
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert!(reqs[0].key.ends_with(".json"));
    }

    #[test]
    fn test_bucket_and_region() {
        let mut sink = S3Sink::new(test_config());
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].bucket, "my-bucket");
        assert_eq!(reqs[0].region, "us-east-1");
    }
}
