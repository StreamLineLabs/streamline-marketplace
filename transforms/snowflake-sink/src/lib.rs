//! Snowflake Sink Connector — loads data into Snowflake.
//!
//! Produces Snowflake load command envelopes. Supports:
//! - NDJSON data formatting for stage loading
//! - Configurable account, warehouse, database, schema, and table
//! - Optional stage path
//! - Configurable batch size

use serde::{Deserialize, Serialize};
use serde_json::Value;

// -- Configuration --

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SnowflakeSinkConfig {
    /// Snowflake account identifier.
    pub account: String,
    /// Warehouse name.
    pub warehouse: String,
    /// Target database.
    pub database: String,
    /// Target schema.
    pub schema: String,
    /// Target table.
    pub table: String,
    /// Optional stage path for file uploads.
    #[serde(default)]
    pub stage_path: Option<String>,
    /// Maximum records per batch.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

fn default_batch_size() -> usize { 1000 }

impl Default for SnowflakeSinkConfig {
    fn default() -> Self {
        Self {
            account: String::new(),
            warehouse: String::new(),
            database: String::new(),
            schema: String::new(),
            table: String::new(),
            stage_path: None,
            batch_size: default_batch_size(),
        }
    }
}

// -- Snowflake Load Command Envelope --

#[derive(Debug, Clone, Serialize)]
pub struct SnowflakeLoadCommand {
    pub account: String,
    pub warehouse: String,
    pub database: String,
    pub schema: String,
    pub table: String,
    pub data: String,
    pub record_count: usize,
    pub stage_path: Option<String>,
}

// -- Sink Implementation --

#[derive(Debug)]
pub struct SnowflakeSink {
    config: SnowflakeSinkConfig,
    buffer: Vec<Value>,
    total_sent: u64,
}

impl SnowflakeSink {
    pub fn new(config: SnowflakeSinkConfig) -> Self {
        Self { config, buffer: Vec::new(), total_sent: 0 }
    }

    pub fn from_config_str(json: &str) -> Result<Self, String> {
        let config: SnowflakeSinkConfig = serde_json::from_str(json)
            .map_err(|e| format!("Invalid config: {e}"))?;
        if config.account.is_empty() { return Err("account is required".to_string()); }
        if config.database.is_empty() { return Err("database is required".to_string()); }
        if config.table.is_empty() { return Err("table is required".to_string()); }
        Ok(Self::new(config))
    }

    pub fn name(&self) -> &str { "snowflake-sink" }

    pub fn put(&mut self, records: Vec<Vec<u8>>) {
        for record in records {
            let value = match serde_json::from_slice::<Value>(&record) {
                Ok(v) => v,
                Err(_) => Value::String(String::from_utf8_lossy(&record).into_owned()),
            };
            self.buffer.push(value);
        }
    }

    pub fn flush(&mut self) -> Result<Vec<SnowflakeLoadCommand>, String> {
        if self.buffer.is_empty() { return Ok(Vec::new()); }

        let mut commands = Vec::new();
        for chunk in self.buffer.chunks(self.config.batch_size.max(1)) {
            let data = self.format_ndjson(chunk)?;
            commands.push(SnowflakeLoadCommand {
                account: self.config.account.clone(),
                warehouse: self.config.warehouse.clone(),
                database: self.config.database.clone(),
                schema: self.config.schema.clone(),
                table: self.config.table.clone(),
                data,
                record_count: chunk.len(),
                stage_path: self.config.stage_path.clone(),
            });
        }

        self.total_sent += self.buffer.len() as u64;
        self.buffer.clear();
        Ok(commands)
    }

    pub fn buffered_count(&self) -> usize { self.buffer.len() }
    pub fn total_sent(&self) -> u64 { self.total_sent }
    pub fn should_flush(&self) -> bool { self.buffer.len() >= self.config.batch_size }

    fn format_ndjson(&self, records: &[Value]) -> Result<String, String> {
        let mut out = String::new();
        for r in records {
            out.push_str(&serde_json::to_string(r)
                .map_err(|e| format!("NDJSON serialization error: {e}"))?);
            out.push('\n');
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SnowflakeSinkConfig {
        SnowflakeSinkConfig {
            account: "xy12345".to_string(),
            warehouse: "compute_wh".to_string(),
            database: "analytics".to_string(),
            schema: "public".to_string(),
            table: "events".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_config_parsing() {
        let json = r#"{
            "account": "xy12345",
            "warehouse": "compute_wh",
            "database": "analytics",
            "schema": "public",
            "table": "events"
        }"#;
        let sink = SnowflakeSink::from_config_str(json).unwrap();
        assert_eq!(sink.name(), "snowflake-sink");
        assert_eq!(sink.config.batch_size, 1000);
        assert!(sink.config.stage_path.is_none());
    }

    #[test]
    fn test_config_parsing_with_stage_path() {
        let json = r#"{
            "account": "xy12345",
            "warehouse": "compute_wh",
            "database": "analytics",
            "schema": "public",
            "table": "events",
            "stage_path": "@my_stage/data"
        }"#;
        let sink = SnowflakeSink::from_config_str(json).unwrap();
        assert_eq!(sink.config.stage_path, Some("@my_stage/data".to_string()));
    }

    #[test]
    fn test_config_parsing_missing_account() {
        let json = r#"{"database":"db","table":"t","warehouse":"w","schema":"s"}"#;
        assert!(SnowflakeSink::from_config_str(json).is_err());
    }

    #[test]
    fn test_config_parsing_missing_database() {
        let json = r#"{"account":"a","table":"t","warehouse":"w","schema":"s"}"#;
        assert!(SnowflakeSink::from_config_str(json).is_err());
    }

    #[test]
    fn test_config_parsing_missing_table() {
        let json = r#"{"account":"a","database":"db","warehouse":"w","schema":"s"}"#;
        assert!(SnowflakeSink::from_config_str(json).is_err());
    }

    #[test]
    fn test_default_batch_size() {
        let c = SnowflakeSinkConfig::default();
        assert_eq!(c.batch_size, 1000);
    }

    #[test]
    fn test_ndjson_format() {
        let mut sink = SnowflakeSink::new(test_config());
        sink.put(vec![
            br#"{"event":"click"}"#.to_vec(),
            br#"{"event":"view"}"#.to_vec(),
        ]);
        let cmds = sink.flush().unwrap();
        assert_eq!(cmds.len(), 1);
        let lines: Vec<&str> = cmds[0].data.trim().split('\n').collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            assert!(serde_json::from_str::<Value>(line).is_ok());
        }
    }

    #[test]
    fn test_ndjson_single_record() {
        let mut sink = SnowflakeSink::new(test_config());
        sink.put(vec![br#"{"a":1}"#.to_vec()]);
        let cmds = sink.flush().unwrap();
        assert_eq!(cmds[0].data, "{\"a\":1}\n");
    }

    #[test]
    fn test_batch_chunking() {
        let mut config = test_config();
        config.batch_size = 2;
        let mut sink = SnowflakeSink::new(config);
        sink.put(vec![
            br#"{"a":1}"#.to_vec(),
            br#"{"b":2}"#.to_vec(),
            br#"{"c":3}"#.to_vec(),
        ]);
        let cmds = sink.flush().unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].record_count, 2);
        assert_eq!(cmds[1].record_count, 1);
    }

    #[test]
    fn test_command_fields() {
        let mut config = test_config();
        config.stage_path = Some("@my_stage/data".to_string());
        let mut sink = SnowflakeSink::new(config);
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        let cmds = sink.flush().unwrap();
        assert_eq!(cmds[0].account, "xy12345");
        assert_eq!(cmds[0].warehouse, "compute_wh");
        assert_eq!(cmds[0].database, "analytics");
        assert_eq!(cmds[0].schema, "public");
        assert_eq!(cmds[0].table, "events");
        assert_eq!(cmds[0].stage_path, Some("@my_stage/data".to_string()));
    }

    #[test]
    fn test_flush_empty() {
        let mut sink = SnowflakeSink::new(test_config());
        assert!(sink.flush().unwrap().is_empty());
    }

    #[test]
    fn test_total_sent() {
        let mut sink = SnowflakeSink::new(test_config());
        sink.put(vec![br#"{"x":1}"#.to_vec(), br#"{"y":2}"#.to_vec()]);
        sink.flush().unwrap();
        assert_eq!(sink.total_sent(), 2);
        assert_eq!(sink.buffered_count(), 0);
    }

    #[test]
    fn test_should_flush() {
        let mut config = test_config();
        config.batch_size = 2;
        let mut sink = SnowflakeSink::new(config);
        assert!(!sink.should_flush());
        sink.put(vec![br#"{"a":1}"#.to_vec()]);
        assert!(!sink.should_flush());
        sink.put(vec![br#"{"b":2}"#.to_vec()]);
        assert!(sink.should_flush());
    }
}
