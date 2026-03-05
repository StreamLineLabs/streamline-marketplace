//! MongoDB Sink Connector — inserts or upserts data into MongoDB collections.
//!
//! Produces MongoDB command envelopes for the host runtime. Supports:
//! - Insert (InsertMany) and Upsert (BulkUpsert) write modes
//! - Configurable upsert key field for matching
//! - Batch operations with configurable batch size

use serde::{Deserialize, Serialize};
use serde_json::Value;

// -- Configuration --

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MongoDbSinkConfig {
    /// MongoDB connection URI.
    #[serde(default = "default_uri")]
    pub uri: String,
    /// Target database name.
    pub database: String,
    /// Target collection name.
    pub collection: String,
    /// Write mode.
    #[serde(default)]
    pub write_mode: WriteMode,
    /// For upsert: field to use as the match key.
    pub upsert_key_field: Option<String>,
    /// Maximum documents per batch command.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

fn default_uri() -> String { "mongodb://localhost:27017".to_string() }
fn default_batch_size() -> usize { 1000 }

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WriteMode {
    Insert,
    Upsert,
}

impl Default for WriteMode {
    fn default() -> Self { WriteMode::Insert }
}

impl Default for MongoDbSinkConfig {
    fn default() -> Self {
        Self {
            uri: default_uri(),
            database: String::new(),
            collection: String::new(),
            write_mode: WriteMode::Insert,
            upsert_key_field: None,
            batch_size: default_batch_size(),
        }
    }
}

// -- Command Envelope --

/// Operation type for MongoDB commands.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum MongoOperation {
    InsertMany,
    BulkUpsert,
}

/// A MongoDB command for the host to execute.
#[derive(Debug, Clone, Serialize)]
pub struct MongoCommand {
    pub uri: String,
    pub database: String,
    pub collection: String,
    pub operation: MongoOperation,
    pub documents: Vec<Value>,
    pub record_count: usize,
}

// -- Sink Implementation --

#[derive(Debug)]
pub struct MongoDbSink {
    config: MongoDbSinkConfig,
    buffer: Vec<Value>,
    total_sent: u64,
}

impl MongoDbSink {
    pub fn new(config: MongoDbSinkConfig) -> Self {
        Self { config, buffer: Vec::new(), total_sent: 0 }
    }

    pub fn from_config_str(json: &str) -> Result<Self, String> {
        let config: MongoDbSinkConfig = serde_json::from_str(json)
            .map_err(|e| format!("Invalid config: {e}"))?;
        if config.database.is_empty() { return Err("database is required".to_string()); }
        if config.collection.is_empty() { return Err("collection is required".to_string()); }
        if config.write_mode == WriteMode::Upsert && config.upsert_key_field.is_none() {
            return Err("upsert_key_field is required for upsert mode".to_string());
        }
        Ok(Self::new(config))
    }

    pub fn name(&self) -> &str { "mongodb-sink" }

    pub fn put(&mut self, records: Vec<Vec<u8>>) {
        for record in records {
            let value = match serde_json::from_slice::<Value>(&record) {
                Ok(v) => v,
                Err(_) => serde_json::json!({ "_raw": String::from_utf8_lossy(&record).into_owned() }),
            };
            self.buffer.push(value);
        }
    }

    pub fn flush(&mut self) -> Result<Vec<MongoCommand>, String> {
        if self.buffer.is_empty() { return Ok(Vec::new()); }

        let mut commands = Vec::new();
        for chunk in self.buffer.chunks(self.config.batch_size.max(1)) {
            commands.push(self.build_command(chunk));
        }

        self.total_sent += self.buffer.len() as u64;
        self.buffer.clear();
        Ok(commands)
    }

    pub fn buffered_count(&self) -> usize { self.buffer.len() }
    pub fn total_sent(&self) -> u64 { self.total_sent }
    pub fn should_flush(&self) -> bool { self.buffer.len() >= self.config.batch_size }

    fn build_command(&self, records: &[Value]) -> MongoCommand {
        let operation = match self.config.write_mode {
            WriteMode::Insert => MongoOperation::InsertMany,
            WriteMode::Upsert => MongoOperation::BulkUpsert,
        };

        MongoCommand {
            uri: self.config.uri.clone(),
            database: self.config.database.clone(),
            collection: self.config.collection.clone(),
            operation,
            documents: records.to_vec(),
            record_count: records.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insert_config() -> MongoDbSinkConfig {
        MongoDbSinkConfig {
            database: "mydb".to_string(),
            collection: "events".to_string(),
            ..Default::default()
        }
    }

    fn upsert_config() -> MongoDbSinkConfig {
        MongoDbSinkConfig {
            database: "mydb".to_string(),
            collection: "users".to_string(),
            write_mode: WriteMode::Upsert,
            upsert_key_field: Some("user_id".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_default_config() {
        let c = MongoDbSinkConfig::default();
        assert_eq!(c.uri, "mongodb://localhost:27017");
        assert_eq!(c.write_mode, WriteMode::Insert);
        assert_eq!(c.batch_size, 1000);
        assert!(c.upsert_key_field.is_none());
    }

    #[test]
    fn test_from_config_str_missing_db() {
        assert!(MongoDbSink::from_config_str(r#"{"collection":"x"}"#).is_err());
    }

    #[test]
    fn test_from_config_str_missing_collection() {
        assert!(MongoDbSink::from_config_str(r#"{"database":"x"}"#).is_err());
    }

    #[test]
    fn test_from_config_str_upsert_missing_key() {
        let json = r#"{"database":"db","collection":"c","write_mode":"upsert"}"#;
        assert!(MongoDbSink::from_config_str(json).unwrap_err().contains("upsert_key_field"));
    }

    #[test]
    fn test_insert_mode() {
        let mut sink = MongoDbSink::new(insert_config());
        sink.put(vec![br#"{"name":"Alice"}"#.to_vec()]);
        let cmds = sink.flush().unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].operation, MongoOperation::InsertMany);
        assert_eq!(cmds[0].database, "mydb");
        assert_eq!(cmds[0].collection, "events");
        assert_eq!(cmds[0].documents.len(), 1);
        assert_eq!(cmds[0].record_count, 1);
    }

    #[test]
    fn test_upsert_mode() {
        let mut sink = MongoDbSink::new(upsert_config());
        sink.put(vec![br#"{"user_id":"u1","name":"Bob"}"#.to_vec()]);
        let cmds = sink.flush().unwrap();
        assert_eq!(cmds[0].operation, MongoOperation::BulkUpsert);
        assert_eq!(cmds[0].documents.len(), 1);
        assert_eq!(cmds[0].record_count, 1);
        assert_eq!(cmds[0].documents[0]["user_id"], "u1");
    }

    #[test]
    fn test_batch_chunking() {
        let mut config = insert_config();
        config.batch_size = 2;
        let mut sink = MongoDbSink::new(config);
        sink.put(vec![
            br#"{"a":1}"#.to_vec(),
            br#"{"b":2}"#.to_vec(),
            br#"{"c":3}"#.to_vec(),
        ]);
        let cmds = sink.flush().unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].documents.len(), 2);
        assert_eq!(cmds[0].record_count, 2);
        assert_eq!(cmds[1].documents.len(), 1);
        assert_eq!(cmds[1].record_count, 1);
    }

    #[test]
    fn test_flush_empty() {
        let mut sink = MongoDbSink::new(insert_config());
        assert!(sink.flush().unwrap().is_empty());
    }

    #[test]
    fn test_total_sent() {
        let mut sink = MongoDbSink::new(insert_config());
        sink.put(vec![br#"{"x":1}"#.to_vec(), br#"{"x":2}"#.to_vec()]);
        sink.flush().unwrap();
        assert_eq!(sink.total_sent(), 2);
        assert_eq!(sink.buffered_count(), 0);
    }

    #[test]
    fn test_uri_passthrough() {
        let config = MongoDbSinkConfig {
            uri: "mongodb://custom:27017".to_string(),
            database: "db".to_string(),
            collection: "c".to_string(),
            ..Default::default()
        };
        let mut sink = MongoDbSink::new(config);
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        let cmds = sink.flush().unwrap();
        assert_eq!(cmds[0].uri, "mongodb://custom:27017");
    }

    #[test]
    fn test_should_flush() {
        let mut config = insert_config();
        config.batch_size = 2;
        let mut sink = MongoDbSink::new(config);
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        assert!(!sink.should_flush());
        sink.put(vec![br#"{"x":2}"#.to_vec()]);
        assert!(sink.should_flush());
    }
}
