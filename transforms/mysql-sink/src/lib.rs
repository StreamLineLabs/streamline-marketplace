//! MySQL Sink Connector — writes data to MySQL via INSERT, REPLACE, or INSERT IGNORE statements.
//!
//! Produces MySQL SQL statement envelopes. Supports:
//! - INSERT, REPLACE, and INSERT IGNORE write modes
//! - Explicit column list or auto-inference from JSON keys
//! - Batch inserts with multi-row VALUES
//! - Configurable batch size

use serde::{Deserialize, Serialize};
use serde_json::Value;

// -- Configuration --

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MySqlSinkConfig {
    /// MySQL connection URL.
    #[serde(default = "default_url")]
    pub url: String,
    /// Target table name.
    pub table: String,
    /// Write mode.
    #[serde(default)]
    pub write_mode: WriteMode,
    /// Column names to write. If empty, inferred from first record's JSON keys.
    #[serde(default)]
    pub columns: Vec<String>,
    /// Maximum rows per batch INSERT.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

fn default_url() -> String { "mysql://localhost:3306/streamline".to_string() }
fn default_batch_size() -> usize { 500 }

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WriteMode {
    Insert,
    Replace,
    InsertIgnore,
}

impl Default for WriteMode {
    fn default() -> Self { WriteMode::Insert }
}

impl Default for MySqlSinkConfig {
    fn default() -> Self {
        Self {
            url: default_url(),
            table: String::new(),
            write_mode: WriteMode::Insert,
            columns: Vec::new(),
            batch_size: default_batch_size(),
        }
    }
}

// -- Statement Envelope --

/// A MySQL statement for the host to execute.
#[derive(Debug, Clone, Serialize)]
pub struct MySqlStatement {
    pub url: String,
    pub sql: String,
    pub values: Vec<Vec<Value>>,
    pub record_count: usize,
}

// -- Sink Implementation --

#[derive(Debug)]
pub struct MySqlSink {
    config: MySqlSinkConfig,
    buffer: Vec<Value>,
    total_sent: u64,
}

impl MySqlSink {
    pub fn new(config: MySqlSinkConfig) -> Self {
        Self { config, buffer: Vec::new(), total_sent: 0 }
    }

    pub fn from_config_str(json: &str) -> Result<Self, String> {
        let config: MySqlSinkConfig = serde_json::from_str(json)
            .map_err(|e| format!("Invalid config: {e}"))?;
        if config.table.is_empty() { return Err("table is required".to_string()); }
        Ok(Self::new(config))
    }

    pub fn name(&self) -> &str { "mysql-sink" }

    pub fn put(&mut self, records: Vec<Vec<u8>>) {
        for record in records {
            let value = serde_json::from_slice::<Value>(&record)
                .unwrap_or_else(|_| serde_json::json!({ "_raw": String::from_utf8_lossy(&record).into_owned() }));
            self.buffer.push(value);
        }
    }

    pub fn flush(&mut self) -> Result<Vec<MySqlStatement>, String> {
        if self.buffer.is_empty() { return Ok(Vec::new()); }

        let mut statements = Vec::new();
        for chunk in self.buffer.chunks(self.config.batch_size.max(1)) {
            statements.push(self.build_statement(chunk)?);
        }

        self.total_sent += self.buffer.len() as u64;
        self.buffer.clear();
        Ok(statements)
    }

    pub fn buffered_count(&self) -> usize { self.buffer.len() }
    pub fn total_sent(&self) -> u64 { self.total_sent }
    pub fn should_flush(&self) -> bool { self.buffer.len() >= self.config.batch_size }

    fn build_statement(&self, records: &[Value]) -> Result<MySqlStatement, String> {
        if records.is_empty() { return Err("Empty batch".to_string()); }

        let columns = self.resolve_columns(&records[0]);
        let col_names = columns.iter().map(|c| format!("`{c}`")).collect::<Vec<_>>().join(", ");

        let keyword = match self.config.write_mode {
            WriteMode::Insert => "INSERT INTO",
            WriteMode::Replace => "REPLACE INTO",
            WriteMode::InsertIgnore => "INSERT IGNORE INTO",
        };

        let mut values = Vec::new();
        let mut placeholders = Vec::new();

        for record in records {
            let row = self.extract_row(&columns, record);
            let ph = vec!["?"; columns.len()].join(", ");
            placeholders.push(format!("({ph})"));
            values.push(row);
        }

        let sql = format!(
            "{keyword} `{}` ({col_names}) VALUES {}",
            self.config.table,
            placeholders.join(", "),
        );

        Ok(MySqlStatement {
            url: self.config.url.clone(),
            sql,
            values,
            record_count: records.len(),
        })
    }

    fn resolve_columns(&self, sample: &Value) -> Vec<String> {
        if !self.config.columns.is_empty() {
            return self.config.columns.clone();
        }
        match sample.as_object() {
            Some(obj) => obj.keys().cloned().collect(),
            None => vec!["value".to_string()],
        }
    }

    fn extract_row(&self, columns: &[String], record: &Value) -> Vec<Value> {
        columns.iter().map(|col| extract_field_value(record, col)).collect()
    }
}

fn extract_field_value(record: &Value, field: &str) -> Value {
    let mut current = record;
    for part in field.split('.') {
        match current.get(part) {
            Some(v) => current = v,
            None => return Value::Null,
        }
    }
    current.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> MySqlSinkConfig {
        MySqlSinkConfig { table: "events".to_string(), ..Default::default() }
    }

    #[test]
    fn test_default_config() {
        let c = MySqlSinkConfig::default();
        assert_eq!(c.write_mode, WriteMode::Insert);
        assert_eq!(c.batch_size, 500);
        assert!(c.columns.is_empty());
    }

    #[test]
    fn test_from_config_str_missing_table() {
        assert!(MySqlSink::from_config_str(r#"{}"#).is_err());
    }

    #[test]
    fn test_from_config_str_valid() {
        let json = r#"{"table":"events","batch_size":100}"#;
        let sink = MySqlSink::from_config_str(json).unwrap();
        assert_eq!(sink.name(), "mysql-sink");
    }

    #[test]
    fn test_insert_sql() {
        let mut sink = MySqlSink::new(test_config());
        sink.put(vec![br#"{"name":"Alice","age":30}"#.to_vec()]);
        let stmts = sink.flush().unwrap();
        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].sql.starts_with("INSERT INTO `events`"));
        assert!(stmts[0].sql.contains("VALUES"));
        assert_eq!(stmts[0].record_count, 1);
    }

    #[test]
    fn test_replace_sql() {
        let mut config = test_config();
        config.write_mode = WriteMode::Replace;
        let mut sink = MySqlSink::new(config);
        sink.put(vec![br#"{"id":"1","v":"x"}"#.to_vec()]);
        let stmts = sink.flush().unwrap();
        assert!(stmts[0].sql.starts_with("REPLACE INTO"));
    }

    #[test]
    fn test_insert_ignore_sql() {
        let mut config = test_config();
        config.write_mode = WriteMode::InsertIgnore;
        let mut sink = MySqlSink::new(config);
        sink.put(vec![br#"{"id":"1","v":"x"}"#.to_vec()]);
        let stmts = sink.flush().unwrap();
        assert!(stmts[0].sql.starts_with("INSERT IGNORE INTO"));
    }

    #[test]
    fn test_column_mapping() {
        let mut config = test_config();
        config.columns = vec!["name".to_string(), "age".to_string()];
        let mut sink = MySqlSink::new(config);
        sink.put(vec![br#"{"name":"Bob","age":25,"extra":"ignored"}"#.to_vec()]);
        let stmts = sink.flush().unwrap();
        assert!(stmts[0].sql.contains("`name`"));
        assert!(stmts[0].sql.contains("`age`"));
        assert!(!stmts[0].sql.contains("`extra`"));
        assert_eq!(stmts[0].values[0][0], Value::String("Bob".to_string()));
        assert_eq!(stmts[0].values[0][1], serde_json::json!(25));
    }

    #[test]
    fn test_multi_row_values() {
        let mut sink = MySqlSink::new(test_config());
        sink.put(vec![
            br#"{"id":"1","v":"a"}"#.to_vec(),
            br#"{"id":"2","v":"b"}"#.to_vec(),
        ]);
        let stmts = sink.flush().unwrap();
        let q_count = stmts[0].sql.matches('?').count();
        assert_eq!(q_count, 4); // 2 columns × 2 rows
        assert_eq!(stmts[0].record_count, 2);
    }

    #[test]
    fn test_batch_chunking() {
        let mut config = test_config();
        config.batch_size = 2;
        let mut sink = MySqlSink::new(config);
        sink.put(vec![
            br#"{"a":"1"}"#.to_vec(),
            br#"{"a":"2"}"#.to_vec(),
            br#"{"a":"3"}"#.to_vec(),
        ]);
        let stmts = sink.flush().unwrap();
        assert_eq!(stmts.len(), 2);
        assert_eq!(sink.total_sent(), 3);
    }

    #[test]
    fn test_flush_empty() {
        let mut sink = MySqlSink::new(test_config());
        assert!(sink.flush().unwrap().is_empty());
    }

    #[test]
    fn test_backtick_escaping() {
        let mut sink = MySqlSink::new(test_config());
        sink.put(vec![br#"{"col_name":"val"}"#.to_vec()]);
        let stmts = sink.flush().unwrap();
        assert!(stmts[0].sql.contains("`col_name`"));
    }

    #[test]
    fn test_should_flush() {
        let mut config = test_config();
        config.batch_size = 2;
        let mut sink = MySqlSink::new(config);
        sink.put(vec![br#"{"x":"1"}"#.to_vec()]);
        assert!(!sink.should_flush());
        sink.put(vec![br#"{"x":"2"}"#.to_vec()]);
        assert!(sink.should_flush());
    }
}
