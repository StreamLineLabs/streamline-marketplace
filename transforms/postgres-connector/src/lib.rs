//! PostgreSQL Connector — sink for writing stream data to PostgreSQL tables.
//!
//! This transform prepares messages for PostgreSQL delivery by:
//! - Mapping JSON fields to SQL columns
//! - Building INSERT or UPSERT (ON CONFLICT) statements
//! - Batching rows for efficient execution
//! - Supporting schema and table configuration
//!
//! The host runtime handles the actual database connection; this module
//! produces SQL statement envelopes for execution.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// -- Configuration --

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PostgresConnectorConfig {
    /// PostgreSQL connection URL.
    #[serde(default = "default_connection_url")]
    pub connection_url: String,
    /// Target table name.
    pub table: String,
    /// Optional schema name (defaults to "public").
    #[serde(default = "default_schema")]
    pub schema: String,
    /// Write mode: insert or upsert.
    #[serde(default)]
    pub mode: WriteMode,
    /// For upsert mode: column(s) that form the conflict target.
    #[serde(default)]
    pub conflict_columns: Vec<String>,
    /// Column mapping: JSON field → SQL column. If empty, uses all JSON keys.
    #[serde(default)]
    pub column_mapping: Vec<ColumnMapping>,
    /// Maximum batch size before auto-flush.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Include metadata columns (streamline_topic, streamline_offset, streamline_timestamp).
    #[serde(default)]
    pub include_metadata: bool,
}

fn default_connection_url() -> String {
    "postgresql://localhost:5432/streamline".to_string()
}
fn default_schema() -> String { "public".to_string() }
fn default_batch_size() -> usize { 100 }

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WriteMode {
    Insert,
    Upsert,
}

impl Default for WriteMode {
    fn default() -> Self { WriteMode::Insert }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ColumnMapping {
    /// JSON field path (dot-notation).
    pub field: String,
    /// SQL column name.
    pub column: String,
    /// SQL type hint (e.g., "TEXT", "INTEGER", "JSONB").
    #[serde(default = "default_sql_type")]
    pub sql_type: String,
}

fn default_sql_type() -> String { "TEXT".to_string() }

impl Default for PostgresConnectorConfig {
    fn default() -> Self {
        Self {
            connection_url: default_connection_url(),
            table: String::new(),
            schema: default_schema(),
            mode: WriteMode::Insert,
            conflict_columns: Vec::new(),
            column_mapping: Vec::new(),
            batch_size: default_batch_size(),
            include_metadata: false,
        }
    }
}

// -- SQL Statement Envelope --

/// A SQL statement produced by the sink for the host to execute.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SqlStatement {
    pub connection_url: String,
    pub sql: String,
    pub params: Vec<Vec<String>>,
}

// -- Sink Implementation --

#[derive(Debug)]
pub struct PostgresConnector {
    config: PostgresConnectorConfig,
    buffer: Vec<Value>,
    total_sent: u64,
}

impl PostgresConnector {
    pub fn new(config: PostgresConnectorConfig) -> Self {
        Self {
            config,
            buffer: Vec::new(),
            total_sent: 0,
        }
    }

    /// Create from a JSON configuration string.
    pub fn from_config_str(json: &str) -> Result<Self, String> {
        let config: PostgresConnectorConfig = serde_json::from_str(json)
            .map_err(|e| format!("Invalid config: {e}"))?;
        if config.table.is_empty() {
            return Err("table is required".to_string());
        }
        if config.mode == WriteMode::Upsert && config.conflict_columns.is_empty() {
            return Err("conflict_columns required for upsert mode".to_string());
        }
        Ok(Self::new(config))
    }

    pub fn name(&self) -> &str {
        "postgres-connector"
    }

    /// Add records to the buffer.
    pub fn put(&mut self, records: Vec<Vec<u8>>) {
        for record in records {
            let value = match serde_json::from_slice::<Value>(&record) {
                Ok(v) => v,
                Err(_) => {
                    let s = String::from_utf8_lossy(&record).into_owned();
                    serde_json::json!({"_raw": s})
                }
            };
            self.buffer.push(value);
        }
    }

    /// Flush the buffer and produce SQL statement envelopes.
    pub fn flush(&mut self) -> Result<Vec<SqlStatement>, String> {
        if self.buffer.is_empty() {
            return Ok(Vec::new());
        }

        let mut statements = Vec::new();

        for chunk in self.buffer.chunks(self.config.batch_size.max(1)) {
            let stmt = self.build_batch_statement(chunk)?;
            statements.push(stmt);
        }

        self.total_sent += self.buffer.len() as u64;
        self.buffer.clear();
        Ok(statements)
    }

    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }

    pub fn total_sent(&self) -> u64 {
        self.total_sent
    }

    pub fn should_flush(&self) -> bool {
        self.buffer.len() >= self.config.batch_size
    }

    // -- SQL Generation --

    fn build_batch_statement(&self, records: &[Value]) -> Result<SqlStatement, String> {
        if records.is_empty() {
            return Err("Empty batch".to_string());
        }

        let columns = self.resolve_columns(&records[0]);
        let table = format!("{}.{}", self.config.schema, self.config.table);
        let col_names = columns.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(", ");

        let mut params = Vec::new();
        let mut value_clauses = Vec::new();

        for (row_idx, record) in records.iter().enumerate() {
            let row_values = self.extract_row(&columns, record);
            let placeholders: Vec<String> = (0..columns.len())
                .map(|col_idx| format!("${}", row_idx * columns.len() + col_idx + 1))
                .collect();
            value_clauses.push(format!("({})", placeholders.join(", ")));
            params.push(row_values);
        }

        let values_str = value_clauses.join(", ");

        let sql = match self.config.mode {
            WriteMode::Insert => {
                format!("INSERT INTO {table} ({col_names}) VALUES {values_str}")
            }
            WriteMode::Upsert => {
                let conflict = self.config.conflict_columns.join(", ");
                let update_cols: Vec<String> = columns.iter()
                    .filter(|c| !self.config.conflict_columns.contains(c))
                    .map(|c| format!("{c} = EXCLUDED.{c}"))
                    .collect();
                let update_clause = if update_cols.is_empty() {
                    "DO NOTHING".to_string()
                } else {
                    format!("DO UPDATE SET {}", update_cols.join(", "))
                };
                format!(
                    "INSERT INTO {table} ({col_names}) VALUES {values_str} ON CONFLICT ({conflict}) {update_clause}"
                )
            }
        };

        Ok(SqlStatement {
            connection_url: self.config.connection_url.clone(),
            sql,
            params,
        })
    }

    fn resolve_columns(&self, sample: &Value) -> Vec<String> {
        if !self.config.column_mapping.is_empty() {
            return self.config.column_mapping.iter().map(|m| m.column.clone()).collect();
        }
        // Auto-detect columns from JSON keys
        match sample.as_object() {
            Some(obj) => obj.keys().cloned().collect(),
            None => vec!["value".to_string()],
        }
    }

    fn extract_row(&self, columns: &[String], record: &Value) -> Vec<String> {
        if !self.config.column_mapping.is_empty() {
            return self.config.column_mapping.iter().map(|mapping| {
                extract_json_field(record, &mapping.field)
            }).collect();
        }
        // Auto-extract by column name
        columns.iter().map(|col| {
            extract_json_field(record, col)
        }).collect()
    }
}

fn extract_json_field(record: &Value, field: &str) -> String {
    let mut current = record;
    for part in field.split('.') {
        match current.get(part) {
            Some(v) => current = v,
            None => return String::new(),
        }
    }
    match current {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

// -- Tests --

#[cfg(test)]
mod tests {
    use super::*;

    fn insert_config() -> PostgresConnectorConfig {
        PostgresConnectorConfig {
            table: "events".to_string(),
            ..Default::default()
        }
    }

    fn upsert_config() -> PostgresConnectorConfig {
        PostgresConnectorConfig {
            table: "users".to_string(),
            mode: WriteMode::Upsert,
            conflict_columns: vec!["id".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn test_default_config() {
        let config = PostgresConnectorConfig::default();
        assert_eq!(config.schema, "public");
        assert_eq!(config.mode, WriteMode::Insert);
        assert!(config.table.is_empty());
        assert_eq!(config.batch_size, 100);
    }

    #[test]
    fn test_from_config_str() {
        let json = r#"{"table":"events"}"#;
        let sink = PostgresConnector::from_config_str(json).unwrap();
        assert_eq!(sink.name(), "postgres-connector");
    }

    #[test]
    fn test_from_config_str_missing_table() {
        let json = r#"{"mode":"insert"}"#;
        let err = PostgresConnector::from_config_str(json).unwrap_err();
        assert!(err.contains("table") || err.contains("missing field"), "unexpected error: {err}");
    }

    #[test]
    fn test_from_config_str_upsert_missing_conflict() {
        let json = r#"{"table":"users","mode":"upsert"}"#;
        let err = PostgresConnector::from_config_str(json).unwrap_err();
        assert!(err.contains("conflict_columns required"));
    }

    #[test]
    fn test_insert_statement() {
        let mut sink = PostgresConnector::new(insert_config());
        sink.put(vec![br#"{"name":"Alice","age":"30"}"#.to_vec()]);
        let stmts = sink.flush().unwrap();
        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].sql.starts_with("INSERT INTO public.events"));
        assert!(stmts[0].sql.contains("VALUES"));
        assert!(!stmts[0].sql.contains("ON CONFLICT"));
    }

    #[test]
    fn test_upsert_statement() {
        let mut sink = PostgresConnector::new(upsert_config());
        sink.put(vec![br#"{"id":"u1","name":"Alice","email":"a@b.com"}"#.to_vec()]);
        let stmts = sink.flush().unwrap();
        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].sql.contains("ON CONFLICT (id)"));
        assert!(stmts[0].sql.contains("DO UPDATE SET"));
    }

    #[test]
    fn test_upsert_all_conflict_columns() {
        let config = PostgresConnectorConfig {
            table: "single_col".to_string(),
            mode: WriteMode::Upsert,
            conflict_columns: vec!["id".to_string()],
            ..Default::default()
        };
        let mut sink = PostgresConnector::new(config);
        sink.put(vec![br#"{"id":"u1"}"#.to_vec()]);
        let stmts = sink.flush().unwrap();
        assert!(stmts[0].sql.contains("DO NOTHING"));
    }

    #[test]
    fn test_column_mapping() {
        let config = PostgresConnectorConfig {
            table: "events".to_string(),
            column_mapping: vec![
                ColumnMapping { field: "user.name".to_string(), column: "username".to_string(), sql_type: "TEXT".to_string() },
                ColumnMapping { field: "action".to_string(), column: "action_type".to_string(), sql_type: "TEXT".to_string() },
            ],
            ..Default::default()
        };
        let mut sink = PostgresConnector::new(config);
        sink.put(vec![br#"{"user":{"name":"Bob"},"action":"click"}"#.to_vec()]);
        let stmts = sink.flush().unwrap();
        assert!(stmts[0].sql.contains("username, action_type"));
        assert_eq!(stmts[0].params[0][0], "Bob");
        assert_eq!(stmts[0].params[0][1], "click");
    }

    #[test]
    fn test_batch_insert() {
        let mut config = insert_config();
        config.batch_size = 2;
        let mut sink = PostgresConnector::new(config);
        sink.put(vec![
            br#"{"id":"1","v":"a"}"#.to_vec(),
            br#"{"id":"2","v":"b"}"#.to_vec(),
            br#"{"id":"3","v":"c"}"#.to_vec(),
        ]);
        let stmts = sink.flush().unwrap();
        assert_eq!(stmts.len(), 2); // 2 records + 1 record
        assert_eq!(sink.total_sent(), 3);
    }

    #[test]
    fn test_flush_empty() {
        let mut sink = PostgresConnector::new(insert_config());
        let stmts = sink.flush().unwrap();
        assert!(stmts.is_empty());
    }

    #[test]
    fn test_non_json_record() {
        let mut sink = PostgresConnector::new(insert_config());
        sink.put(vec![b"not json".to_vec()]);
        let stmts = sink.flush().unwrap();
        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].sql.contains("_raw"));
    }

    #[test]
    fn test_should_flush() {
        let mut config = insert_config();
        config.batch_size = 2;
        let mut sink = PostgresConnector::new(config);
        assert!(!sink.should_flush());
        sink.put(vec![br#"{"x":1}"#.to_vec(), br#"{"x":2}"#.to_vec()]);
        assert!(sink.should_flush());
    }

    #[test]
    fn test_custom_schema() {
        let config = PostgresConnectorConfig {
            table: "events".to_string(),
            schema: "analytics".to_string(),
            ..Default::default()
        };
        let mut sink = PostgresConnector::new(config);
        sink.put(vec![br#"{"k":"v"}"#.to_vec()]);
        let stmts = sink.flush().unwrap();
        assert!(stmts[0].sql.contains("analytics.events"));
    }

    #[test]
    fn test_parameterized_placeholders() {
        let mut sink = PostgresConnector::new(insert_config());
        sink.put(vec![br#"{"a":"1","b":"2"}"#.to_vec()]);
        let stmts = sink.flush().unwrap();
        assert!(stmts[0].sql.contains("$1") && stmts[0].sql.contains("$2"));
    }
}
