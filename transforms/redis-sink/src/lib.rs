//! Redis Sink Connector — writes data to Redis via SET, XADD, LPUSH, or PUBLISH.
//!
//! This transform prepares messages for Redis delivery by:
//! - Extracting keys from JSON fields with optional prefix
//! - Building typed Redis command envelopes (SET, XADD, LPUSH, PUBLISH)
//! - Supporting TTL for SET commands
//! - Batching commands into a single envelope for efficient pipeline execution
//!
//! The host runtime handles the actual Redis connection; this module produces
//! command envelopes for execution.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

// -- Configuration --

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedisSinkConfig {
    /// Redis connection URL.
    #[serde(default = "default_url")]
    pub url: String,
    /// Redis command type to execute for each record.
    #[serde(default)]
    pub command: RedisCommandType,
    /// JSON field to use as the Redis key (for SET/LPUSH).
    pub key_field: Option<String>,
    /// Static key prefix prepended to extracted keys.
    pub key_prefix: Option<String>,
    /// TTL in seconds for SET commands.
    pub ttl_secs: Option<u64>,
    /// Redis stream name for XADD.
    pub stream_name: Option<String>,
    /// Redis channel for PUBLISH.
    pub channel: Option<String>,
    /// Maximum records before auto-flush.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

fn default_url() -> String { "redis://127.0.0.1:6379".to_string() }
fn default_batch_size() -> usize { 100 }

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RedisCommandType {
    Set,
    Xadd,
    Lpush,
    Publish,
}

impl Default for RedisCommandType {
    fn default() -> Self { RedisCommandType::Set }
}

impl Default for RedisSinkConfig {
    fn default() -> Self {
        Self {
            url: default_url(),
            command: RedisCommandType::Set,
            key_field: None,
            key_prefix: None,
            ttl_secs: None,
            stream_name: None,
            channel: None,
            batch_size: default_batch_size(),
        }
    }
}

// -- Redis Command Envelopes --

/// A typed Redis command produced by the sink.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RedisCommand {
    Set { key: String, value: String, ttl: Option<u64> },
    Xadd { stream: String, fields: BTreeMap<String, String> },
    Lpush { key: String, value: String },
    Publish { channel: String, message: String },
}

/// A batch of Redis commands for the host to execute via pipeline.
#[derive(Debug, Clone, Serialize)]
pub struct RedisCommandEnvelope {
    pub url: String,
    pub commands: Vec<RedisCommand>,
}

// -- Sink Implementation --

#[derive(Debug)]
pub struct RedisSink {
    config: RedisSinkConfig,
    buffer: Vec<Value>,
    total_sent: u64,
}

impl RedisSink {
    pub fn new(config: RedisSinkConfig) -> Self {
        Self { config, buffer: Vec::new(), total_sent: 0 }
    }

    pub fn from_config_str(json: &str) -> Result<Self, String> {
        let config: RedisSinkConfig = serde_json::from_str(json)
            .map_err(|e| format!("Invalid config: {e}"))?;

        match config.command {
            RedisCommandType::Set if config.key_field.is_none() => {
                return Err("key_field is required for SET command".to_string());
            }
            RedisCommandType::Lpush if config.key_field.is_none() => {
                return Err("key_field is required for LPUSH command".to_string());
            }
            RedisCommandType::Publish if config.channel.is_none() => {
                return Err("channel is required for PUBLISH command".to_string());
            }
            RedisCommandType::Xadd if config.stream_name.is_none() => {
                return Err("stream_name is required for XADD command".to_string());
            }
            _ => {}
        }

        Ok(Self::new(config))
    }

    pub fn name(&self) -> &str { "redis-sink" }

    pub fn put(&mut self, records: Vec<Vec<u8>>) {
        for record in records {
            let value = match serde_json::from_slice::<Value>(&record) {
                Ok(v) => v,
                Err(_) => Value::String(String::from_utf8_lossy(&record).into_owned()),
            };
            self.buffer.push(value);
        }
    }

    pub fn flush(&mut self) -> Result<Vec<RedisCommandEnvelope>, String> {
        if self.buffer.is_empty() {
            return Ok(Vec::new());
        }

        let mut commands = Vec::new();
        for record in &self.buffer {
            let cmd = match self.config.command {
                RedisCommandType::Set => self.build_set(record)?,
                RedisCommandType::Xadd => self.build_xadd(record)?,
                RedisCommandType::Lpush => self.build_lpush(record)?,
                RedisCommandType::Publish => self.build_publish(record)?,
            };
            commands.push(cmd);
        }

        let envelope = RedisCommandEnvelope {
            url: self.config.url.clone(),
            commands,
        };

        self.total_sent += self.buffer.len() as u64;
        self.buffer.clear();
        Ok(vec![envelope])
    }

    pub fn buffered_count(&self) -> usize { self.buffer.len() }
    pub fn total_sent(&self) -> u64 { self.total_sent }
    pub fn should_flush(&self) -> bool { self.buffer.len() >= self.config.batch_size }

    // -- Command Builders --

    fn build_set(&self, record: &Value) -> Result<RedisCommand, String> {
        let key = self.extract_key(record)?;
        let value = serde_json::to_string(record)
            .map_err(|e| format!("Serialization error: {e}"))?;
        Ok(RedisCommand::Set { key, value, ttl: self.config.ttl_secs })
    }

    fn build_xadd(&self, record: &Value) -> Result<RedisCommand, String> {
        let stream = self.config.stream_name.clone()
            .ok_or_else(|| "stream_name is required for XADD".to_string())?;
        let mut fields = BTreeMap::new();
        match record.as_object() {
            Some(obj) => {
                for (k, v) in obj {
                    let val = match v {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    fields.insert(k.clone(), val);
                }
            }
            None => {
                let val = serde_json::to_string(record)
                    .map_err(|e| format!("Serialization error: {e}"))?;
                fields.insert("data".to_string(), val);
            }
        }
        Ok(RedisCommand::Xadd { stream, fields })
    }

    fn build_lpush(&self, record: &Value) -> Result<RedisCommand, String> {
        let key = self.extract_key(record)?;
        let value = serde_json::to_string(record)
            .map_err(|e| format!("Serialization error: {e}"))?;
        Ok(RedisCommand::Lpush { key, value })
    }

    fn build_publish(&self, record: &Value) -> Result<RedisCommand, String> {
        let channel = self.config.channel.clone()
            .ok_or_else(|| "channel is required for PUBLISH".to_string())?;
        let message = serde_json::to_string(record)
            .map_err(|e| format!("Serialization error: {e}"))?;
        Ok(RedisCommand::Publish { channel, message })
    }

    fn extract_key(&self, record: &Value) -> Result<String, String> {
        let raw_key = match &self.config.key_field {
            Some(field) => {
                let mut current = record;
                for part in field.split('.') {
                    current = current.get(part)
                        .ok_or_else(|| format!("Key field '{field}' not found in record"))?;
                }
                match current {
                    Value::String(s) => s.clone(),
                    other => other.to_string().trim_matches('"').to_string(),
                }
            }
            None => serde_json::to_string(record).unwrap_or_default(),
        };

        match &self.config.key_prefix {
            Some(prefix) => Ok(format!("{prefix}{raw_key}")),
            None => Ok(raw_key),
        }
    }
}

// -- Tests --

#[cfg(test)]
mod tests {
    use super::*;

    fn set_config() -> RedisSinkConfig {
        RedisSinkConfig {
            command: RedisCommandType::Set,
            key_field: Some("id".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_default_config() {
        let config = RedisSinkConfig::default();
        assert_eq!(config.url, "redis://127.0.0.1:6379");
        assert_eq!(config.command, RedisCommandType::Set);
        assert!(config.key_field.is_none());
        assert!(config.key_prefix.is_none());
        assert!(config.ttl_secs.is_none());
        assert_eq!(config.batch_size, 100);
    }

    #[test]
    fn test_from_config_str_set_valid() {
        let json = r#"{"command":"set","key_field":"id"}"#;
        let sink = RedisSink::from_config_str(json).unwrap();
        assert_eq!(sink.name(), "redis-sink");
    }

    #[test]
    fn test_from_config_str_set_missing_key_field() {
        let json = r#"{"command":"set"}"#;
        assert!(RedisSink::from_config_str(json).unwrap_err().contains("key_field is required"));
    }

    #[test]
    fn test_from_config_str_publish_missing_channel() {
        let json = r#"{"command":"publish"}"#;
        assert!(RedisSink::from_config_str(json).unwrap_err().contains("channel is required"));
    }

    #[test]
    fn test_from_config_str_xadd_missing_stream() {
        let json = r#"{"command":"xadd"}"#;
        assert!(RedisSink::from_config_str(json).unwrap_err().contains("stream_name is required"));
    }

    #[test]
    fn test_set_command() {
        let mut sink = RedisSink::new(set_config());
        sink.put(vec![br#"{"id":"user-1","name":"Alice"}"#.to_vec()]);
        let envelopes = sink.flush().unwrap();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].commands.len(), 1);
        match &envelopes[0].commands[0] {
            RedisCommand::Set { key, value, ttl } => {
                assert_eq!(key, "user-1");
                assert!(value.contains("Alice"));
                assert!(ttl.is_none());
            }
            _ => panic!("Expected Set command"),
        }
    }

    #[test]
    fn test_set_with_ttl() {
        let mut config = set_config();
        config.ttl_secs = Some(3600);
        let mut sink = RedisSink::new(config);
        sink.put(vec![br#"{"id":"k1","v":"val"}"#.to_vec()]);
        let envelopes = sink.flush().unwrap();
        match &envelopes[0].commands[0] {
            RedisCommand::Set { ttl, .. } => assert_eq!(*ttl, Some(3600)),
            _ => panic!("Expected Set command"),
        }
    }

    #[test]
    fn test_set_with_key_prefix() {
        let mut config = set_config();
        config.key_prefix = Some("cache:".to_string());
        let mut sink = RedisSink::new(config);
        sink.put(vec![br#"{"id":"user-1"}"#.to_vec()]);
        let envelopes = sink.flush().unwrap();
        match &envelopes[0].commands[0] {
            RedisCommand::Set { key, .. } => assert_eq!(key, "cache:user-1"),
            _ => panic!("Expected Set command"),
        }
    }

    #[test]
    fn test_xadd_command() {
        let config = RedisSinkConfig {
            command: RedisCommandType::Xadd,
            stream_name: Some("events-stream".to_string()),
            ..Default::default()
        };
        let mut sink = RedisSink::new(config);
        sink.put(vec![br#"{"event":"click","page":"home"}"#.to_vec()]);
        let envelopes = sink.flush().unwrap();
        match &envelopes[0].commands[0] {
            RedisCommand::Xadd { stream, fields } => {
                assert_eq!(stream, "events-stream");
                assert_eq!(fields.get("event").unwrap(), "click");
                assert_eq!(fields.get("page").unwrap(), "home");
            }
            _ => panic!("Expected Xadd command"),
        }
    }

    #[test]
    fn test_lpush_command() {
        let config = RedisSinkConfig {
            command: RedisCommandType::Lpush,
            key_field: Some("queue".to_string()),
            ..Default::default()
        };
        let mut sink = RedisSink::new(config);
        sink.put(vec![br#"{"queue":"tasks","payload":"do-thing"}"#.to_vec()]);
        let envelopes = sink.flush().unwrap();
        match &envelopes[0].commands[0] {
            RedisCommand::Lpush { key, value } => {
                assert_eq!(key, "tasks");
                assert!(value.contains("do-thing"));
            }
            _ => panic!("Expected Lpush command"),
        }
    }

    #[test]
    fn test_publish_command() {
        let config = RedisSinkConfig {
            command: RedisCommandType::Publish,
            channel: Some("notifications".to_string()),
            ..Default::default()
        };
        let mut sink = RedisSink::new(config);
        sink.put(vec![br#"{"msg":"hello"}"#.to_vec()]);
        let envelopes = sink.flush().unwrap();
        match &envelopes[0].commands[0] {
            RedisCommand::Publish { channel, message } => {
                assert_eq!(channel, "notifications");
                assert!(message.contains("hello"));
            }
            _ => panic!("Expected Publish command"),
        }
    }

    #[test]
    fn test_multiple_records_single_envelope() {
        let mut sink = RedisSink::new(set_config());
        sink.put(vec![
            br#"{"id":"k1","v":"v1"}"#.to_vec(),
            br#"{"id":"k2","v":"v2"}"#.to_vec(),
            br#"{"id":"k3","v":"v3"}"#.to_vec(),
        ]);
        assert_eq!(sink.buffered_count(), 3);
        let envelopes = sink.flush().unwrap();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].commands.len(), 3);
        assert_eq!(sink.total_sent(), 3);
        assert_eq!(sink.buffered_count(), 0);
    }

    #[test]
    fn test_flush_empty() {
        let mut sink = RedisSink::new(set_config());
        assert!(sink.flush().unwrap().is_empty());
    }

    #[test]
    fn test_should_flush() {
        let mut config = set_config();
        config.batch_size = 2;
        let mut sink = RedisSink::new(config);
        assert!(!sink.should_flush());
        sink.put(vec![br#"{"id":"k1"}"#.to_vec()]);
        assert!(!sink.should_flush());
        sink.put(vec![br#"{"id":"k2"}"#.to_vec()]);
        assert!(sink.should_flush());
    }

    #[test]
    fn test_nested_key_field() {
        let mut config = set_config();
        config.key_field = Some("user.id".to_string());
        let mut sink = RedisSink::new(config);
        sink.put(vec![br#"{"user":{"id":"u123","name":"Bob"}}"#.to_vec()]);
        let envelopes = sink.flush().unwrap();
        match &envelopes[0].commands[0] {
            RedisCommand::Set { key, .. } => assert_eq!(key, "u123"),
            _ => panic!("Expected Set command"),
        }
    }

    #[test]
    fn test_missing_key_field_in_record() {
        let mut sink = RedisSink::new(set_config());
        sink.put(vec![br#"{"name":"Alice"}"#.to_vec()]);
        assert!(sink.flush().is_err());
    }

    #[test]
    fn test_non_json_record_publish() {
        let config = RedisSinkConfig {
            command: RedisCommandType::Publish,
            channel: Some("raw".to_string()),
            ..Default::default()
        };
        let mut sink = RedisSink::new(config);
        sink.put(vec![b"plain text message".to_vec()]);
        let envelopes = sink.flush().unwrap();
        match &envelopes[0].commands[0] {
            RedisCommand::Publish { message, .. } => {
                assert!(message.contains("plain text message"));
            }
            _ => panic!("Expected Publish command"),
        }
    }
}
