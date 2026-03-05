//! Slack Sink Connector — posts messages to Slack channels via webhooks.
//!
//! Produces Slack webhook request envelopes. Supports:
//! - Incoming webhook URL delivery
//! - Message template interpolation with `{field}` placeholders
//! - Channel, username, and icon emoji overrides
//! - Rate limiting metadata

use serde::{Deserialize, Serialize};
use serde_json::Value;

// -- Configuration --

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SlackSinkConfig {
    /// Slack incoming webhook URL.
    pub webhook_url: String,
    /// Message text template. Use `{field}` for JSON field substitution.
    #[serde(default)]
    pub template: Option<String>,
    /// Override channel.
    #[serde(default)]
    pub channel: Option<String>,
    /// Optional username to display.
    #[serde(default)]
    pub username: Option<String>,
    /// Optional emoji icon (e.g., ":rocket:").
    #[serde(default)]
    pub icon_emoji: Option<String>,
    /// Rate limit in messages per second (for host runtime to enforce).
    #[serde(default)]
    pub rate_limit_per_sec: Option<u32>,
}

impl Default for SlackSinkConfig {
    fn default() -> Self {
        Self {
            webhook_url: String::new(),
            template: None,
            channel: None,
            username: None,
            icon_emoji: None,
            rate_limit_per_sec: None,
        }
    }
}

// -- Webhook Request Envelope --

#[derive(Debug, Clone, Serialize)]
pub struct SlackWebhookRequest {
    pub url: String,
    pub payload: SlackPayload,
}

#[derive(Debug, Clone, Serialize)]
pub struct SlackPayload {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_emoji: Option<String>,
}

// -- Sink Implementation --

#[derive(Debug)]
pub struct SlackSink {
    config: SlackSinkConfig,
    buffer: Vec<Value>,
    total_sent: u64,
}

impl SlackSink {
    pub fn new(config: SlackSinkConfig) -> Self {
        Self { config, buffer: Vec::new(), total_sent: 0 }
    }

    pub fn from_config_str(json: &str) -> Result<Self, String> {
        let config: SlackSinkConfig = serde_json::from_str(json)
            .map_err(|e| format!("Invalid config: {e}"))?;
        if config.webhook_url.is_empty() {
            return Err("webhook_url is required".to_string());
        }
        Ok(Self::new(config))
    }

    pub fn name(&self) -> &str { "slack-sink" }

    pub fn put(&mut self, records: Vec<Vec<u8>>) {
        for record in records {
            let value = match serde_json::from_slice::<Value>(&record) {
                Ok(v) => v,
                Err(_) => Value::String(String::from_utf8_lossy(&record).into_owned()),
            };
            self.buffer.push(value);
        }
    }

    pub fn flush(&mut self) -> Result<Vec<SlackWebhookRequest>, String> {
        if self.buffer.is_empty() { return Ok(Vec::new()); }

        let mut requests = Vec::new();
        for record in &self.buffer {
            let text = self.render_text(record);
            requests.push(SlackWebhookRequest {
                url: self.config.webhook_url.clone(),
                payload: SlackPayload {
                    text,
                    channel: self.config.channel.clone(),
                    username: self.config.username.clone(),
                    icon_emoji: self.config.icon_emoji.clone(),
                },
            });
        }

        self.total_sent += self.buffer.len() as u64;
        self.buffer.clear();
        Ok(requests)
    }

    pub fn buffered_count(&self) -> usize { self.buffer.len() }
    pub fn total_sent(&self) -> u64 { self.total_sent }
    pub fn should_flush(&self) -> bool { !self.buffer.is_empty() }

    fn render_text(&self, record: &Value) -> String {
        match &self.config.template {
            Some(template) => {
                let mut result = template.clone();
                if let Some(obj) = record.as_object() {
                    for (key, val) in obj {
                        let placeholder = format!("{{{key}}}");
                        if result.contains(&placeholder) {
                            let replacement = match val {
                                Value::String(s) => s.clone(),
                                Value::Null => "null".to_string(),
                                other => other.to_string(),
                            };
                            result = result.replace(&placeholder, &replacement);
                        }
                    }
                }
                result
            }
            None => {
                serde_json::to_string(record).unwrap_or_else(|_| record.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SlackSinkConfig {
        SlackSinkConfig {
            webhook_url: "https://hooks.slack.com/services/T00/B00/xxx".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_config_parsing() {
        let json = r##"{
            "webhook_url": "https://hooks.slack.com/services/T/B/x",
            "template": "Alert: {msg}",
            "channel": "#alerts",
            "username": "bot",
            "icon_emoji": ":zap:",
            "rate_limit_per_sec": 5
        }"##;
        let sink = SlackSink::from_config_str(json).unwrap();
        assert_eq!(sink.name(), "slack-sink");
        assert_eq!(sink.config.template, Some("Alert: {msg}".to_string()));
        assert_eq!(sink.config.channel, Some("#alerts".to_string()));
        assert_eq!(sink.config.username, Some("bot".to_string()));
        assert_eq!(sink.config.icon_emoji, Some(":zap:".to_string()));
        assert_eq!(sink.config.rate_limit_per_sec, Some(5));
    }

    #[test]
    fn test_config_parsing_minimal() {
        let json = r#"{"webhook_url":"https://hooks.slack.com/services/T/B/x"}"#;
        let sink = SlackSink::from_config_str(json).unwrap();
        assert!(sink.config.template.is_none());
        assert!(sink.config.channel.is_none());
        assert!(sink.config.username.is_none());
        assert!(sink.config.icon_emoji.is_none());
        assert!(sink.config.rate_limit_per_sec.is_none());
    }

    #[test]
    fn test_config_parsing_missing_url() {
        assert!(SlackSink::from_config_str(r#"{}"#).is_err());
    }

    #[test]
    fn test_template_substitution() {
        let mut config = test_config();
        config.template = Some("Alert: {level} - {msg}".to_string());
        let mut sink = SlackSink::new(config);
        sink.put(vec![br#"{"level":"ERROR","msg":"disk full"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].payload.text, "Alert: ERROR - disk full");
    }

    #[test]
    fn test_template_substitution_numeric() {
        let mut config = test_config();
        config.template = Some("Count: {count}".to_string());
        let mut sink = SlackSink::new(config);
        sink.put(vec![br#"{"count":42}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].payload.text, "Count: 42");
    }

    #[test]
    fn test_template_substitution_partial() {
        let mut config = test_config();
        config.template = Some("User: {name}, Role: {role}".to_string());
        let mut sink = SlackSink::new(config);
        sink.put(vec![br#"{"name":"Alice"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].payload.text, "User: Alice, Role: {role}");
    }

    #[test]
    fn test_default_formatting() {
        let mut sink = SlackSink::new(test_config());
        sink.put(vec![br#"{"event":"click","user":"alice"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        let text = &reqs[0].payload.text;
        assert!(text.contains("click"));
        assert!(text.contains("alice"));
        assert!(serde_json::from_str::<Value>(text).is_ok());
    }

    #[test]
    fn test_default_formatting_non_json() {
        let mut sink = SlackSink::new(test_config());
        sink.put(vec![b"plain text alert".to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].payload.text, "\"plain text alert\"");
    }

    #[test]
    fn test_payload_channel() {
        let mut config = test_config();
        config.channel = Some("#alerts".to_string());
        let mut sink = SlackSink::new(config);
        sink.put(vec![br#"{"msg":"test"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].payload.channel, Some("#alerts".to_string()));
    }

    #[test]
    fn test_payload_username_and_emoji() {
        let mut config = test_config();
        config.username = Some("StreamlineBot".to_string());
        config.icon_emoji = Some(":zap:".to_string());
        let mut sink = SlackSink::new(config);
        sink.put(vec![br#"{"msg":"hello"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].payload.username, Some("StreamlineBot".to_string()));
        assert_eq!(reqs[0].payload.icon_emoji, Some(":zap:".to_string()));
    }

    #[test]
    fn test_payload_optional_fields_none() {
        let mut sink = SlackSink::new(test_config());
        sink.put(vec![br#"{"msg":"test"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].payload.channel, None);
        assert_eq!(reqs[0].payload.username, None);
        assert_eq!(reqs[0].payload.icon_emoji, None);
    }

    #[test]
    fn test_webhook_url() {
        let mut sink = SlackSink::new(test_config());
        sink.put(vec![br#"{"msg":"test"}"#.to_vec()]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs[0].url, "https://hooks.slack.com/services/T00/B00/xxx");
    }

    #[test]
    fn test_multiple_messages() {
        let mut sink = SlackSink::new(test_config());
        sink.put(vec![
            br#"{"msg":"one"}"#.to_vec(),
            br#"{"msg":"two"}"#.to_vec(),
        ]);
        let reqs = sink.flush().unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(sink.total_sent(), 2);
    }

    #[test]
    fn test_flush_empty() {
        let mut sink = SlackSink::new(test_config());
        assert!(sink.flush().unwrap().is_empty());
    }

    #[test]
    fn test_buffered_count() {
        let mut sink = SlackSink::new(test_config());
        assert_eq!(sink.buffered_count(), 0);
        sink.put(vec![br#"{"a":1}"#.to_vec(), br#"{"b":2}"#.to_vec()]);
        assert_eq!(sink.buffered_count(), 2);
        sink.flush().unwrap();
        assert_eq!(sink.buffered_count(), 0);
    }
}
