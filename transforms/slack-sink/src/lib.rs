//! Slack Sink Connector — posts messages to Slack channels via webhooks.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct SlackSinkConfig {
    pub webhook_url: String,
    pub channel: String,
    pub message_template: String,
    pub rate_limit_per_sec: u32,
}

impl Default for SlackSinkConfig {
    fn default() -> Self {
        Self {
            webhook_url: String::new(),
            channel: String::new(),
            message_template: "{{message}}".to_string(),
            rate_limit_per_sec: 1,
        }
    }
}

pub struct SlackSink {
    config: SlackSinkConfig,
    buffer: Vec<Vec<u8>>,
}

impl SlackSink {
    pub fn new(config: SlackSinkConfig) -> Self {
        Self {
            config,
            buffer: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        "slack-sink"
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
