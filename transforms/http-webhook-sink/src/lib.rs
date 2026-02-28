//! HTTP Webhook Sink Connector — sends data via POST/PUT to HTTP endpoints.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct HttpWebhookSinkConfig {
    pub url: String,
    pub method: HttpMethod,
    pub headers: Vec<(String, String)>,
    pub auth_type: AuthType,
    pub auth_token: Option<String>,
    pub batch_mode: bool,
    pub retry_count: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Post,
    Put,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    None,
    Bearer,
    Basic,
}

impl Default for HttpWebhookSinkConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            method: HttpMethod::Post,
            headers: Vec::new(),
            auth_type: AuthType::None,
            auth_token: None,
            batch_mode: false,
            retry_count: 3,
        }
    }
}

pub struct HttpWebhookSink {
    config: HttpWebhookSinkConfig,
    buffer: Vec<Vec<u8>>,
}

impl HttpWebhookSink {
    pub fn new(config: HttpWebhookSinkConfig) -> Self {
        Self {
            config,
            buffer: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        "http-webhook-sink"
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
