//! HTTP Webhook Sink Connector — sends data via POST/PUT to HTTP endpoints.
//!
//! Produces HTTP request envelopes for the host runtime to execute. Supports:
//! - Single-record and batch delivery modes
//! - Bearer, Basic, and API Key authentication
//! - Custom headers
//! - Configurable retry count and timeout

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

// -- Configuration --

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpWebhookSinkConfig {
    /// Target URL for the webhook.
    pub url: String,
    /// HTTP method (POST or PUT).
    #[serde(default)]
    pub method: HttpMethod,
    /// Authentication configuration.
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    /// Extra headers to include in requests.
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    /// When true, buffer records and send as a JSON array.
    #[serde(default)]
    pub batch_mode: bool,
    /// Number of retry attempts on failure.
    #[serde(default = "default_retry_count")]
    pub retry_count: u32,
    /// Request timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_retry_count() -> u32 { 3 }
fn default_timeout_ms() -> u64 { 30000 }

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Post,
    Put,
}

impl Default for HttpMethod {
    fn default() -> Self { HttpMethod::Post }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    Bearer { token: String },
    Basic { username: String, password: String },
    ApiKey { header: String, value: String },
}

impl Default for HttpWebhookSinkConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            method: HttpMethod::Post,
            auth: None,
            headers: None,
            batch_mode: false,
            retry_count: default_retry_count(),
            timeout_ms: default_timeout_ms(),
        }
    }
}

// -- HTTP Request Envelope --

#[derive(Debug, Clone, Serialize)]
pub struct HttpRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub record_count: usize,
    pub retry_count: u32,
}

// -- Sink Implementation --

#[derive(Debug)]
pub struct HttpWebhookSink {
    config: HttpWebhookSinkConfig,
    buffer: Vec<Value>,
    total_sent: u64,
}

impl HttpWebhookSink {
    pub fn new(config: HttpWebhookSinkConfig) -> Self {
        Self { config, buffer: Vec::new(), total_sent: 0 }
    }

    pub fn from_config_str(json: &str) -> Result<Self, String> {
        let config: HttpWebhookSinkConfig = serde_json::from_str(json)
            .map_err(|e| format!("Invalid config: {e}"))?;
        if config.url.is_empty() { return Err("url is required".to_string()); }
        Ok(Self::new(config))
    }

    pub fn name(&self) -> &str { "http-webhook-sink" }

    pub fn put(&mut self, records: Vec<Vec<u8>>) {
        for record in records {
            let value = match serde_json::from_slice::<Value>(&record) {
                Ok(v) => v,
                Err(_) => Value::String(String::from_utf8_lossy(&record).into_owned()),
            };
            self.buffer.push(value);
        }
    }

    pub fn flush(&mut self) -> Result<Vec<HttpRequest>, String> {
        if self.buffer.is_empty() { return Ok(Vec::new()); }

        let mut requests = Vec::new();
        let headers = self.build_headers();
        let method = match self.config.method {
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
        };

        if self.config.batch_mode {
            let body = serde_json::to_string(&self.buffer)
                .map_err(|e| format!("Serialization error: {e}"))?;
            requests.push(HttpRequest {
                url: self.config.url.clone(),
                method: method.to_string(),
                headers: headers.clone(),
                body,
                record_count: self.buffer.len(),
                retry_count: self.config.retry_count,
            });
        } else {
            for record in &self.buffer {
                let body = serde_json::to_string(record)
                    .map_err(|e| format!("Serialization error: {e}"))?;
                requests.push(HttpRequest {
                    url: self.config.url.clone(),
                    method: method.to_string(),
                    headers: headers.clone(),
                    body,
                    record_count: 1,
                    retry_count: self.config.retry_count,
                });
            }
        }

        self.total_sent += self.buffer.len() as u64;
        self.buffer.clear();
        Ok(requests)
    }

    pub fn buffered_count(&self) -> usize { self.buffer.len() }
    pub fn total_sent(&self) -> u64 { self.total_sent }
    pub fn should_flush(&self) -> bool { self.config.batch_mode && !self.buffer.is_empty() }

    fn build_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        match &self.config.auth {
            Some(AuthConfig::Bearer { token }) => {
                headers.insert("Authorization".to_string(), format!("Bearer {token}"));
            }
            Some(AuthConfig::Basic { username, password }) => {
                let credentials = format!("{username}:{password}");
                headers.insert("Authorization".to_string(), format!("Basic {credentials}"));
            }
            Some(AuthConfig::ApiKey { header, value }) => {
                headers.insert(header.clone(), value.clone());
            }
            None => {}
        }

        if let Some(custom) = &self.config.headers {
            for (k, v) in custom {
                headers.insert(k.clone(), v.clone());
            }
        }

        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> HttpWebhookSinkConfig {
        HttpWebhookSinkConfig {
            url: "https://example.com/webhook".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_config_parsing() {
        let json = r#"{"url":"https://example.com/hook","method":"POST"}"#;
        let sink = HttpWebhookSink::from_config_str(json).unwrap();
        assert_eq!(sink.name(), "http-webhook-sink");
        assert_eq!(sink.config.retry_count, 3);
        assert_eq!(sink.config.timeout_ms, 30000);
    }

    #[test]
    fn test_config_parsing_missing_url() {
        assert!(HttpWebhookSink::from_config_str(r#"{"method":"POST"}"#).is_err());
    }

    #[test]
    fn test_default_config() {
        let c = HttpWebhookSinkConfig::default();
        assert_eq!(c.method, HttpMethod::Post);
        assert!(!c.batch_mode);
        assert_eq!(c.retry_count, 3);
        assert_eq!(c.timeout_ms, 30000);
        assert!(c.auth.is_none());
        assert!(c.headers.is_none());
    }

    #[test]
    fn test_single_mode() {
        let mut sink = HttpWebhookSink::new(test_config());
        sink.put(vec![
            br#"{"a":1}"#.to_vec(),
            br#"{"b":2}"#.to_vec(),
        ]);
        let requests = sink.flush().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].record_count, 1);
        assert_eq!(requests[0].url, "https://example.com/webhook");
        assert!(requests[0].body.contains("\"a\":1"));
        assert!(requests[1].body.contains("\"b\":2"));
        assert_eq!(sink.total_sent(), 2);
    }

    #[test]
    fn test_batch_mode() {
        let mut config = test_config();
        config.batch_mode = true;
        let mut sink = HttpWebhookSink::new(config);
        sink.put(vec![
            br#"{"a":1}"#.to_vec(),
            br#"{"b":2}"#.to_vec(),
        ]);
        let requests = sink.flush().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].body.starts_with('['));
        assert_eq!(requests[0].record_count, 2);
    }

    #[test]
    fn test_auth_bearer() {
        let mut config = test_config();
        config.auth = Some(AuthConfig::Bearer { token: "my-token".to_string() });
        let mut sink = HttpWebhookSink::new(config);
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        let requests = sink.flush().unwrap();
        assert_eq!(requests[0].headers.get("Authorization").unwrap(), "Bearer my-token");
    }

    #[test]
    fn test_auth_basic() {
        let mut config = test_config();
        config.auth = Some(AuthConfig::Basic {
            username: "user".to_string(),
            password: "pass".to_string(),
        });
        let mut sink = HttpWebhookSink::new(config);
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        let requests = sink.flush().unwrap();
        assert_eq!(requests[0].headers.get("Authorization").unwrap(), "Basic user:pass");
    }

    #[test]
    fn test_auth_api_key() {
        let mut config = test_config();
        config.auth = Some(AuthConfig::ApiKey {
            header: "X-API-Key".to_string(),
            value: "secret-key".to_string(),
        });
        let mut sink = HttpWebhookSink::new(config);
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        let requests = sink.flush().unwrap();
        assert_eq!(requests[0].headers.get("X-API-Key").unwrap(), "secret-key");
    }

    #[test]
    fn test_custom_headers() {
        let mut config = test_config();
        let mut headers = HashMap::new();
        headers.insert("X-Custom".to_string(), "value".to_string());
        config.headers = Some(headers);
        let mut sink = HttpWebhookSink::new(config);
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        let requests = sink.flush().unwrap();
        assert_eq!(requests[0].headers.get("X-Custom").unwrap(), "value");
    }

    #[test]
    fn test_put_method() {
        let mut config = test_config();
        config.method = HttpMethod::Put;
        let mut sink = HttpWebhookSink::new(config);
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        let requests = sink.flush().unwrap();
        assert_eq!(requests[0].method, "PUT");
    }

    #[test]
    fn test_retry_count_propagated() {
        let mut config = test_config();
        config.retry_count = 5;
        let mut sink = HttpWebhookSink::new(config);
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        let requests = sink.flush().unwrap();
        assert_eq!(requests[0].retry_count, 5);
    }

    #[test]
    fn test_flush_empty() {
        let mut sink = HttpWebhookSink::new(test_config());
        assert!(sink.flush().unwrap().is_empty());
    }

    #[test]
    fn test_should_flush() {
        let mut config = test_config();
        config.batch_mode = true;
        let mut sink = HttpWebhookSink::new(config);
        assert!(!sink.should_flush());
        sink.put(vec![br#"{"a":1}"#.to_vec()]);
        assert!(sink.should_flush());
    }

    #[test]
    fn test_content_type_header() {
        let mut sink = HttpWebhookSink::new(test_config());
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        let requests = sink.flush().unwrap();
        assert_eq!(requests[0].headers.get("Content-Type").unwrap(), "application/json");
    }

    #[test]
    fn test_no_auth() {
        let mut sink = HttpWebhookSink::new(test_config());
        sink.put(vec![br#"{"x":1}"#.to_vec()]);
        let requests = sink.flush().unwrap();
        assert!(requests[0].headers.get("Authorization").is_none());
    }
}
