# Streamline Connector SDK

Build custom source and sink connectors for the Streamline streaming platform.

## Quick Start

```bash
# Create a new connector project from template
cargo init my-connector
cd my-connector
```

Add to `Cargo.toml`:
```toml
[dependencies]
streamline-connector-sdk = { path = "../connector-sdk" }
tokio = { version = "1", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
async-trait = "0.1"
```

## Implementing a Sink Connector

```rust
use streamline_connector_sdk::prelude::*;
use async_trait::async_trait;

pub struct MySinkConnector {
    config: MyConfig,
}

#[derive(Debug, serde::Deserialize)]
pub struct MyConfig {
    pub target_url: String,
    pub batch_size: usize,
}

#[async_trait]
impl SinkConnector for MySinkConnector {
    fn name(&self) -> &str {
        "my-sink-connector"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    async fn start(&mut self) -> Result<(), ConnectorError> {
        // Initialize resources (connections, files, etc.)
        Ok(())
    }

    async fn put(&mut self, records: Vec<Record>) -> Result<(), ConnectorError> {
        // Process a batch of records
        for record in &records {
            println!("Processing: {:?}", record.value);
        }
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), ConnectorError> {
        // Flush any buffered data
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ConnectorError> {
        // Cleanup resources
        Ok(())
    }
}
```

## Implementing a Source Connector

```rust
#[async_trait]
impl SourceConnector for MySourceConnector {
    fn name(&self) -> &str { "my-source-connector" }
    fn version(&self) -> &str { env!("CARGO_PKG_VERSION") }

    async fn start(&mut self) -> Result<(), ConnectorError> {
        Ok(())
    }

    async fn poll(&mut self) -> Result<Vec<Record>, ConnectorError> {
        // Return new records from your source
        Ok(vec![])
    }

    async fn stop(&mut self) -> Result<(), ConnectorError> {
        Ok(())
    }
}
```

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use streamline_connector_sdk::testing::*;

    #[tokio::test]
    async fn test_sink() {
        let mut connector = MySinkConnector { /* ... */ };
        connector.start().await.unwrap();

        let records = vec![
            Record::new("test-topic", b"hello".to_vec()),
        ];
        connector.put(records).await.unwrap();
        connector.stop().await.unwrap();
    }
}
```

## Publishing to Marketplace

1. Create `transform.toml` in your project root:
```toml
[transform]
name = "my-connector"
version = "0.1.0"
description = "My custom connector"
author = "Your Name"
license = "Apache-2.0"
category = "sink"
tags = ["custom", "example"]

[transform.config]
target_url = { type = "string", required = true, description = "Target URL" }
batch_size = { type = "integer", default = 100, description = "Batch size" }
```

2. Build and publish:
```bash
streamline-marketplace publish my-connector
```

## Error Handling

```rust
use streamline_connector_sdk::ConnectorError;

// Return typed errors
return Err(ConnectorError::Configuration("missing required field 'url'".into()));
return Err(ConnectorError::Connection("target unreachable".into()));
return Err(ConnectorError::Serialization("invalid JSON".into()));
```
