# Streamline WASM Transform Marketplace

A registry and discovery system for user-contributed WebAssembly (WASM) transforms for [Streamline](https://github.com/streamlinelabs/streamline) -- "The Redis of Streaming".

## Overview

The WASM Transform Marketplace enables the Streamline community to share, discover, and install reusable stream processing transforms. Each transform is a compiled WebAssembly module that runs inside the Streamline server's sandboxed `wasmtime` runtime, providing safe and performant message processing without external dependencies.

### How It Works

1. **Transforms are WASM modules** compiled from Rust (or any language targeting `wasm32-wasip1`).
2. **The registry** (`registry/transforms.json`) is a JSON index of all available transforms with metadata, download URLs, and categorization.
3. **The CLI** (`streamline-marketplace`) lets you search, install, and publish transforms.
4. **The server** fetches and caches WASM modules, then executes them inline as messages flow through topics.

### Architecture

```
                      registry/transforms.json
                              |
                    +---------+---------+
                    |                   |
              CLI (search,         Server (HTTP API)
              install, publish)    GET /api/v1/marketplace/transforms
                    |                   |
                    v                   v
              ~/.streamline/       <data-dir>/transforms/
              transforms/          (cached WASM modules)
```

## Publishing Transforms

### 1. Write Your Transform

Create a Rust library targeting `wasm32-wasip1`:

```rust
use serde_json::Value;

/// Called once when the module is loaded. Receives configuration JSON.
#[no_mangle]
pub extern "C" fn init(config_ptr: *const u8, config_len: u32) -> u32 {
    // Parse config, return 1 for success, 0 for failure
    1
}

/// Transform a single message. Return transformed bytes.
#[no_mangle]
pub extern "C" fn transform(input_ptr: *const u8, input_len: u32, output_ptr: *mut u8) -> u32 {
    let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len as usize) };
    // Process the message...
    let output = input.to_vec(); // pass-through example
    let len = output.len();
    unsafe { std::ptr::copy_nonoverlapping(output.as_ptr(), output_ptr, len); }
    len as u32
}
```

### 2. Build for WASM

```bash
cargo build --target wasm32-wasip1 --release
```

### 3. Publish

```bash
# Host your .wasm file (GitHub Releases, S3, etc.), then:
streamline-marketplace publish ./path/to/transform/ \
  --name my-transform \
  --version 0.2.0 \
  --wasm-url https://github.com/you/repo/releases/download/v0.2.0/my_transform.wasm
```

Or submit a pull request adding your transform entry to `registry/transforms.json`.

## Discovering and Installing Transforms

### Search

```bash
# Search by keyword
streamline-marketplace search "json filter"

# Search by category
streamline-marketplace search --category transform
```

### Install

```bash
# Install a transform by name
streamline-marketplace install json-filter

# Install a specific version
streamline-marketplace install json-filter@0.2.0
```

### List Installed

```bash
streamline-marketplace list
```

### Get Info

```bash
streamline-marketplace info json-filter
```

## Built-in Transforms

The following transforms are maintained as part of the official marketplace:

| Name | Category | Description |
|------|----------|-------------|
| `json-filter` | filtering | Filter messages by JSON field values |
| `json-transform` | format-conversion | Transform JSON structure (rename fields, flatten, etc.) |
| `csv-to-json` | format-conversion | Convert CSV messages to JSON |
| `json-to-avro` | format-conversion | Convert JSON messages to Avro format |
| `timestamp-enricher` | enrichment | Add processing timestamps to messages |
| `pii-redactor` | security | Redact personally identifiable information |
| `schema-validator` | filtering, analytics | Validate messages against a JSON schema |
| `field-router` | routing | Route messages to topics based on field values |
| `deduplicator` | filtering | Remove duplicate messages by key |
| `rate-limiter` | filtering, analytics | Rate-limit message throughput |
| `geo-enricher` | enrichment | Enrich messages with geolocation data from IP addresses |

## Server Integration

When the Streamline server has the `wasm-transforms` feature enabled, it exposes marketplace endpoints:

```
GET  /api/v1/marketplace/transforms             - List available transforms
POST /api/v1/marketplace/transforms/{name}/install - Install a transform
GET  /api/v1/marketplace/transforms/installed    - List installed transforms
```

### Deploy an installed transform

```bash
streamline-cli transforms deploy \
  --name my-pipeline \
  --wasm ~/.streamline/transforms/json-filter/0.2.0/json_filter.wasm \
  --input raw-events \
  --output filtered-events \
  --config '{"field": "status", "operator": "eq", "value": "active"}'
```

## Development

### Prerequisites

- Rust 1.75+
- `wasm32-wasip1` target: `rustup target add wasm32-wasip1`

### Building

```bash
# Build all transforms
cargo build --target wasm32-wasip1 --release

# Build the CLI
cargo build -p streamline-marketplace-cli

# Run tests
cargo test --workspace
```

### Project Structure

```
streamline-marketplace/
+-- Cargo.toml              # Workspace definition
+-- registry/
|   +-- transforms.json     # Transform registry index
+-- transforms/
|   +-- json-filter/        # Example: JSON field filter
|   +-- timestamp-enricher/ # Example: Timestamp enrichment
|   +-- pii-redactor/       # Example: PII redaction
|   +-- schema-validator/   # Example: JSON Schema validation
|   +-- field-router/       # Example: Field-based routing
+-- cli/                    # CLI tool for marketplace interaction
+-- .github/workflows/      # CI for building WASM modules
```

## Contributing

We welcome community-contributed transforms. Please see the [Contributing Guide](https://github.com/streamlinelabs/.github/blob/main/CONTRIBUTING.md) for guidelines.

To add a new transform:

1. Fork this repository.
2. Add your transform source under `transforms/<name>/`.
3. Add an entry to `registry/transforms.json`.
4. Submit a pull request with a description of your transform.

## License

Apache 2.0. See [LICENSE](LICENSE) for details.
