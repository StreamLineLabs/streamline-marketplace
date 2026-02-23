# Streamline Connector SDK

Build custom source and sink connectors for Streamline using WebAssembly.

## Quick Start

```bash
# Create a new connector project
streamline-cli connector new my-sink --type sink

# Build to WASM
cd my-sink
cargo build --target wasm32-wasip1 --release

# Test locally
streamline-cli connector test target/wasm32-wasip1/release/my_sink.wasm

# Publish to marketplace
streamline-cli connector publish
```

## Connector Types

| Type | Interface | Use Case |
|------|-----------|----------|
| **Source** | `fn poll() -> Vec<Record>` | Pull data into Streamline |
| **Sink** | `fn write(records: Vec<Record>)` | Push data out of Streamline |
| **Transform** | `fn transform(record: Record) -> Record` | Modify records in-flight |

## Project Structure

```
my-connector/
├── Cargo.toml          # WASM build configuration
├── src/
│   └── lib.rs          # Connector implementation
├── config.schema.json  # Configuration schema
└── README.md           # Documentation
```

## API Reference

### Source Connector

```rust
#[no_mangle]
pub extern "C" fn init(config_ptr: *const u8, config_len: u32) -> i32;

#[no_mangle]
pub extern "C" fn poll(out_ptr: *mut u8, out_len: *mut u32) -> i32;

#[no_mangle]
pub extern "C" fn shutdown() -> i32;
```

### Sink Connector

```rust
#[no_mangle]
pub extern "C" fn init(config_ptr: *const u8, config_len: u32) -> i32;

#[no_mangle]
pub extern "C" fn write(records_ptr: *const u8, records_len: u32) -> i32;

#[no_mangle]
pub extern "C" fn flush() -> i32;

#[no_mangle]
pub extern "C" fn shutdown() -> i32;
```

## Publishing

1. Build: `cargo build --target wasm32-wasip1 --release`
2. Test: `streamline-cli connector test <wasm-file>`
3. Publish: `streamline-cli connector publish --name my-connector --version 0.1.0`
