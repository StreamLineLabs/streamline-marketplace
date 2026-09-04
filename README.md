# Streamline WASM Transform Marketplace

[![CI](https://github.com/streamlinelabs/streamline-marketplace/actions/workflows/ci.yml/badge.svg)](https://github.com/streamlinelabs/streamline-marketplace/actions/workflows/ci.yml)
[![CodeQL](https://github.com/streamlinelabs/streamline-marketplace/actions/workflows/codeql.yml/badge.svg)](https://github.com/streamlinelabs/streamline-marketplace/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![WASM](https://img.shields.io/badge/WebAssembly-purple?style=flat-square)](https://webassembly.org/)
[![Docs](https://img.shields.io/badge/docs-streamlinelabs.dev-blue?style=flat-square)](https://streamlinelabs.dev/docs/features/wasm-transforms)
[![Release](https://img.shields.io/github/v/release/streamlinelabs/streamline-marketplace?label=release)](https://github.com/streamlinelabs/streamline-marketplace/releases)

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

## Quick Start

### Install a Transform

```bash
# Search the marketplace
streamline marketplace search "json-filter"

# Install a WASM transform
streamline marketplace install json-filter

# Apply to a topic
streamline topic alter my-topic --transform json-filter
```

### Publish a Transform

```bash
# Create a new transform project
streamline marketplace init my-transform --lang rust

# Build the WASM module
cd my-transform && make build

# Publish to the marketplace
streamline marketplace publish --name my-transform --version 0.1.0
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

## Running the Registry Server

The registry server fails closed on unsafe configuration:

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `REGISTRY_AUTH_TOKEN` | **yes** | none — the server refuses to start | Bearer token required by `POST /api/v1/transforms`. Minimum 16 printable ASCII characters; there is no development fallback. |
| `REGISTRY_BIND` | no | `127.0.0.1:8080` | Listen address. Binding publicly must be explicit. |
| `REGISTRY_ALLOWED_ORIGINS` | no | empty (no cross-origin access) | Comma-separated browser origins, e.g. `https://portal.example.com`. Wildcards, paths, and non-HTTP schemes are rejected at startup. |
| `REGISTRY_DATA_DIR` | no | `registry/data` | Catalog and artifact storage. Unreadable or corrupt catalogs abort startup instead of presenting an empty registry. |

```bash
REGISTRY_AUTH_TOKEN="$(openssl rand -hex 24)" \
REGISTRY_BIND=127.0.0.1:8080 \
  cargo run -p streamline-marketplace-registry
```

### Checksum policy

Catalog checksums are either a canonical `sha256:<64 hex>` digest of the released
artifact or the literal sentinel `pending`, which means "no released artifact
exists yet". Verification fails closed: empty, `pending`, non-SHA-256, and
malformed values all abort an install, and the registry refuses to serve an
artifact whose bytes do not match its catalog digest.

Published validation is **artifact-, identity-, and tag-bound**, not syntactic.
`registry/published-releases.json` is immutable metadata for assets that
actually exist on GitHub. For each published tag it records the exact catalog
`name`, transform `version`, and release asset basename. The verifier requires:

1. the selected name/version identifies exactly one live catalog entry;
2. that entry's canonical GitHub `wasm_url` uses the published release tag and the
   selected basename;
3. the downloaded GitHub asset bytes equal the live catalog SHA-256 digest;
4. every downloaded `*.wasm` belongs to that immutable manifest.

The live catalog currently points all six released modules at the real v0.3.0
assets. GitHub has no transform assets for v0.1.0 or v0.2.0, so no manifest or
catalog URL claims otherwise.

```bash
make validate-registry            # structural / pre-artifact validation
make validate-registry-digests    # advisory audit: which entries are still 'pending'?

# Release builds require exactly rustc 1.85.1, the
# x86_64-unknown-linux-gnu host, and Cargo.lock.
make build-transforms-release

# Verify the real public v0.3.0 downloads against the live catalog.
make verify-published-registry

# Current-source reproducibility is independent of published catalog history.
make check-reproducible-wasm

make validate-registry-controls          # hermetic positive/negative controls
bash scripts/validate_registry_controls.sh --built-artifacts dist  # + real outputs
bash scripts/e2e_publish_install.sh      # hermetic publish -> download -> install check
```

The canonical build environment is the pinned `linux/amd64` image also used by
CI:

```bash
docker run --rm --platform linux/amd64 \
  -v "$PWD:/work" -w /work \
  -e CARGO_TARGET_DIR=/work/target/reproducible-release \
  -e SOURCE_DATE_EPOCH=0 \
  rust:1.85.1-bookworm@sha256:e51d0265072d2d9d5d320f6a44dde6b9ef13653b035098febd68cce8fa7c0bc4 \
  bash -c 'rustup target add wasm32-wasip1 && bash scripts/check_reproducible_wasm.sh'
```

The builder rejects macOS, Linux ARM64, or any other host even when the rustc
version matches. It also fixes `SOURCE_DATE_EPOCH`, disables incremental
compilation, rejects ambient Rust flags, and remaps the checkout path to
`/workspace`. Rust/LLVM host differences change these WASM bytes, so hashes must
only be updated from the canonical amd64 Linux output.

`.github/workflows/release.yml` checks `GITHUB_REF_NAME` against locked Cargo
workspace/CLI metadata and requires `registry/shipping.json` to contain that
future tag before target installation or compilation. CLI builds use
`cargo build --locked`. If those preconditions are eventually met, only that
tag's explicit future selection can enter `dist/`.

`.github/workflows/ci.yml` additionally performs two clean builds in the pinned
amd64 Linux container, using the same dedicated target path sequentially, and
compares all six current-source modules byte-for-byte. That result is not used
as historical catalog metadata. A separate job downloads the actual published
v0.3.0 assets and verifies `registry/transforms.json` against their bytes.

Published hashes are updated only after downloading the public release assets.
Future build hashes belong in the future shipping process until those assets
exist; they must not overwrite or masquerade as immutable published metadata.

## Development

### Prerequisites

- Rust 1.85+ for the full workspace (CLI and registry dependencies use Edition 2024 crates)
- `wasm32-wasip1` target: `rustup target add wasm32-wasip1`

### Building

```bash
# Build all transforms
cargo build --target wasm32-wasip1 --release

# Build the CLI
cargo build --locked -p streamline-marketplace-cli

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
<!-- test: 451d957d -->


<!-- add connector development guide -->
