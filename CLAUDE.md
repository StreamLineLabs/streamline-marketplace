# CLAUDE.md — Streamline Marketplace

## Overview
WASM transform registry and CLI for [Streamline](https://github.com/streamlinelabs/streamline). Contains pre-built stream processing transforms (filters, enrichers, validators) compiled to WebAssembly.

## Build & Test
```bash
make build                   # Build CLI + all WASM transforms
make test                    # Run all tests
make build-cli               # Build CLI only
make build-transforms        # Build all WASM transforms
make validate-registry       # Validate registry JSON
make check                   # Formatting + linting
```

## Architecture
```
├── Cargo.toml               # Workspace with 7 members
├── cli/                     # marketplace CLI tool
│   └── src/                 # Install, search, publish commands
├── registry/
│   ├── src/                 # Registry server
│   ├── transforms.json      # Transform catalog
│   ├── published-releases.json # Immutable manifests for real GitHub assets
│   └── shipping.json        # Future tag shipping plan (empty = fail closed)
├── transforms/
│   ├── json-filter/         # Filter messages by JSON field values
│   ├── timestamp-enricher/  # Add processing timestamps to messages
│   ├── pii-redactor/        # Redact PII (emails, SSNs, etc.)
│   ├── schema-validator/    # Validate messages against JSON Schema
│   └── field-router/        # Route messages to topics based on field values
```

## Coding Conventions
- **WASM target**: Transforms compile to `wasm32-wasip1`
- **CLI**: Native binary for host platform
- **Registry**: JSON catalog with required fields (name, version, description, author, wasm_url, categories, checksum)
- **Categories**: filtering, enrichment, routing, security, analytics, format-conversion

## Transform Development
Each transform is a Rust crate that compiles to WASM:
```bash
# Build a single transform
cargo build -p json-filter --target wasm32-wasip1 --release

# Test a transform (native)
cargo test -p json-filter
```

Canonical future release builds use exactly Rust 1.85.1 on
`x86_64-unknown-linux-gnu`, the pinned amd64 Linux container documented in the
README, and `Cargo.lock`:
```bash
make build-transforms-release
make check-reproducible-wasm
make verify-published-registry
```

Never stage `target/wasm32-wasip1/release/*.wasm` wholesale for a tag.
`registry/published-releases.json` describes only assets that actually exist;
`registry/shipping.json` is separate and must contain a new, version-matched tag
before current source can be built or staged by the release workflow.

## Registry Schema
```json
{
  "name": "json-filter",
  "version": "0.1.0",
  "description": "Filter messages by JSON field values",
  "author": "StreamlineLabs",
  "wasm_url": "https://...",
  "categories": ["filtering"],
  "min_streamline_version": "0.2.0",
  "checksum": "sha256:..."
}
```
