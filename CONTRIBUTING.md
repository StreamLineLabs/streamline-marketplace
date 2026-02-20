# Contributing to Streamline WASM Transform Marketplace

Thank you for your interest in contributing to the Streamline WASM Transform Marketplace! This document provides guidelines for contributing transforms, improving the CLI, and working with the registry.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Install prerequisites:
   - Rust 1.75+ with `wasm32-wasip1` target: `rustup target add wasm32-wasip1`
4. Build and test:
   ```bash
   cargo build --workspace
   cargo test --workspace
   ```

## Contributing a Transform

### 1. Create the Transform

```bash
mkdir -p transforms/my-transform/src
```

Create `transforms/my-transform/Cargo.toml`:
```toml
[package]
name = "my-transform"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "Brief description of what the transform does"

[lib]
crate-type = ["cdylib"]

[dependencies]
serde_json = "1.0"
```

### 2. Implement the WASM Interface

Your transform must export these functions:

- `init(config_ptr, config_len) -> u32` — Initialize with config JSON. Return 1 for success.
- `filter(input_ptr, input_len) -> u32` — Return 1 to keep the message, 0 to drop it.
- `transform(input_ptr, input_len, output_ptr) -> u32` — Transform the message. Return output length.

### 3. Add Tests

Include unit tests in your `lib.rs` using `#[cfg(test)]` modules. Test all operators, edge cases, and error handling.

### 4. Update the Registry

Add an entry to `registry/transforms.json` with all required fields:
- `name`, `version`, `description`, `author`
- `downloads` (set to 0 for new transforms)
- `checksum` (SHA-256 of the compiled WASM binary)
- `categories` (one or more of: filtering, enrichment, routing, security, analytics, format-conversion)
- `min_streamline_version`
- `wasm_url`, `input_format`, `output_format`, `tags`, `license`, `repository_url`, `config_schema`

### 5. Add to Workspace

Add your transform to the `members` list in the root `Cargo.toml`.

### 6. Submit a Pull Request

- Include a clear description of what your transform does
- Ensure all tests pass: `cargo test --workspace`
- Ensure formatting is correct: `cargo fmt --all -- --check`
- Ensure no lint warnings: `cargo clippy --all-targets -- -D warnings`

## Code Style

- Follow standard Rust conventions and `rustfmt` formatting
- Document public functions with doc comments
- Keep WASM modules minimal — avoid unnecessary dependencies to reduce binary size
- Handle errors gracefully (pass through messages on failure rather than panicking)

## Reporting Issues

- Use GitHub Issues to report bugs or request features
- Include Streamline server version, OS, and steps to reproduce

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
