# Changelog

All notable changes to this project will be documented in this file.
- refactor: simplify operator state machine transitions (2026-02-22)

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-19

### Added

- Initial WASM Transform Marketplace with registry and CLI.
- Transform registry (`registry/transforms.json`) with 10 built-in transform entries.
- Three example transform implementations:
  - `json-filter` - Filter messages by JSON field values with configurable conditions.
  - `timestamp-enricher` - Add `_processed_at` timestamps to JSON messages.
  - `pii-redactor` - Regex-based PII detection and redaction for emails, phones, and SSNs.
- CLI tool (`streamline-marketplace`) with commands:
  - `search` - Search transforms by query string.
  - `install` - Download and install a transform locally.
  - `publish` - Publish a new transform to the registry.
  - `list` - List installed transforms.
  - `info` - Show detailed transform information.
- GitHub Actions CI workflow for building transforms to `wasm32-wasip1`.
- Apache 2.0 license.
