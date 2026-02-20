# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in the Streamline WASM Transform Marketplace, please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub issue** for security vulnerabilities.
2. Email **security@streamlinelabs.dev** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment** within 48 hours of your report
- **Assessment** within 5 business days
- **Fix timeline** communicated once the issue is confirmed
- **Credit** in the release notes (unless you prefer anonymity)

## Security Considerations for Transforms

### WASM Sandbox

All transforms run inside a `wasmtime` WebAssembly sandbox with:
- No filesystem access (unless explicitly granted via WASI capabilities)
- No network access
- Memory isolation between transforms
- CPU time limits to prevent infinite loops

### Registry Integrity

- All transform entries include a `checksum` field (SHA-256 hash of the WASM binary)
- The CLI verifies checksums after download before installation
- The registry is version-controlled and changes require pull request review

### Supply Chain

- Official transforms in this repository are maintained by StreamlineLabs
- Community transforms should be reviewed before installation
- Always verify the `author` and `repository_url` fields before installing third-party transforms

## Best Practices for Transform Authors

- Never embed secrets or credentials in WASM modules
- Validate all input data before processing
- Handle malformed JSON gracefully (return pass-through, not panic)
- Use the `pii-redactor` transform for data that may contain sensitive information
- Keep dependencies minimal to reduce attack surface
