//! WASM security verification, sandboxing policies, and version management.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ─── Sandbox level ───────────────────────────────────────────────────────────

/// Controls how strict the WASM sandbox enforcement is.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SandboxLevel {
    /// No network, no filesystem, minimal WASI subset.
    Strict,
    /// Standard WASI imports allowed.
    Standard,
    /// All documented WASI imports allowed; advisory warnings only.
    Permissive,
}

// ─── Security policy ─────────────────────────────────────────────────────────

/// Configurable policy that governs what a WASM transform is allowed to do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmSecurityPolicy {
    pub max_binary_size_bytes: usize,
    pub max_memory_pages: u32,
    pub max_execution_time_ms: u64,
    pub allowed_imports: HashSet<String>,
    pub denied_imports: HashSet<String>,
    pub require_signature: bool,
    pub sandbox_level: SandboxLevel,
}

impl Default for WasmSecurityPolicy {
    fn default() -> Self {
        Self {
            max_binary_size_bytes: 10 * 1024 * 1024, // 10 MB
            max_memory_pages: 256,                    // 16 MB WASM memory
            max_execution_time_ms: 5000,
            allowed_imports: SecurityAuditor::default_allowed_imports(),
            denied_imports: HashSet::new(),
            require_signature: false,
            sandbox_level: SandboxLevel::Standard,
        }
    }
}

// ─── Violation severity ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

// ─── Security audit types ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmImport {
    pub module: String,
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmExport {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityViolation {
    pub severity: Severity,
    pub rule: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAudit {
    pub transform_name: String,
    pub binary_size_bytes: usize,
    pub imports: Vec<WasmImport>,
    pub exports: Vec<WasmExport>,
    pub violations: Vec<SecurityViolation>,
    /// 0 = no risk, 100 = maximum risk.
    pub risk_score: u8,
    pub passed: bool,
}

// ─── Version management ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedVersion {
    pub version: String,
    pub checksum: String,
    pub published_at: String,
    pub yanked: bool,
    pub changelog: Option<String>,
    pub min_streamline_version: String,
}

/// Tracks all published versions per transform name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionManager {
    versions: HashMap<String, Vec<PublishedVersion>>,
}

impl VersionManager {
    pub fn new() -> Self {
        Self {
            versions: HashMap::new(),
        }
    }

    /// Register a new published version.
    pub fn publish_version(&mut self, name: &str, version: PublishedVersion) -> Result<(), String> {
        let list = self.versions.entry(name.to_string()).or_default();
        if list.iter().any(|v| v.version == version.version) {
            return Err(format!(
                "Version {} already exists for '{}'",
                version.version, name
            ));
        }
        list.push(version);
        Ok(())
    }

    /// Mark a version as yanked (still visible but should not be installed).
    pub fn yank_version(&mut self, name: &str, version: &str) -> Result<(), String> {
        let list = self
            .versions
            .get_mut(name)
            .ok_or_else(|| format!("Transform '{}' not found", name))?;
        let entry = list
            .iter_mut()
            .find(|v| v.version == version)
            .ok_or_else(|| format!("Version {} not found for '{}'", version, name))?;
        entry.yanked = true;
        Ok(())
    }

    /// Return the latest non-yanked version, if any.
    pub fn get_latest(&self, name: &str) -> Option<&PublishedVersion> {
        self.versions
            .get(name)
            .and_then(|list| list.iter().rev().find(|v| !v.yanked))
    }

    /// Look up a specific version.
    pub fn get_version(&self, name: &str, version: &str) -> Option<&PublishedVersion> {
        self.versions
            .get(name)
            .and_then(|list| list.iter().find(|v| v.version == version))
    }

    /// List all versions for a transform (newest last).
    pub fn list_versions(&self, name: &str) -> Vec<&PublishedVersion> {
        self.versions
            .get(name)
            .map(|list| list.iter().collect())
            .unwrap_or_default()
    }

    /// Simple semver-compatible compatibility check.
    ///
    /// A version is compatible when `min_streamline_version` ≤ the provided
    /// `streamline_version`.  Both values are expected in `major.minor.patch`
    /// format; we compare component-wise.
    pub fn is_compatible(version: &PublishedVersion, streamline_version: &str) -> bool {
        parse_semver(&version.min_streamline_version) <= parse_semver(streamline_version)
    }
}

impl Default for VersionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a `"major.minor.patch"` string into a comparable tuple.
fn parse_semver(s: &str) -> (u64, u64, u64) {
    let parts: Vec<u64> = s.split('.').filter_map(|p| p.parse().ok()).collect();
    (
        parts.first().copied().unwrap_or(0),
        parts.get(1).copied().unwrap_or(0),
        parts.get(2).copied().unwrap_or(0),
    )
}

// ─── Security auditor ────────────────────────────────────────────────────────

/// Inspects raw WASM bytes and produces a [`SecurityAudit`].
pub struct SecurityAuditor {
    policy: WasmSecurityPolicy,
}

impl SecurityAuditor {
    pub fn new(policy: WasmSecurityPolicy) -> Self {
        Self { policy }
    }

    /// Canonical set of WASI preview-1 imports considered safe.
    pub fn default_allowed_imports() -> HashSet<String> {
        [
            "fd_write",
            "fd_read",
            "fd_close",
            "fd_seek",
            "fd_prestat_get",
            "fd_prestat_dir_name",
            "environ_get",
            "environ_sizes_get",
            "args_get",
            "args_sizes_get",
            "clock_time_get",
            "proc_exit",
            "random_get",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// Run a full audit on raw WASM bytes.
    pub fn audit_binary(&self, name: &str, wasm_bytes: &[u8]) -> SecurityAudit {
        let mut violations = Vec::new();
        let binary_size_bytes = wasm_bytes.len();

        // 1. Size check
        if binary_size_bytes > self.policy.max_binary_size_bytes {
            violations.push(SecurityViolation {
                severity: Severity::High,
                rule: "max_binary_size".into(),
                message: format!(
                    "Binary size {} exceeds maximum {}",
                    binary_size_bytes, self.policy.max_binary_size_bytes
                ),
            });
        }

        // 2. Magic & version header
        let valid_header = wasm_bytes.len() >= 8
            && &wasm_bytes[0..4] == b"\0asm"
            && u32::from_le_bytes([wasm_bytes[4], wasm_bytes[5], wasm_bytes[6], wasm_bytes[7]])
                == 1;

        if !valid_header {
            violations.push(SecurityViolation {
                severity: Severity::Critical,
                rule: "invalid_wasm_header".into(),
                message: "Missing or invalid WASM magic header (\\0asm v1)".into(),
            });
        }

        // 3 & 4. Parse import (section 2) and export (section 7) sections
        let imports = if valid_header {
            Self::parse_imports(wasm_bytes)
        } else {
            Vec::new()
        };

        let exports = if valid_header {
            Self::parse_exports(wasm_bytes)
        } else {
            Vec::new()
        };

        // 5. Check imports against policy
        for imp in &imports {
            if self.policy.denied_imports.contains(&imp.name) {
                violations.push(SecurityViolation {
                    severity: Severity::Critical,
                    rule: "denied_import".into(),
                    message: format!("Import '{}::{}' is explicitly denied", imp.module, imp.name),
                });
            } else if !self.policy.allowed_imports.contains(&imp.name) {
                let sev = match self.policy.sandbox_level {
                    SandboxLevel::Strict => Severity::High,
                    SandboxLevel::Standard => Severity::Medium,
                    SandboxLevel::Permissive => Severity::Low,
                };
                violations.push(SecurityViolation {
                    severity: sev,
                    rule: "unlisted_import".into(),
                    message: format!(
                        "Import '{}::{}' is not in the allowed set",
                        imp.module, imp.name
                    ),
                });
            }
        }

        // 6. Risk score
        let risk_score = Self::calculate_risk_score(&violations);
        let passed = !violations
            .iter()
            .any(|v| matches!(v.severity, Severity::Critical | Severity::High));

        SecurityAudit {
            transform_name: name.to_string(),
            binary_size_bytes,
            imports,
            exports,
            violations,
            risk_score,
            passed,
        }
    }

    // ── WASM binary parsing helpers ──────────────────────────────────────

    /// Read a LEB128 unsigned integer starting at `pos`.  Returns `(value, bytes_consumed)`.
    fn read_leb128(bytes: &[u8], pos: usize) -> Option<(u32, usize)> {
        let mut result: u32 = 0;
        let mut shift = 0u32;
        let mut i = pos;
        loop {
            if i >= bytes.len() {
                return None;
            }
            let byte = bytes[i];
            result |= ((byte & 0x7F) as u32) << shift;
            i += 1;
            if byte & 0x80 == 0 {
                return Some((result, i - pos));
            }
            shift += 7;
            if shift >= 35 {
                return None;
            }
        }
    }

    /// Read a length-prefixed UTF-8 name.
    fn read_name(bytes: &[u8], pos: usize) -> Option<(String, usize)> {
        let (len, consumed) = Self::read_leb128(bytes, pos)?;
        let start = pos + consumed;
        let end = start + len as usize;
        if end > bytes.len() {
            return None;
        }
        let s = String::from_utf8_lossy(&bytes[start..end]).to_string();
        Some((s, consumed + len as usize))
    }

    /// Locate and parse section `target_id` from the binary.
    fn find_section(bytes: &[u8], target_id: u8) -> Option<(usize, usize)> {
        let mut pos = 8; // skip magic + version
        while pos < bytes.len() {
            let section_id = bytes[pos];
            pos += 1;
            let (section_len, consumed) = Self::read_leb128(bytes, pos)?;
            pos += consumed;
            if section_id == target_id {
                return Some((pos, section_len as usize));
            }
            pos += section_len as usize;
        }
        None
    }

    fn extern_kind_name(kind: u8) -> &'static str {
        match kind {
            0x00 => "function",
            0x01 => "table",
            0x02 => "memory",
            0x03 => "global",
            _ => "unknown",
        }
    }

    /// Parse the import section (id 2).
    fn parse_imports(bytes: &[u8]) -> Vec<WasmImport> {
        let mut result = Vec::new();
        let (start, _section_len) = match Self::find_section(bytes, 2) {
            Some(s) => s,
            None => return result,
        };

        let mut pos = start;
        let (count, consumed) = match Self::read_leb128(bytes, pos) {
            Some(v) => v,
            None => return result,
        };
        pos += consumed;

        for _ in 0..count {
            let (module, mc) = match Self::read_name(bytes, pos) {
                Some(v) => v,
                None => break,
            };
            pos += mc;
            let (name, nc) = match Self::read_name(bytes, pos) {
                Some(v) => v,
                None => break,
            };
            pos += nc;

            if pos >= bytes.len() {
                break;
            }
            let kind_byte = bytes[pos];
            pos += 1;

            // Skip the type description that follows the kind byte.
            match kind_byte {
                0x00 => {
                    // function: typeidx
                    if let Some((_, c)) = Self::read_leb128(bytes, pos) {
                        pos += c;
                    }
                }
                0x01 => {
                    // table: reftype + limits
                    pos += 1; // reftype
                    if let Some(skip) = Self::skip_limits(bytes, pos) {
                        pos += skip;
                    }
                }
                0x02 => {
                    // memory: limits
                    if let Some(skip) = Self::skip_limits(bytes, pos) {
                        pos += skip;
                    }
                }
                0x03 => {
                    // global: valtype + mut
                    pos += 2;
                }
                _ => break,
            }

            result.push(WasmImport {
                module,
                name,
                kind: Self::extern_kind_name(kind_byte).into(),
            });
        }
        result
    }

    /// Parse the export section (id 7).
    fn parse_exports(bytes: &[u8]) -> Vec<WasmExport> {
        let mut result = Vec::new();
        let (start, _section_len) = match Self::find_section(bytes, 7) {
            Some(s) => s,
            None => return result,
        };

        let mut pos = start;
        let (count, consumed) = match Self::read_leb128(bytes, pos) {
            Some(v) => v,
            None => return result,
        };
        pos += consumed;

        for _ in 0..count {
            let (name, nc) = match Self::read_name(bytes, pos) {
                Some(v) => v,
                None => break,
            };
            pos += nc;

            if pos >= bytes.len() {
                break;
            }
            let kind_byte = bytes[pos];
            pos += 1;

            // export index
            if let Some((_, c)) = Self::read_leb128(bytes, pos) {
                pos += c;
            } else {
                break;
            }

            result.push(WasmExport {
                name,
                kind: Self::extern_kind_name(kind_byte).into(),
            });
        }
        result
    }

    /// Skip over a WASM limits encoding (flag byte + LEB128 min [+ LEB128 max]).
    fn skip_limits(bytes: &[u8], pos: usize) -> Option<usize> {
        if pos >= bytes.len() {
            return None;
        }
        let flag = bytes[pos];
        let mut offset = 1;
        let (_, c) = Self::read_leb128(bytes, pos + offset)?;
        offset += c;
        if flag == 1 {
            let (_, c2) = Self::read_leb128(bytes, pos + offset)?;
            offset += c2;
        }
        Some(offset)
    }

    /// Compute a 0-100 risk score from a set of violations.
    fn calculate_risk_score(violations: &[SecurityViolation]) -> u8 {
        let score: u32 = violations
            .iter()
            .map(|v| match v.severity {
                Severity::Critical => 40,
                Severity::High => 25,
                Severity::Medium => 10,
                Severity::Low => 5,
                Severity::Info => 1,
            })
            .sum();
        std::cmp::min(score, 100) as u8
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid WASM module (no imports, no exports).
    fn minimal_wasm() -> Vec<u8> {
        vec![
            0x00, 0x61, 0x73, 0x6D, // \0asm
            0x01, 0x00, 0x00, 0x00, // version 1
        ]
    }

    /// Build a WASM binary with a single import: `wasi_snapshot_preview1.fd_write` (func).
    fn wasm_with_import(module: &str, name: &str) -> Vec<u8> {
        let mut buf = vec![
            0x00, 0x61, 0x73, 0x6D, // magic
            0x01, 0x00, 0x00, 0x00, // version
        ];

        // ── Type section (section 1): one func type () -> () ──
        // section id
        buf.push(0x01);
        // section contents: count=1, func-type marker, 0 params, 0 results
        let type_body = vec![0x01, 0x60, 0x00, 0x00];
        leb128_push(&mut buf, type_body.len() as u32);
        buf.extend_from_slice(&type_body);

        // ── Import section (section 2) ──
        buf.push(0x02);
        let mut import_body = Vec::new();
        leb128_push(&mut import_body, 1); // count = 1
        // module name
        leb128_push(&mut import_body, module.len() as u32);
        import_body.extend_from_slice(module.as_bytes());
        // import name
        leb128_push(&mut import_body, name.len() as u32);
        import_body.extend_from_slice(name.as_bytes());
        // kind = function (0x00), typeidx = 0
        import_body.push(0x00);
        leb128_push(&mut import_body, 0);

        leb128_push(&mut buf, import_body.len() as u32);
        buf.extend_from_slice(&import_body);

        buf
    }

    /// Build a WASM binary with a single export.
    fn wasm_with_export(name: &str) -> Vec<u8> {
        let mut buf = vec![
            0x00, 0x61, 0x73, 0x6D,
            0x01, 0x00, 0x00, 0x00,
        ];

        // ── Type section ──
        buf.push(0x01);
        let type_body = vec![0x01, 0x60, 0x00, 0x00];
        leb128_push(&mut buf, type_body.len() as u32);
        buf.extend_from_slice(&type_body);

        // ── Function section (section 3): one function of type 0 ──
        buf.push(0x03);
        let func_body = vec![0x01, 0x00];
        leb128_push(&mut buf, func_body.len() as u32);
        buf.extend_from_slice(&func_body);

        // ── Code section (section 10): empty body ──
        buf.push(0x0A);
        let code_body = vec![0x01, 0x02, 0x00, 0x0B]; // count=1, body-size=2, no locals, end
        leb128_push(&mut buf, code_body.len() as u32);
        buf.extend_from_slice(&code_body);

        // ── Export section (section 7) ──
        buf.push(0x07);
        let mut export_body = Vec::new();
        leb128_push(&mut export_body, 1); // count
        leb128_push(&mut export_body, name.len() as u32);
        export_body.extend_from_slice(name.as_bytes());
        export_body.push(0x00); // kind = function
        leb128_push(&mut export_body, 0); // func index
        leb128_push(&mut buf, export_body.len() as u32);
        buf.extend_from_slice(&export_body);

        buf
    }

    fn leb128_push(buf: &mut Vec<u8>, mut val: u32) {
        loop {
            let mut byte = (val & 0x7F) as u8;
            val >>= 7;
            if val != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if val == 0 {
                break;
            }
        }
    }

    // ── Policy / defaults ────────────────────────────────────────────────

    #[test]
    fn test_default_policy() {
        let p = WasmSecurityPolicy::default();
        assert_eq!(p.max_binary_size_bytes, 10 * 1024 * 1024);
        assert_eq!(p.max_memory_pages, 256);
        assert_eq!(p.max_execution_time_ms, 5000);
        assert!(!p.require_signature);
        assert_eq!(p.sandbox_level, SandboxLevel::Standard);
    }

    #[test]
    fn test_default_allowed_imports() {
        let imports = SecurityAuditor::default_allowed_imports();
        assert!(imports.contains("fd_write"));
        assert!(imports.contains("proc_exit"));
        assert!(imports.contains("random_get"));
        assert!(!imports.contains("sock_connect"));
    }

    // ── Audit: header validation ─────────────────────────────────────────

    #[test]
    fn test_audit_valid_minimal_wasm() {
        let auditor = SecurityAuditor::new(WasmSecurityPolicy::default());
        let audit = auditor.audit_binary("test", &minimal_wasm());
        assert!(audit.passed);
        assert_eq!(audit.risk_score, 0);
        assert!(audit.violations.is_empty());
    }

    #[test]
    fn test_audit_invalid_header() {
        let auditor = SecurityAuditor::new(WasmSecurityPolicy::default());
        let audit = auditor.audit_binary("bad", &[0xFF, 0x00, 0x00, 0x00]);
        assert!(!audit.passed);
        assert!(audit
            .violations
            .iter()
            .any(|v| v.rule == "invalid_wasm_header"));
    }

    #[test]
    fn test_audit_empty_bytes() {
        let auditor = SecurityAuditor::new(WasmSecurityPolicy::default());
        let audit = auditor.audit_binary("empty", &[]);
        assert!(!audit.passed);
    }

    // ── Audit: size check ────────────────────────────────────────────────

    #[test]
    fn test_audit_oversized_binary() {
        let mut policy = WasmSecurityPolicy::default();
        policy.max_binary_size_bytes = 4;
        let auditor = SecurityAuditor::new(policy);
        let audit = auditor.audit_binary("big", &minimal_wasm());
        assert!(audit
            .violations
            .iter()
            .any(|v| v.rule == "max_binary_size"));
    }

    // ── Audit: imports ───────────────────────────────────────────────────

    #[test]
    fn test_audit_allowed_import() {
        let auditor = SecurityAuditor::new(WasmSecurityPolicy::default());
        let wasm = wasm_with_import("wasi_snapshot_preview1", "fd_write");
        let audit = auditor.audit_binary("ok-import", &wasm);
        assert!(audit.passed);
        assert_eq!(audit.imports.len(), 1);
        assert_eq!(audit.imports[0].name, "fd_write");
    }

    #[test]
    fn test_audit_unlisted_import_standard() {
        let auditor = SecurityAuditor::new(WasmSecurityPolicy::default());
        let wasm = wasm_with_import("wasi_snapshot_preview1", "sock_connect");
        let audit = auditor.audit_binary("net", &wasm);
        assert!(audit
            .violations
            .iter()
            .any(|v| v.rule == "unlisted_import" && v.severity == Severity::Medium));
        // Standard sandbox: medium severity → still passes
        assert!(audit.passed);
    }

    #[test]
    fn test_audit_denied_import() {
        let mut policy = WasmSecurityPolicy::default();
        policy.denied_imports.insert("evil_func".into());
        let auditor = SecurityAuditor::new(policy);
        let wasm = wasm_with_import("env", "evil_func");
        let audit = auditor.audit_binary("evil", &wasm);
        assert!(!audit.passed);
        assert!(audit
            .violations
            .iter()
            .any(|v| v.rule == "denied_import" && v.severity == Severity::Critical));
    }

    #[test]
    fn test_audit_strict_unlisted_import() {
        let mut policy = WasmSecurityPolicy::default();
        policy.sandbox_level = SandboxLevel::Strict;
        let auditor = SecurityAuditor::new(policy);
        let wasm = wasm_with_import("env", "custom_func");
        let audit = auditor.audit_binary("strict", &wasm);
        assert!(!audit.passed);
        assert!(audit
            .violations
            .iter()
            .any(|v| v.severity == Severity::High));
    }

    // ── Audit: exports ───────────────────────────────────────────────────

    #[test]
    fn test_audit_exports() {
        let auditor = SecurityAuditor::new(WasmSecurityPolicy::default());
        let wasm = wasm_with_export("transform");
        let audit = auditor.audit_binary("exp", &wasm);
        assert!(audit.passed);
        assert_eq!(audit.exports.len(), 1);
        assert_eq!(audit.exports[0].name, "transform");
        assert_eq!(audit.exports[0].kind, "function");
    }

    // ── Risk score ───────────────────────────────────────────────────────

    #[test]
    fn test_risk_score_caps_at_100() {
        let violations: Vec<SecurityViolation> = (0..10)
            .map(|i| SecurityViolation {
                severity: Severity::Critical,
                rule: format!("rule_{}", i),
                message: "x".into(),
            })
            .collect();
        assert_eq!(SecurityAuditor::calculate_risk_score(&violations), 100);
    }

    // ── Version manager ──────────────────────────────────────────────────

    fn sample_version(ver: &str) -> PublishedVersion {
        PublishedVersion {
            version: ver.into(),
            checksum: format!("sha256:{}", ver),
            published_at: "2025-01-01T00:00:00Z".into(),
            yanked: false,
            changelog: None,
            min_streamline_version: "0.2.0".into(),
        }
    }

    #[test]
    fn test_version_publish_and_list() {
        let mut vm = VersionManager::new();
        vm.publish_version("t", sample_version("0.1.0")).unwrap();
        vm.publish_version("t", sample_version("0.2.0")).unwrap();
        assert_eq!(vm.list_versions("t").len(), 2);
    }

    #[test]
    fn test_version_duplicate_rejected() {
        let mut vm = VersionManager::new();
        vm.publish_version("t", sample_version("0.1.0")).unwrap();
        assert!(vm.publish_version("t", sample_version("0.1.0")).is_err());
    }

    #[test]
    fn test_version_yank() {
        let mut vm = VersionManager::new();
        vm.publish_version("t", sample_version("0.1.0")).unwrap();
        vm.yank_version("t", "0.1.0").unwrap();
        assert!(vm.get_version("t", "0.1.0").unwrap().yanked);
        assert!(vm.get_latest("t").is_none());
    }

    #[test]
    fn test_version_get_latest_skips_yanked() {
        let mut vm = VersionManager::new();
        vm.publish_version("t", sample_version("0.1.0")).unwrap();
        vm.publish_version("t", sample_version("0.2.0")).unwrap();
        vm.yank_version("t", "0.2.0").unwrap();
        assert_eq!(vm.get_latest("t").unwrap().version, "0.1.0");
    }

    #[test]
    fn test_version_compatibility() {
        let v = PublishedVersion {
            min_streamline_version: "0.3.0".into(),
            ..sample_version("1.0.0")
        };
        assert!(VersionManager::is_compatible(&v, "0.3.0"));
        assert!(VersionManager::is_compatible(&v, "1.0.0"));
        assert!(!VersionManager::is_compatible(&v, "0.2.9"));
    }

    #[test]
    fn test_version_unknown_transform() {
        let mut vm = VersionManager::new();
        assert!(vm.yank_version("nope", "0.1.0").is_err());
        assert!(vm.get_latest("nope").is_none());
        assert!(vm.list_versions("nope").is_empty());
    }

    // ── Serialization round-trip ─────────────────────────────────────────

    #[test]
    fn test_policy_serde_roundtrip() {
        let policy = WasmSecurityPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let restored: WasmSecurityPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.max_binary_size_bytes, policy.max_binary_size_bytes);
        assert_eq!(restored.sandbox_level, policy.sandbox_level);
    }

    #[test]
    fn test_audit_serde_roundtrip() {
        let auditor = SecurityAuditor::new(WasmSecurityPolicy::default());
        let audit = auditor.audit_binary("test", &minimal_wasm());
        let json = serde_json::to_string(&audit).unwrap();
        let restored: SecurityAudit = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.transform_name, "test");
        assert_eq!(restored.passed, audit.passed);
    }
}
