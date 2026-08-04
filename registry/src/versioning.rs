// The version-manager API is exercised by this module's unit tests but is not
// yet wired into the registry binary's publish path, so its items look unused
// to the non-test build.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    /// A version is compatible when `min_streamline_version` <= the provided
    /// `streamline_version`. Both values are expected in `major.minor.patch`
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
