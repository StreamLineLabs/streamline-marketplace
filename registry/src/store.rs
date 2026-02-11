//! Persistence layer for the registry.
//!
//! Stores transform metadata in a JSON file and WASM binaries on disk.

use crate::TransformEntry;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// On-disk data store backed by a JSON file.
pub struct DataStore {
    /// `name -> (version -> entry)`
    pub transforms: BTreeMap<String, BTreeMap<String, TransformEntry>>,
    data_dir: PathBuf,
}

impl DataStore {
    /// Load (or initialize) the store from `data_dir`.
    ///
    /// If `data_dir/transforms.json` exists it is loaded; otherwise the store
    /// attempts to seed from `registry/transforms.json` (the flat-file
    /// registry that ships with the repo).
    pub fn load(data_dir: &str) -> Self {
        let data_dir = PathBuf::from(data_dir);
        std::fs::create_dir_all(&data_dir).ok();
        std::fs::create_dir_all(data_dir.join("wasm")).ok();

        let json_path = data_dir.join("transforms.json");
        let transforms = if json_path.exists() {
            Self::load_from_file(&json_path)
        } else {
            // Try to seed from the repo-level flat file
            let seed = data_dir.parent().and_then(|p| {
                let candidate = p.join("transforms.json");
                if candidate.exists() {
                    Some(candidate)
                } else {
                    None
                }
            });
            match seed {
                Some(path) => {
                    tracing::info!("Seeding from {}", path.display());
                    Self::load_from_file(&path)
                }
                None => BTreeMap::new(),
            }
        };

        Self {
            transforms,
            data_dir,
        }
    }

    fn load_from_file(path: &Path) -> BTreeMap<String, BTreeMap<String, TransformEntry>> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to read {}: {}", path.display(), e);
                return BTreeMap::new();
            }
        };

        // The flat file is Vec<TransformEntry>; the server file is the nested map.
        // Try nested first, fall back to flat.
        if let Ok(nested) = serde_json::from_str::<
            BTreeMap<String, BTreeMap<String, TransformEntry>>,
        >(&content)
        {
            return nested;
        }

        match serde_json::from_str::<Vec<TransformEntry>>(&content) {
            Ok(entries) => {
                let mut map: BTreeMap<String, BTreeMap<String, TransformEntry>> = BTreeMap::new();
                for e in entries {
                    map.entry(e.name.clone())
                        .or_default()
                        .insert(e.version.clone(), e);
                }
                map
            }
            Err(e) => {
                tracing::warn!("Failed to parse {}: {}", path.display(), e);
                BTreeMap::new()
            }
        }
    }

    /// Persist the current state to `data_dir/transforms.json`.
    pub fn save(&self) -> Result<(), String> {
        let path = self.data_dir.join("transforms.json");
        let json = serde_json::to_string_pretty(&self.transforms)
            .map_err(|e| format!("Serialization error: {}", e))?;
        std::fs::write(&path, json).map_err(|e| format!("Write error: {}", e))?;
        Ok(())
    }

    /// Canonical path for a WASM binary.
    pub fn wasm_path(&self, name: &str, version: &str) -> PathBuf {
        self.data_dir
            .join("wasm")
            .join(name)
            .join(version)
            .join(format!("{}.wasm", name.replace('-', "_")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_empty_dir() {
        let tmp = std::env::temp_dir().join("streamline-registry-test-empty");
        let _ = std::fs::remove_dir_all(&tmp);
        let store = DataStore::load(tmp.to_str().unwrap());
        assert!(store.transforms.is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_save_and_reload() {
        let tmp = std::env::temp_dir().join("streamline-registry-test-save");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let mut store = DataStore::load(tmp.to_str().unwrap());
        store
            .transforms
            .entry("test".into())
            .or_default()
            .insert(
                "0.1.0".into(),
                TransformEntry {
                    name: "test".into(),
                    version: "0.1.0".into(),
                    description: "d".into(),
                    author: "a".into(),
                    downloads: 0,
                    checksum: "".into(),
                    categories: vec![],
                    min_streamline_version: "".into(),
                    wasm_url: "".into(),
                    input_format: "json".into(),
                    output_format: "json".into(),
                    tags: vec![],
                    license: "".into(),
                    repository_url: "".into(),
                    config_schema: serde_json::Value::Null,
                },
            );
        store.save().unwrap();

        let store2 = DataStore::load(tmp.to_str().unwrap());
        assert!(store2.transforms.contains_key("test"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_wasm_path() {
        let tmp = std::env::temp_dir().join("streamline-registry-test-path");
        let store = DataStore {
            transforms: BTreeMap::new(),
            data_dir: tmp.clone(),
        };
        let p = store.wasm_path("json-filter", "0.1.0");
        assert!(p.ends_with("wasm/json-filter/0.1.0/json_filter.wasm"));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
