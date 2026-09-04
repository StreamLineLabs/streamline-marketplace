//! Persistence layer for the registry.
//!
//! Stores transform metadata in a JSON file and WASM binaries on disk.

use crate::TransformEntry;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// Maximum accepted length of a transform name or version component.
const MAX_COMPONENT_LEN: usize = 128;

/// Errors raised while loading or addressing the store.
#[derive(Debug)]
pub enum StoreError {
    /// The data directory could not be created.
    DataDir { path: PathBuf, source: String },
    /// A catalog file could not be read.
    Read { path: PathBuf, source: String },
    /// A catalog file exists but could not be parsed in any supported shape.
    Parse { path: PathBuf, source: String },
    /// A name or version is not usable as a path component.
    InvalidComponent { field: &'static str, value: String },
    /// A resolved path escaped the data directory.
    PathEscape(PathBuf),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DataDir { path, source } => {
                write!(
                    f,
                    "failed to prepare data directory {}: {source}",
                    path.display()
                )
            }
            Self::Read { path, source } => {
                write!(f, "failed to read {}: {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(f, "failed to parse {}: {source}", path.display())
            }
            Self::InvalidComponent { field, value } => write!(
                f,
                "invalid {field} '{value}': expected 1-{MAX_COMPONENT_LEN} characters from \
                 [A-Za-z0-9._-] that do not start with '.'"
            ),
            Self::PathEscape(path) => write!(
                f,
                "resolved path {} escapes the registry data directory",
                path.display()
            ),
        }
    }
}

impl std::error::Error for StoreError {}

/// True when `value` is safe to use as a single filesystem path component.
fn is_safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_COMPONENT_LEN
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// Lexically normalize a path (no filesystem access, no symlink resolution).
///
/// `.` segments are dropped and `..` segments pop the preceding component. A
/// leading `..` on a relative path is preserved (there is nothing to pop, and
/// dropping it would silently retarget the path at the current directory), and
/// `..` can never escape a root or prefix on an absolute path.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let poppable = out.components().next_back().is_some_and(|last| {
                    !matches!(
                        last,
                        Component::RootDir | Component::Prefix(_) | Component::ParentDir
                    )
                });
                if poppable {
                    out.pop();
                } else if !out.has_root() {
                    out.push(Component::ParentDir.as_os_str());
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Resolve a configured data directory to the single root this store uses.
///
/// Relative values — including ones beginning with `..` — are made absolute
/// against the current working directory and then normalized, so every path the
/// store derives (`transforms.json`, `wasm/...`) is rooted identically. This is
/// done once, at load time, rather than at each call site.
///
/// Resolution is lexical: the directory need not exist yet and symlinks are not
/// followed. If the current directory cannot be read, the value is normalized
/// as-is; that is strictly better than failing to start, and the store still
/// uses one consistent root.
fn resolve_data_dir(data_dir: &Path) -> PathBuf {
    if data_dir.is_absolute() {
        return normalize(data_dir);
    }
    match std::env::current_dir() {
        Ok(cwd) => normalize(&cwd.join(data_dir)),
        Err(_) => normalize(data_dir),
    }
}

/// On-disk data store backed by a JSON file.
#[derive(Debug)]
pub struct DataStore {
    /// `name -> (version -> entry)`
    pub transforms: BTreeMap<String, BTreeMap<String, TransformEntry>>,
    /// Absolute, normalized root for every path this store derives.
    data_dir: PathBuf,
}

impl DataStore {
    /// Load (or initialize) the store from `data_dir`.
    ///
    /// `data_dir` is resolved once here (made absolute and normalized) and that
    /// resolved value is the only root the store ever uses, so a relative or
    /// `..`-containing configuration addresses the same directory from
    /// [`Self::save`] and [`Self::wasm_path`].
    ///
    /// If `data_dir/transforms.json` exists it is loaded; otherwise the store
    /// attempts to seed from `registry/transforms.json` (the flat-file
    /// registry that ships with the repo).
    ///
    /// I/O and parse failures are propagated: a transient permission problem or
    /// a corrupt catalog must never look like a valid empty registry.
    pub fn load(data_dir: &str) -> Result<Self, StoreError> {
        let data_dir = resolve_data_dir(Path::new(data_dir));
        for dir in [data_dir.clone(), data_dir.join("wasm")] {
            std::fs::create_dir_all(&dir).map_err(|e| StoreError::DataDir {
                path: dir.clone(),
                source: e.to_string(),
            })?;
        }

        let json_path = data_dir.join("transforms.json");
        let transforms = if json_path.exists() {
            Self::load_from_file(&json_path)?
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
                    Self::load_from_file(&path)?
                }
                None => BTreeMap::new(),
            }
        };

        Ok(Self {
            transforms,
            data_dir,
        })
    }

    fn load_from_file(
        path: &Path,
    ) -> Result<BTreeMap<String, BTreeMap<String, TransformEntry>>, StoreError> {
        let content = std::fs::read_to_string(path).map_err(|e| StoreError::Read {
            path: path.to_path_buf(),
            source: e.to_string(),
        })?;

        // The flat file is Vec<TransformEntry>; the server file is the nested map.
        // Try nested first, fall back to flat.
        if let Ok(nested) =
            serde_json::from_str::<BTreeMap<String, BTreeMap<String, TransformEntry>>>(&content)
        {
            return Ok(nested);
        }

        match serde_json::from_str::<Vec<TransformEntry>>(&content) {
            Ok(entries) => {
                let mut map: BTreeMap<String, BTreeMap<String, TransformEntry>> = BTreeMap::new();
                for e in entries {
                    map.entry(e.name.clone())
                        .or_default()
                        .insert(e.version.clone(), e);
                }
                Ok(map)
            }
            Err(e) => Err(StoreError::Parse {
                path: path.to_path_buf(),
                source: e.to_string(),
            }),
        }
    }

    /// Persist the current state to `data_dir/transforms.json`.
    pub fn save(&self) -> Result<(), String> {
        let path = self.catalog_path();
        let json = serde_json::to_string_pretty(&self.transforms)
            .map_err(|e| format!("Serialization error: {}", e))?;
        std::fs::write(&path, json).map_err(|e| format!("Write error: {}", e))?;
        Ok(())
    }

    /// The single root every derived path is built from.
    ///
    /// [`Self::load`] already resolves `data_dir`, so this is a no-op there;
    /// normalizing again keeps directly constructed stores consistent too.
    fn root(&self) -> PathBuf {
        normalize(&self.data_dir)
    }

    /// Path of the catalog file written by [`Self::save`].
    fn catalog_path(&self) -> PathBuf {
        self.root().join("transforms.json")
    }

    /// Canonical path for a WASM binary.
    ///
    /// `name` and `version` are validated as single, traversal-free path
    /// components, and the resolved path is checked to stay under
    /// `data_dir/wasm`.
    pub fn wasm_path(&self, name: &str, version: &str) -> Result<PathBuf, StoreError> {
        if !is_safe_component(name) {
            return Err(StoreError::InvalidComponent {
                field: "transform name",
                value: name.to_string(),
            });
        }
        if !is_safe_component(version) {
            return Err(StoreError::InvalidComponent {
                field: "transform version",
                value: version.to_string(),
            });
        }

        let root = self.root().join("wasm");
        let candidate = normalize(
            &root
                .join(name)
                .join(version)
                .join(format!("{}.wasm", name.replace('-', "_"))),
        );
        if !candidate.starts_with(&root) {
            return Err(StoreError::PathEscape(candidate));
        }
        Ok(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("streamline-registry-test-{label}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// A relative path that begins with `..` yet resolves back under the
    /// current directory, e.g. `../<cwd-name>/target/store-tests/<label>`.
    ///
    /// Building it from the live working directory keeps the test independent
    /// of where the harness is invoked from.
    fn relative_parent_dir(label: &str) -> (String, PathBuf) {
        let cwd = std::env::current_dir().expect("cwd");
        let cwd_name = cwd
            .file_name()
            .expect("cwd has a final component")
            .to_str()
            .expect("cwd is UTF-8")
            .to_string();
        let suffix = format!("target/store-tests/{label}");
        let relative = format!("../{cwd_name}/{suffix}");
        let absolute = cwd.join(&suffix);
        let _ = std::fs::remove_dir_all(&absolute);
        (relative, absolute)
    }

    /// A minimal catalog entry for persistence tests.
    fn entry(name: &str, version: &str) -> TransformEntry {
        TransformEntry {
            name: name.into(),
            version: version.into(),
            description: "d".into(),
            author: "a".into(),
            downloads: 0,
            checksum: String::new(),
            categories: vec![],
            min_streamline_version: String::new(),
            wasm_url: String::new(),
            input_format: "json".into(),
            output_format: "json".into(),
            tags: vec![],
            license: String::new(),
            repository_url: String::new(),
            config_schema: serde_json::Value::Null,
        }
    }

    #[test]
    fn test_load_empty_dir() {
        let tmp = temp_dir("empty");
        let store = DataStore::load(tmp.to_str().unwrap()).unwrap();
        assert!(store.transforms.is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_save_and_reload() {
        let tmp = temp_dir("save");
        std::fs::create_dir_all(&tmp).unwrap();

        let mut store = DataStore::load(tmp.to_str().unwrap()).unwrap();
        store
            .transforms
            .entry("test".into())
            .or_default()
            .insert("0.1.0".into(), entry("test", "0.1.0"));
        store.save().unwrap();

        let store2 = DataStore::load(tmp.to_str().unwrap()).unwrap();
        assert!(store2.transforms.contains_key("test"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_corrupt_catalog_is_propagated_not_silently_empty() {
        let tmp = temp_dir("corrupt");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("transforms.json"), b"{ not json at all").unwrap();

        let err = DataStore::load(tmp.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, StoreError::Parse { .. }), "got {err:?}");
        // The unreadable data is preserved for recovery.
        assert_eq!(
            std::fs::read_to_string(tmp.join("transforms.json")).unwrap(),
            "{ not json at all"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_unreadable_catalog_is_propagated() {
        let tmp = temp_dir("unreadable");
        // A directory named transforms.json exists but cannot be read as a file.
        std::fs::create_dir_all(tmp.join("transforms.json")).unwrap();
        let err = DataStore::load(tmp.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, StoreError::Read { .. }), "got {err:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_data_dir_creation_failure_is_propagated() {
        let tmp = temp_dir("nodir");
        std::fs::create_dir_all(tmp.parent().unwrap()).unwrap();
        // A regular file cannot also be a directory.
        std::fs::write(&tmp, b"blocked").unwrap();
        let err = DataStore::load(tmp.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, StoreError::DataDir { .. }), "got {err:?}");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_wasm_path() {
        let store = DataStore {
            transforms: BTreeMap::new(),
            data_dir: PathBuf::from("/srv/registry"),
        };
        let p = store.wasm_path("json-filter", "0.1.0").unwrap();
        assert!(p.ends_with("wasm/json-filter/0.1.0/json_filter.wasm"));
        assert!(p.starts_with("/srv/registry/wasm"));
    }

    #[test]
    fn test_wasm_path_rejects_traversal_and_separators() {
        let store = DataStore {
            transforms: BTreeMap::new(),
            data_dir: PathBuf::from("/srv/registry"),
        };

        for (name, version) in [
            ("..", "0.1.0"),
            ("../../etc", "0.1.0"),
            ("ok", ".."),
            ("ok", "../../.."),
            ("a/b", "0.1.0"),
            ("ok", "0.1.0/../../.."),
            ("a\\b", "0.1.0"),
            ("", "0.1.0"),
            ("ok", ""),
            (".hidden", "0.1.0"),
            ("/etc/passwd", "0.1.0"),
            ("ok", "/abs"),
            ("naïve", "0.1.0"),
            ("ok\0evil", "0.1.0"),
        ] {
            let err = store
                .wasm_path(name, version)
                .expect_err("expected rejection for ({name:?}, {version:?})");
            assert!(
                matches!(err, StoreError::InvalidComponent { .. }),
                "unexpected error for ({name:?}, {version:?}): {err:?}"
            );
        }

        let too_long = "a".repeat(MAX_COMPONENT_LEN + 1);
        assert!(store.wasm_path(&too_long, "0.1.0").is_err());
    }

    #[test]
    fn test_wasm_path_stays_under_data_dir() {
        let store = DataStore {
            transforms: BTreeMap::new(),
            data_dir: PathBuf::from("/srv/registry/../registry"),
        };
        let p = store.wasm_path("json-filter", "0.1.0").unwrap();
        assert!(p.starts_with("/srv/registry/wasm"), "{}", p.display());
    }

    #[test]
    fn test_normalize_keeps_leading_parent_and_never_escapes_root() {
        // A leading `..` on a relative path must survive: dropping it would
        // silently retarget the path at the current directory.
        assert_eq!(
            normalize(Path::new("../shared/data")),
            PathBuf::from("../shared/data")
        );
        assert_eq!(
            normalize(Path::new("../../a/./b/../c")),
            PathBuf::from("../../a/c")
        );
        assert_eq!(normalize(Path::new("a/../../b")), PathBuf::from("../b"));
        // `..` cannot climb above an absolute root.
        assert_eq!(normalize(Path::new("/../../etc")), PathBuf::from("/etc"));
        assert_eq!(
            normalize(Path::new("/srv/registry/../registry")),
            PathBuf::from("/srv/registry")
        );
    }

    #[test]
    fn test_resolve_data_dir_absolutizes_relative_parent_path() {
        let cwd = std::env::current_dir().unwrap();
        let resolved = resolve_data_dir(Path::new("../shared/data"));
        assert!(resolved.is_absolute(), "{}", resolved.display());
        assert_eq!(resolved, normalize(&cwd.join("../shared/data")));
        assert_eq!(resolved, cwd.parent().unwrap().join("shared/data"));
        // No `..`/`.` survives resolution.
        assert!(!resolved
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir)));

        // Absolute inputs are normalized but otherwise untouched.
        assert_eq!(
            resolve_data_dir(Path::new("/srv/registry/../registry/./data")),
            PathBuf::from("/srv/registry/data")
        );
    }

    #[test]
    fn test_relative_parent_data_dir_shares_one_root_for_save_and_wasm_path() {
        // `../shared/data`-style configuration: save() and wasm_path() must
        // address the very same directory, and it must be the resolved one.
        let (relative, absolute) = relative_parent_dir("relparent");
        assert!(relative.starts_with("../"), "{relative}");

        let mut store = DataStore::load(&relative).unwrap();
        assert_eq!(store.data_dir, absolute);
        assert!(absolute.join("wasm").is_dir());

        store
            .transforms
            .entry("relative-transform".into())
            .or_default()
            .insert("0.1.0".into(), entry("relative-transform", "0.1.0"));
        store.save().unwrap();

        // The catalog landed under the resolved root, not under a second root
        // produced by lexically dropping the leading `..`.
        assert!(absolute.join("transforms.json").is_file());
        assert!(!PathBuf::from("shared/data/transforms.json").exists());

        let wasm = store.wasm_path("relative-transform", "0.1.0").unwrap();
        assert!(wasm.is_absolute(), "{}", wasm.display());
        assert!(
            wasm.starts_with(absolute.join("wasm")),
            "{} is not contained in {}",
            wasm.display(),
            absolute.display()
        );
        // root/wasm/<name>/<version>/<file>.wasm — four levels above the file.
        assert_eq!(
            wasm.ancestors().nth(4),
            store.catalog_path().parent(),
            "save() and wasm_path() disagree about the store root"
        );

        // A round trip through the same relative configuration sees the data.
        let reloaded = DataStore::load(&relative).unwrap();
        assert!(reloaded.transforms.contains_key("relative-transform"));
        // And so does a load addressed by the absolute equivalent.
        let by_absolute = DataStore::load(absolute.to_str().unwrap()).unwrap();
        assert!(by_absolute.transforms.contains_key("relative-transform"));

        let _ = std::fs::remove_dir_all(&absolute);
    }

    #[test]
    fn test_plain_relative_data_dir_remains_usable() {
        // The shipped default is a relative `data` directory; it must keep
        // working and resolve against the current directory.
        let cwd = std::env::current_dir().unwrap();
        let relative = "target/store-tests/relplain/data";
        let absolute = cwd.join(relative);
        let _ = std::fs::remove_dir_all(cwd.join("target/store-tests/relplain"));

        let mut store = DataStore::load(relative).unwrap();
        assert_eq!(store.data_dir, absolute);
        store
            .transforms
            .entry("plain".into())
            .or_default()
            .insert("0.1.0".into(), entry("plain", "0.1.0"));
        store.save().unwrap();
        assert!(absolute.join("transforms.json").is_file());
        assert!(store
            .wasm_path("plain", "0.1.0")
            .unwrap()
            .starts_with(absolute.join("wasm")));

        let _ = std::fs::remove_dir_all(cwd.join("target/store-tests/relplain"));
    }

    #[test]
    fn test_unresolved_relative_root_is_still_contained() {
        // Defense in depth for a directly constructed store: even without
        // load()'s resolution, both derived paths share the same root and the
        // artifact path stays inside it.
        let store = DataStore {
            transforms: BTreeMap::new(),
            data_dir: PathBuf::from("../shared/data"),
        };
        let wasm = store.wasm_path("json-filter", "0.1.0").unwrap();
        assert!(
            wasm.starts_with("../shared/data/wasm"),
            "{}",
            wasm.display()
        );
        assert_eq!(
            store.catalog_path(),
            PathBuf::from("../shared/data/transforms.json")
        );
    }
}

// add connector dependency resolution engine

/// Metadata for a registered transform in the marketplace.
///
/// Part of the store's published API surface; not yet consumed by the HTTP
/// handlers, which still serve the flat `TransformEntry` shape.
#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransformMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub category: TransformCategory,
    pub downloads: u64,
    pub verified: bool,
}

/// Canonical category taxonomy for [`TransformMetadata`].
#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TransformCategory {
    Sink,
    Source,
    Filter,
    Transform,
    Enrichment,
}
