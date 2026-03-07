//! Integration tests for the Streamline Marketplace
//!
//! These tests verify:
//! - Registry JSON is well-formed and internally consistent
//! - All transforms declared in the registry have matching workspace members
//! - Transform metadata meets quality standards (description, categories, checksum)
//! - No duplicate entries exist

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct TransformEntry {
    name: String,
    version: String,
    description: String,
    author: String,
    checksum: String,
    categories: Vec<String>,
    min_streamline_version: String,
    wasm_url: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    repository_url: Option<String>,
    #[serde(default)]
    config_schema: Option<serde_json::Value>,
    #[serde(default)]
    input_format: Option<String>,
    #[serde(default)]
    output_format: Option<String>,
}

const VALID_CATEGORIES: &[&str] = &[
    "filtering",
    "enrichment",
    "routing",
    "security",
    "analytics",
    "format-conversion",
    "sink",
];

fn registry_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("registry")
        .join("transforms.json")
}

fn load_registry() -> Vec<TransformEntry> {
    let content = fs::read_to_string(registry_path())
        .expect("Failed to read registry/transforms.json");
    serde_json::from_str(&content).expect("Failed to parse registry JSON")
}

#[test]
fn test_registry_is_valid_json() {
    let content = fs::read_to_string(registry_path())
        .expect("Failed to read registry/transforms.json");
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("Registry JSON is not valid");
    assert!(parsed.is_array(), "Registry must be a JSON array");
}

#[test]
fn test_registry_no_duplicate_names() {
    let entries = load_registry();
    let mut seen = HashSet::new();
    for entry in &entries {
        assert!(
            seen.insert(&entry.name),
            "Duplicate transform name in registry: {}",
            entry.name
        );
    }
}

#[test]
fn test_registry_entries_have_required_fields() {
    let entries = load_registry();
    assert!(!entries.is_empty(), "Registry must contain at least one transform");

    for entry in &entries {
        assert!(
            !entry.name.is_empty(),
            "Transform name must not be empty"
        );
        assert!(
            !entry.version.is_empty(),
            "Transform '{}' must have a version",
            entry.name
        );
        assert!(
            !entry.description.is_empty(),
            "Transform '{}' must have a description",
            entry.name
        );
        assert!(
            entry.description.len() >= 10,
            "Transform '{}' description is too short: '{}'",
            entry.name,
            entry.description
        );
        assert!(
            !entry.author.is_empty(),
            "Transform '{}' must have an author",
            entry.name
        );
        assert!(
            !entry.checksum.is_empty(),
            "Transform '{}' must have a checksum",
            entry.name
        );
        assert!(
            entry.checksum.starts_with("sha256:"),
            "Transform '{}' checksum must use sha256: prefix, got: {}",
            entry.name,
            entry.checksum
        );
        assert!(
            !entry.categories.is_empty(),
            "Transform '{}' must have at least one category",
            entry.name
        );
        assert!(
            !entry.wasm_url.is_empty(),
            "Transform '{}' must have a wasm_url",
            entry.name
        );
        assert!(
            entry.wasm_url.starts_with("https://"),
            "Transform '{}' wasm_url must be HTTPS: {}",
            entry.name,
            entry.wasm_url
        );
        assert!(
            !entry.min_streamline_version.is_empty(),
            "Transform '{}' must specify min_streamline_version",
            entry.name
        );
    }
}

#[test]
fn test_registry_categories_are_valid() {
    let entries = load_registry();
    for entry in &entries {
        for cat in &entry.categories {
            assert!(
                VALID_CATEGORIES.contains(&cat.as_str()),
                "Transform '{}' has invalid category '{}'. Valid: {:?}",
                entry.name,
                cat,
                VALID_CATEGORIES
            );
        }
    }
}

#[test]
fn test_registry_versions_are_semver() {
    let entries = load_registry();
    for entry in &entries {
        let parts: Vec<&str> = entry.version.split('.').collect();
        assert!(
            parts.len() == 3
                && parts.iter().all(|p| p.parse::<u32>().is_ok()),
            "Transform '{}' version '{}' is not valid semver (expected X.Y.Z)",
            entry.name,
            entry.version
        );
    }
}

#[test]
fn test_workspace_members_match_registry() {
    let workspace_toml = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("Cargo.toml"),
    )
    .expect("Failed to read workspace Cargo.toml");

    let entries = load_registry();
    let transforms_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("transforms");

    for entry in &entries {
        let crate_name = entry.name.replace('-', "-");
        let crate_dir = transforms_dir.join(&entry.name);

        // Check the transform directory exists
        assert!(
            crate_dir.exists(),
            "Transform '{}' is in registry but directory transforms/{} does not exist",
            entry.name,
            entry.name
        );

        // Check it's listed in workspace members
        let member_path = format!("transforms/{}", entry.name);
        assert!(
            workspace_toml.contains(&member_path),
            "Transform '{}' has directory but is not in workspace members (expected 'transforms/{}')",
            entry.name,
            entry.name
        );

        // Check it has a Cargo.toml
        let cargo_toml = crate_dir.join("Cargo.toml");
        assert!(
            cargo_toml.exists(),
            "Transform '{}' is missing Cargo.toml at {:?}",
            crate_name,
            cargo_toml
        );
    }
}

#[test]
fn test_minimum_transform_count() {
    let entries = load_registry();
    assert!(
        entries.len() >= 10,
        "Expected at least 10 transforms in registry, found {}",
        entries.len()
    );
}

#[test]
fn test_category_coverage() {
    let entries = load_registry();
    let mut categories_seen: HashSet<String> = HashSet::new();
    for entry in &entries {
        for cat in &entry.categories {
            categories_seen.insert(cat.clone());
        }
    }

    // At minimum, filtering + enrichment + routing + security should be covered
    let required = ["filtering", "enrichment", "routing", "security"];
    for req in required {
        assert!(
            categories_seen.contains(req),
            "Registry is missing transforms for required category: {}",
            req
        );
    }
}
