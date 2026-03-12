//! Integration tests for the Streamline Marketplace Registry

#[test]
fn test_registry_package_metadata() {
    let version = env!("CARGO_PKG_VERSION");
    assert!(!version.is_empty(), "Version should not be empty");

    let name = env!("CARGO_PKG_NAME");
    assert_eq!(name, "streamline-marketplace-registry");
}

#[test]
fn test_registry_transforms_json_exists() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let transforms_path = std::path::Path::new(manifest_dir).join("transforms.json");
    assert!(
        transforms_path.exists(),
        "Registry transforms.json should exist at {}",
        transforms_path.display()
    );
}

#[test]
fn test_registry_transforms_json_valid() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let transforms_path = std::path::Path::new(manifest_dir).join("transforms.json");

    if transforms_path.exists() {
        let content =
            std::fs::read_to_string(&transforms_path).expect("Should read transforms.json");
        let parsed: serde_json::Value =
            serde_json::from_str(&content).expect("transforms.json should be valid JSON");

        assert!(
            parsed.is_array(),
            "transforms.json should contain a JSON array"
        );

        let entries = parsed.as_array().unwrap();
        assert!(
            !entries.is_empty(),
            "transforms.json should have at least one entry"
        );

        for entry in entries {
            assert!(
                entry.get("name").and_then(|v| v.as_str()).is_some(),
                "Each entry must have a name field"
            );
            assert!(
                entry.get("version").and_then(|v| v.as_str()).is_some(),
                "Each entry must have a version field"
            );
            assert!(
                entry.get("description").and_then(|v| v.as_str()).is_some(),
                "Each entry must have a description field"
            );
        }
    }
}

#[test]
fn test_registry_version_semver() {
    let version = env!("CARGO_PKG_VERSION");
    let parts: Vec<&str> = version.split('.').collect();
    assert_eq!(parts.len(), 3, "Version should be major.minor.patch");
    for part in &parts {
        assert!(
            part.parse::<u64>().is_ok(),
            "Version component '{}' should be numeric",
            part
        );
    }
}
