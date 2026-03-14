//! Integration tests for the Streamline Marketplace CLI

#[test]
fn test_cli_version_format() {
    let version = env!("CARGO_PKG_VERSION");
    assert!(!version.is_empty(), "Version should not be empty");
    let parts: Vec<&str> = version.split('.').collect();
    assert!(
        parts.len() >= 2,
        "Version should have at least major.minor: {}",
        version
    );
    for part in &parts {
        assert!(
            part.parse::<u64>().is_ok(),
            "Version part '{}' should be numeric",
            part
        );
    }
}

#[test]
fn test_cli_package_name() {
    let name = env!("CARGO_PKG_NAME");
    assert_eq!(name, "streamline-marketplace-cli");
}

#[test]
fn test_cli_binary_name() {
    // The binary should be discoverable
    let bin = env!("CARGO_BIN_EXE_streamline-marketplace");
    assert!(!bin.is_empty(), "Binary path should resolve");
}

#[test]
fn test_cli_help_flag() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_streamline-marketplace"))
        .arg("--help")
        .output()
        .expect("Failed to run CLI with --help");
    assert!(
        output.status.success(),
        "CLI --help should exit successfully"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("streamline-marketplace") || stdout.contains("Discover"),
        "Help text should mention the tool name"
    );
}

#[test]
fn test_cli_version_flag() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_streamline-marketplace"))
        .arg("--version")
        .output()
        .expect("Failed to run CLI with --version");
    assert!(
        output.status.success(),
        "CLI --version should exit successfully"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "Version output should contain package version"
    );
}

#[test]
fn test_cli_list_with_missing_dir() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_streamline-marketplace"))
        .arg("--transforms-dir")
        .arg("/tmp/streamline-test-nonexistent-dir")
        .arg("list")
        .output()
        .expect("Failed to run CLI list command");
    // list should succeed even with empty/missing dir (just shows empty list)
    assert!(
        output.status.success(),
        "CLI list should handle missing transforms dir gracefully"
    );
}

#[test]
fn test_cli_unknown_subcommand_fails() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_streamline-marketplace"))
        .arg("nonexistent-command")
        .output()
        .expect("Failed to run CLI with unknown subcommand");
    assert!(
        !output.status.success(),
        "Unknown subcommand should produce an error"
    );
}

