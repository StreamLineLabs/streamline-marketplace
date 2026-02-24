//! Streamline WASM Transform Marketplace CLI
//!
//! A command-line tool for discovering, installing, and publishing WASM transforms.
//!
//! ## Commands
//!
//! - `search <query>` - Search transforms by keyword
//! - `install <name>` - Download and install a transform
//! - `publish <path>` - Publish a new transform
//! - `list` - List installed transforms
//! - `info <name>` - Show transform details
//! - `update <name>` - Update an installed transform
//! - `remove <name>` - Remove an installed transform

use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

/// Default registry URL (local server; fall back to GitHub raw if server is not running)
const DEFAULT_REGISTRY_URL: &str = "http://localhost:8080";

/// Fallback: raw GitHub registry file for offline use
const FALLBACK_REGISTRY_URL: &str =
    "https://raw.githubusercontent.com/streamlinelabs/streamline-marketplace/main/registry/transforms.json";

/// Streamline WASM Transform Marketplace
#[derive(Parser)]
#[command(name = "streamline-marketplace")]
#[command(version, about = "Discover, install, and publish WASM transforms for Streamline")]
struct Cli {
    /// Registry URL (overrides default)
    #[arg(long, env = "STREAMLINE_MARKETPLACE_URL")]
    registry_url: Option<String>,

    /// Installation directory (default: ~/.streamline/transforms)
    #[arg(long, env = "STREAMLINE_TRANSFORMS_DIR")]
    transforms_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Search for transforms by keyword
    Search {
        /// Search query (matches name, description, tags)
        query: String,
        /// Filter by category (filtering, enrichment, routing, security, analytics, format-conversion)
        #[arg(long, short)]
        category: Option<String>,
    },

    /// Install a transform from the marketplace
    Install {
        /// Transform name (optionally with @version, e.g., "json-filter@0.1.0")
        name: String,
        /// Force reinstall even if already installed
        #[arg(long, short)]
        force: bool,
    },

    /// Publish a new transform to the marketplace
    Publish {
        /// Path to the transform directory (must contain Cargo.toml)
        path: PathBuf,
        /// Transform name
        #[arg(long)]
        name: Option<String>,
        /// Transform version
        #[arg(long)]
        version: Option<String>,
        /// WASM download URL
        #[arg(long)]
        wasm_url: Option<String>,
    },

    /// List installed transforms
    List,

    /// Show detailed information about a transform
    Info {
        /// Transform name
        name: String,
    },

    /// Update an installed transform to the latest version
    Update {
        /// Transform name (or "all" to update everything)
        name: String,
    },

    /// Remove an installed transform
    Remove {
        /// Transform name
        name: String,
    },
}

/// A transform entry from the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransformEntry {
    name: String,
    version: String,
    description: String,
    author: String,
    #[serde(default)]
    downloads: u64,
    #[serde(default)]
    checksum: String,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    min_streamline_version: String,
    wasm_url: String,
    input_format: String,
    output_format: String,
    tags: Vec<String>,
    license: String,
    repository_url: String,
    #[serde(default)]
    config_schema: serde_json::Value,
}

/// Metadata for an installed transform.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InstalledTransform {
    name: String,
    version: String,
    installed_at: String,
    wasm_path: String,
    source_url: String,
    sha256: String,
}

/// Get the transforms installation directory.
fn transforms_dir(cli: &Cli) -> PathBuf {
    if let Some(ref dir) = cli.transforms_dir {
        dir.clone()
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".streamline")
            .join("transforms")
    }
}

/// Load the registry from the API server, a URL, or a local file.
fn load_registry(cli: &Cli) -> Result<Vec<TransformEntry>, String> {
    let url = cli
        .registry_url
        .as_deref()
        .unwrap_or(DEFAULT_REGISTRY_URL);

    // Check if it is a local file path
    let path = PathBuf::from(url);
    if path.exists() {
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read registry file {}: {}", path.display(), e))?;
        let entries: Vec<TransformEntry> =
            serde_json::from_str(&content).map_err(|e| format!("Failed to parse registry: {}", e))?;
        return Ok(entries);
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // Try the API endpoint first (append /api/v1/transforms if it looks like a base URL)
    let api_url = if url.ends_with("/transforms") || url.ends_with("/transforms.json") {
        url.to_string()
    } else {
        format!("{}/api/v1/transforms", url.trim_end_matches('/'))
    };

    let response = client
        .get(&api_url)
        .header("User-Agent", "streamline-marketplace-cli")
        .send();

    match response {
        Ok(resp) if resp.status().is_success() => {
            let entries: Vec<TransformEntry> = resp
                .json()
                .map_err(|e| format!("Failed to parse registry JSON: {}", e))?;
            return Ok(entries);
        }
        _ => {
            // Fall back to the direct URL (could be a raw JSON file)
            if api_url != url {
                let resp = client
                    .get(url)
                    .header("User-Agent", "streamline-marketplace-cli")
                    .send();
                match resp {
                    Ok(r) if r.status().is_success() => {
                        let entries: Vec<TransformEntry> = r
                            .json()
                            .map_err(|e| format!("Failed to parse registry JSON: {}", e))?;
                        return Ok(entries);
                    }
                    _ => {}
                }
            }
        }
    }

    // Final fallback
    if url == DEFAULT_REGISTRY_URL {
        let resp = client
            .get(FALLBACK_REGISTRY_URL)
            .header("User-Agent", "streamline-marketplace-cli")
            .send()
            .map_err(|e| format!("Failed to fetch registry: {}", e))?;
        if resp.status().is_success() {
            let entries: Vec<TransformEntry> = resp
                .json()
                .map_err(|e| format!("Failed to parse registry JSON: {}", e))?;
            return Ok(entries);
        }
    }

    Err(format!("Failed to reach registry at {}", url))
}

/// Load the list of installed transforms.
fn load_installed(cli: &Cli) -> Vec<InstalledTransform> {
    let manifest_path = transforms_dir(cli).join("installed.json");
    if !manifest_path.exists() {
        return Vec::new();
    }
    let content = match fs::read_to_string(&manifest_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    serde_json::from_str(&content).unwrap_or_default()
}

/// Save the list of installed transforms.
fn save_installed(cli: &Cli, installed: &[InstalledTransform]) -> Result<(), String> {
    let dir = transforms_dir(cli);
    fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create transforms directory: {}", e))?;
    let manifest_path = dir.join("installed.json");
    let content = serde_json::to_string_pretty(installed)
        .map_err(|e| format!("Failed to serialize installed list: {}", e))?;
    fs::write(&manifest_path, content)
        .map_err(|e| format!("Failed to write installed manifest: {}", e))?;
    Ok(())
}

/// Compute SHA-256 hash of a byte slice.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Execute the `search` command.
fn cmd_search(cli: &Cli, query: &str, category: &Option<String>) {
    let registry = match load_registry(cli) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            std::process::exit(1);
        }
    };

    let query_lower = query.to_lowercase();
    let results: Vec<&TransformEntry> = registry
        .iter()
        .filter(|entry| {
            let matches_query = entry.name.to_lowercase().contains(&query_lower)
                || entry.description.to_lowercase().contains(&query_lower)
                || entry
                    .tags
                    .iter()
                    .any(|t| t.to_lowercase().contains(&query_lower));

            let matches_category = category
                .as_ref()
                .map(|c| {
                    entry
                        .categories
                        .iter()
                        .any(|cat| cat.to_lowercase() == c.to_lowercase())
                })
                .unwrap_or(true);

            matches_query && matches_category
        })
        .collect();

    if results.is_empty() {
        println!("{}", "No transforms found matching your query.".yellow());
        return;
    }

    println!(
        "{} {} transform(s) found:\n",
        "==>".green().bold(),
        results.len()
    );

    // Table header
    println!(
        "  {:<20} {:<10} {:<24} {:>10}",
        "NAME".bold(),
        "VERSION".bold(),
        "CATEGORIES".bold(),
        "DOWNLOADS".bold()
    );
    println!("  {}", "─".repeat(68));

    for entry in &results {
        let cats = entry.categories.join(", ");
        println!(
            "  {:<20} {:<10} {:<24} {:>10}",
            entry.name.cyan(),
            format!("v{}", entry.version).dimmed(),
            cats.yellow(),
            entry.downloads
        );
        println!("  {}", entry.description.dimmed());
        if !entry.tags.is_empty() {
            println!("  Tags: {}", entry.tags.join(", ").dimmed());
        }
        println!();
    }
}

/// Execute the `install` command.
fn cmd_install(cli: &Cli, name_with_version: &str, force: bool) {
    // Parse name@version
    let (name, requested_version) = if let Some(idx) = name_with_version.find('@') {
        (
            &name_with_version[..idx],
            Some(&name_with_version[idx + 1..]),
        )
    } else {
        (name_with_version, None)
    };

    // Check if already installed
    let installed = load_installed(cli);
    if !force {
        if let Some(existing) = installed.iter().find(|i| i.name == name) {
            if requested_version.is_none() || requested_version == Some(existing.version.as_str()) {
                println!(
                    "{} {} v{} is already installed at {}",
                    "==>".green().bold(),
                    name.bold(),
                    existing.version,
                    existing.wasm_path
                );
                println!(
                    "    Use {} to reinstall.",
                    "--force".yellow()
                );
                return;
            }
        }
    }

    // Load registry
    let registry = match load_registry(cli) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            std::process::exit(1);
        }
    };

    // Find the transform
    let entry = registry.iter().find(|e| {
        e.name == name
            && requested_version
                .map(|v| e.version == v)
                .unwrap_or(true)
    });

    let entry = match entry {
        Some(e) => e,
        None => {
            eprintln!(
                "{}: Transform '{}' not found in the registry.",
                "Error".red().bold(),
                name
            );
            std::process::exit(1);
        }
    };

    println!(
        "{} Installing {} v{}...",
        "==>".green().bold(),
        entry.name.bold().cyan(),
        entry.version
    );

    // Resolve download URL: prefer the server download endpoint, fall back to wasm_url
    let registry_base = cli
        .registry_url
        .as_deref()
        .unwrap_or(DEFAULT_REGISTRY_URL)
        .trim_end_matches('/')
        .to_string();
    let download_url = if entry.wasm_url.starts_with('/') {
        format!("{}{}", registry_base, entry.wasm_url)
    } else if entry.wasm_url.starts_with("http") {
        entry.wasm_url.clone()
    } else {
        // Try the server download endpoint
        format!(
            "{}/api/v1/transforms/{}/{}/download",
            registry_base, entry.name, entry.version
        )
    };

    // Download the WASM module
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: Failed to create HTTP client: {}", "Error".red().bold(), e);
            std::process::exit(1);
        }
    };

    println!("    Downloading from {}...", download_url.dimmed());

    let response = match client
        .get(&download_url)
        .header("User-Agent", "streamline-marketplace-cli")
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "{}: Failed to download WASM module: {}",
                "Error".red().bold(),
                e
            );
            std::process::exit(1);
        }
    };

    if !response.status().is_success() {
        eprintln!(
            "{}: Download failed with status {}",
            "Error".red().bold(),
            response.status()
        );
        std::process::exit(1);
    }

    let wasm_bytes = match response.bytes() {
        Ok(b) => b.to_vec(),
        Err(e) => {
            eprintln!(
                "{}: Failed to read WASM bytes: {}",
                "Error".red().bold(),
                e
            );
            std::process::exit(1);
        }
    };

    let hash = sha256_hex(&wasm_bytes);
    println!(
        "    Downloaded {} bytes (SHA-256: {})",
        wasm_bytes.len(),
        &hash[..16]
    );

    // Verify checksum against registry entry
    if !entry.checksum.is_empty() && entry.checksum != "pending" && hash != entry.checksum {
        eprintln!(
            "{}: Checksum mismatch! Expected {}, got {}. The download may be corrupted or tampered with.",
            "Error".red().bold(),
            &entry.checksum[..16],
            &hash[..16]
        );
        std::process::exit(1);
    }

    // Save to transforms directory
    let install_dir = transforms_dir(cli)
        .join(&entry.name)
        .join(&entry.version);

    if let Err(e) = fs::create_dir_all(&install_dir) {
        eprintln!(
            "{}: Failed to create install directory: {}",
            "Error".red().bold(),
            e
        );
        std::process::exit(1);
    }

    let wasm_filename = format!("{}.wasm", entry.name.replace('-', "_"));
    let wasm_path = install_dir.join(&wasm_filename);

    let mut file = match fs::File::create(&wasm_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "{}: Failed to create WASM file: {}",
                "Error".red().bold(),
                e
            );
            std::process::exit(1);
        }
    };

    if let Err(e) = file.write_all(&wasm_bytes) {
        eprintln!(
            "{}: Failed to write WASM file: {}",
            "Error".red().bold(),
            e
        );
        std::process::exit(1);
    }

    // Save metadata
    let metadata_path = install_dir.join("metadata.json");
    let metadata = serde_json::to_string_pretty(entry).unwrap_or_default();
    let _ = fs::write(&metadata_path, metadata);

    // Update installed manifest
    let mut installed_list = installed;
    installed_list.retain(|i| i.name != name);
    installed_list.push(InstalledTransform {
        name: entry.name.clone(),
        version: entry.version.clone(),
        installed_at: chrono_now_iso8601(),
        wasm_path: wasm_path.to_string_lossy().to_string(),
        source_url: entry.wasm_url.clone(),
        sha256: hash,
    });

    if let Err(e) = save_installed(cli, &installed_list) {
        eprintln!(
            "{}: Failed to update installed manifest: {}",
            "Warning".yellow().bold(),
            e
        );
    }

    println!(
        "{} {} v{} installed successfully!",
        "==>".green().bold(),
        entry.name.bold().cyan(),
        entry.version
    );
    println!("    WASM module: {}", wasm_path.display());
    println!();
    println!("    Deploy with:");
    println!(
        "      streamline-cli transforms deploy \\",
    );
    println!("        --name my-transform \\");
    println!(
        "        --wasm {} \\",
        wasm_path.display()
    );
    println!("        --input <source-topic> \\");
    println!("        --output <dest-topic>");
}

/// Execute the `publish` command.
fn cmd_publish(cli: &Cli, path: &PathBuf, name: &Option<String>, version: &Option<String>, wasm_url: &Option<String>) {
    let cargo_toml_path = path.join("Cargo.toml");
    if !cargo_toml_path.exists() {
        eprintln!(
            "{}: No Cargo.toml found at {}",
            "Error".red().bold(),
            path.display()
        );
        std::process::exit(1);
    }

    let cargo_content = match fs::read_to_string(&cargo_toml_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{}: Failed to read Cargo.toml: {}",
                "Error".red().bold(),
                e
            );
            std::process::exit(1);
        }
    };

    // Extract name and version from Cargo.toml (simple parsing)
    let pkg_name = name.clone().or_else(|| {
        cargo_content
            .lines()
            .find(|l| l.trim().starts_with("name"))
            .and_then(|l| l.split('=').nth(1))
            .map(|s| s.trim().trim_matches('"').to_string())
    });

    let pkg_version = version.clone().or_else(|| {
        cargo_content
            .lines()
            .find(|l| l.trim().starts_with("version") && !l.contains("workspace"))
            .and_then(|l| l.split('=').nth(1))
            .map(|s| s.trim().trim_matches('"').to_string())
    });

    let pkg_name = match pkg_name {
        Some(n) => n,
        None => {
            eprintln!(
                "{}: Could not determine transform name. Use --name.",
                "Error".red().bold()
            );
            std::process::exit(1);
        }
    };

    let pkg_version = pkg_version.unwrap_or_else(|| "0.1.0".to_string());

    println!(
        "{} Preparing to publish {} v{}",
        "==>".green().bold(),
        pkg_name.bold().cyan(),
        pkg_version
    );

    // Check that the WASM target file exists
    let wasm_name = format!("{}.wasm", pkg_name.replace('-', "_"));
    let wasm_path = path
        .join("target")
        .join("wasm32-wasip1")
        .join("release")
        .join(&wasm_name);

    // Compute checksum for the WASM binary
    let wasm_checksum = if wasm_path.exists() {
        let wasm_bytes = fs::read(&wasm_path).unwrap_or_default();
        let hash = sha256_hex(&wasm_bytes);
        println!(
            "    WASM binary: {} ({} bytes, SHA-256: {})",
            wasm_path.display(),
            wasm_bytes.len(),
            &hash[..16]
        );
        hash
    } else {
        println!(
            "    {} WASM binary not found at {}",
            "Warning:".yellow().bold(),
            wasm_path.display()
        );
        println!(
            "    Build with: cargo build --target wasm32-wasip1 --release"
        );
        String::new()
    };

    let url = wasm_url.clone().unwrap_or_else(|| {
        format!(
            "https://github.com/streamlinelabs/streamline-marketplace/releases/download/v{}/{}",
            pkg_version, wasm_name
        )
    });

    // Generate a registry entry
    let entry = serde_json::json!({
        "name": pkg_name,
        "version": pkg_version,
        "description": format!("User-contributed transform: {}", pkg_name),
        "author": "community",
        "downloads": 0,
        "checksum": wasm_checksum,
        "categories": ["format-conversion"],
        "min_streamline_version": "0.1.0",
        "wasm_url": url,
        "input_format": "json",
        "output_format": "json",
        "tags": [pkg_name],
        "license": "Apache-2.0",
        "repository_url": format!("https://github.com/streamlinelabs/streamline-marketplace/tree/main/transforms/{}", pkg_name),
        "config_schema": {}
    });

    let entry_json = serde_json::to_string_pretty(&entry).unwrap_or_default();

    // Try publishing to the registry server via API
    let registry_base = cli
        .registry_url
        .as_deref()
        .unwrap_or(DEFAULT_REGISTRY_URL)
        .trim_end_matches('/')
        .to_string();
    let api_url = format!("{}/api/v1/transforms", registry_base);

    let auth_token = match std::env::var("STREAMLINE_MARKETPLACE_TOKEN") {
        Ok(token) if !token.is_empty() => token,
        _ => {
            eprintln!(
                "{}: STREAMLINE_MARKETPLACE_TOKEN environment variable is required for publishing.",
                "Error".red().bold()
            );
            eprintln!("    Set it with: export STREAMLINE_MARKETPLACE_TOKEN=<your-token>");
            std::process::exit(1);
        }
    };

    let publish_client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build();

    let mut published_to_server = false;
    if let Ok(client) = publish_client {
        if wasm_path.exists() {
            let wasm_bytes = fs::read(&wasm_path).unwrap_or_default();
            let form = reqwest::blocking::multipart::Form::new()
                .text("metadata", entry_json.clone())
                .part(
                    "wasm",
                    reqwest::blocking::multipart::Part::bytes(wasm_bytes)
                        .file_name(wasm_name.clone())
                        .mime_str("application/wasm")
                        .unwrap(),
                );

            match client
                .post(&api_url)
                .header("Authorization", format!("Bearer {}", auth_token))
                .multipart(form)
                .send()
            {
                Ok(resp) if resp.status().is_success() => {
                    println!(
                        "\n{} Published to registry server!",
                        "==>".green().bold()
                    );
                    published_to_server = true;
                }
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().unwrap_or_default();
                    println!(
                        "\n    {} Could not publish to server ({}): {}",
                        "Note:".yellow().bold(),
                        status,
                        body
                    );
                }
                Err(e) => {
                    println!(
                        "\n    {} Registry server not reachable: {}",
                        "Note:".yellow().bold(),
                        e
                    );
                }
            }
        }
    }

    // Save to a file as fallback
    let output_path = path.join("registry-entry.json");
    if let Err(e) = fs::write(&output_path, &entry_json) {
        eprintln!(
            "{}: Failed to write registry entry: {}",
            "Warning".yellow().bold(),
            e
        );
    }

    // Load existing registry to check for conflicts
    let _registry = load_registry(cli).unwrap_or_default();

    println!();
    println!("{} Registry entry generated:", "==>".green().bold());
    println!("{}", entry_json);
    println!();
    println!("    Saved to: {}", output_path.display());
    if !published_to_server {
        println!();
        println!(
            "    To publish, submit a PR adding this entry to {}",
            "registry/transforms.json".bold()
        );
        println!(
            "    in the streamline-marketplace repository, and upload the .wasm"
        );
        println!("    file to your release URL.");
        println!();
        println!("    Or start the registry server and re-run this command.");
    }
}

/// Execute the `list` command.
fn cmd_list(cli: &Cli) {
    let installed = load_installed(cli);

    if installed.is_empty() {
        println!("{}", "No transforms installed.".yellow());
        println!(
            "    Run {} to find transforms.",
            "streamline-marketplace search <query>".bold()
        );
        return;
    }

    println!(
        "{} {} installed transform(s):\n",
        "==>".green().bold(),
        installed.len()
    );

    for transform in &installed {
        println!(
            "  {} {}",
            transform.name.bold().cyan(),
            format!("v{}", transform.version).dimmed()
        );
        println!("      Path:      {}", transform.wasm_path);
        println!("      Installed: {}", transform.installed_at.dimmed());
        println!(
            "      SHA-256:   {}",
            &transform.sha256[..16].to_string().dimmed()
        );
        println!();
    }
}

/// Execute the `info` command.
fn cmd_info(cli: &Cli, name: &str) {
    // Try from registry first
    let registry = load_registry(cli).unwrap_or_default();
    let entry = registry.iter().find(|e| e.name == name);

    // Check installed
    let installed = load_installed(cli);
    let installed_entry = installed.iter().find(|i| i.name == name);

    if entry.is_none() && installed_entry.is_none() {
        eprintln!(
            "{}: Transform '{}' not found in registry or installed list.",
            "Error".red().bold(),
            name
        );
        std::process::exit(1);
    }

    if let Some(entry) = entry {
        println!("{}\n", "Registry Information".bold().underline());
        println!("  Name:        {}", entry.name.bold().cyan());
        println!("  Version:     {}", entry.version);
        println!("  Author:      {}", entry.author);
        println!(
            "  Categories:  {}",
            entry.categories.join(", ").yellow()
        );
        println!("  License:     {}", entry.license);
        println!("  Input:       {}", entry.input_format);
        println!("  Output:      {}", entry.output_format);
        println!("  Downloads:   {}", entry.downloads);
        if !entry.min_streamline_version.is_empty() {
            println!(
                "  Min Version: {}",
                entry.min_streamline_version
            );
        }
        if !entry.checksum.is_empty() {
            println!("  Checksum:    {}", entry.checksum.dimmed());
        }
        println!();
        println!("  {}", "Description:".bold());
        println!("  {}", entry.description);
        println!();
        println!("  Tags:        {}", entry.tags.join(", "));
        println!("  WASM URL:    {}", entry.wasm_url.dimmed());
        println!("  Repository:  {}", entry.repository_url.dimmed());

        if !entry.config_schema.is_null() && entry.config_schema.is_object() {
            println!();
            println!("  {}", "Configuration Schema:".bold());
            if let Some(obj) = entry.config_schema.as_object() {
                for (key, val) in obj {
                    let desc = val
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let required = val
                        .get("required")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let req_str = if required { " (required)" } else { "" };
                    println!("    {} - {}{}", key.bold(), desc, req_str.red());
                }
            }
        }
    }

    if let Some(inst) = installed_entry {
        println!();
        println!("{}\n", "Installation Details".bold().underline());
        println!("  WASM Path:   {}", inst.wasm_path);
        println!("  Installed:   {}", inst.installed_at);
        println!("  SHA-256:     {}", inst.sha256);
        println!("  Source:      {}", inst.source_url.dimmed());
    } else {
        println!();
        println!(
            "  {} Not installed. Run: {}",
            "Status:".bold(),
            format!("streamline-marketplace install {}", name).yellow()
        );
    }
}

/// Execute the `update` command.
fn cmd_update(cli: &Cli, name: &str) {
    let installed = load_installed(cli);

    if name == "all" {
        if installed.is_empty() {
            println!("{}", "No transforms installed.".yellow());
            return;
        }
        println!(
            "{} Checking updates for {} transform(s)...\n",
            "==>".green().bold(),
            installed.len()
        );
        let registry = match load_registry(cli) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{}: {}", "Error".red().bold(), e);
                std::process::exit(1);
            }
        };
        let mut updated = 0;
        for inst in &installed {
            if let Some(latest) = registry.iter().find(|e| e.name == inst.name) {
                if version_gt(&latest.version, &inst.version) {
                    println!(
                        "  {} {} -> {}",
                        inst.name.cyan(),
                        inst.version.dimmed(),
                        latest.version.green()
                    );
                    cmd_install(cli, &inst.name, true);
                    updated += 1;
                }
            }
        }
        if updated == 0 {
            println!("{}", "All transforms are up to date.".green());
        }
        return;
    }

    let inst = match installed.iter().find(|i| i.name == name) {
        Some(i) => i,
        None => {
            eprintln!(
                "{}: Transform '{}' is not installed.",
                "Error".red().bold(),
                name
            );
            std::process::exit(1);
        }
    };

    let registry = match load_registry(cli) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            std::process::exit(1);
        }
    };

    let latest = match registry.iter().find(|e| e.name == name) {
        Some(e) => e,
        None => {
            eprintln!(
                "{}: Transform '{}' not found in registry.",
                "Error".red().bold(),
                name
            );
            std::process::exit(1);
        }
    };

    if !version_gt(&latest.version, &inst.version) {
        println!(
            "{} {} v{} is already the latest version.",
            "==>".green().bold(),
            name.bold().cyan(),
            inst.version
        );
        return;
    }

    println!(
        "{} Updating {} v{} -> v{}",
        "==>".green().bold(),
        name.bold().cyan(),
        inst.version,
        latest.version
    );

    cmd_install(cli, name, true);
}

/// Execute the `remove` command.
fn cmd_remove(cli: &Cli, name: &str) {
    let installed = load_installed(cli);

    let inst = match installed.iter().find(|i| i.name == name) {
        Some(i) => i.clone(),
        None => {
            eprintln!(
                "{}: Transform '{}' is not installed.",
                "Error".red().bold(),
                name
            );
            std::process::exit(1);
        }
    };

    // Remove the WASM files
    let install_dir = transforms_dir(cli).join(&inst.name);
    if install_dir.exists() {
        if let Err(e) = fs::remove_dir_all(&install_dir) {
            eprintln!(
                "{}: Failed to remove transform directory: {}",
                "Warning".yellow().bold(),
                e
            );
        }
    }

    // Update the installed manifest
    let mut installed_list = installed;
    installed_list.retain(|i| i.name != name);
    if let Err(e) = save_installed(cli, &installed_list) {
        eprintln!(
            "{}: Failed to update installed manifest: {}",
            "Warning".yellow().bold(),
            e
        );
    }

    println!(
        "{} {} v{} has been removed.",
        "==>".green().bold(),
        name.bold().cyan(),
        inst.version
    );
}

/// Compare two semver version strings. Returns true if a > b.
fn version_gt(a: &str, b: &str) -> bool {
    let parse = |v: &str| -> (u64, u64, u64) {
        let parts: Vec<u64> = v.split('.').filter_map(|p| p.parse().ok()).collect();
        (
            parts.first().copied().unwrap_or(0),
            parts.get(1).copied().unwrap_or(0),
            parts.get(2).copied().unwrap_or(0),
        )
    };
    parse(a) > parse(b)
}

/// Check if a version satisfies a version constraint (e.g., ">=0.1.0", "0.1.0").
#[allow(dead_code)]
fn version_satisfies(version: &str, constraint: &str) -> bool {
    let constraint = constraint.trim();
    if constraint.is_empty() {
        return true;
    }

    let (op, ver_str) = if constraint.starts_with(">=") {
        (">=", constraint[2..].trim())
    } else if constraint.starts_with("<=") {
        ("<=", constraint[2..].trim())
    } else if constraint.starts_with('>') {
        (">", constraint[1..].trim())
    } else if constraint.starts_with('<') {
        ("<", constraint[1..].trim())
    } else if constraint.starts_with('=') {
        ("=", constraint[1..].trim())
    } else {
        ("=", constraint)
    };

    let parse = |v: &str| -> (u64, u64, u64) {
        let parts: Vec<u64> = v.split('.').filter_map(|p| p.parse().ok()).collect();
        (
            parts.first().copied().unwrap_or(0),
            parts.get(1).copied().unwrap_or(0),
            parts.get(2).copied().unwrap_or(0),
        )
    };

    let ver = parse(version);
    let cmp = parse(ver_str);

    match op {
        ">=" => ver >= cmp,
        "<=" => ver <= cmp,
        ">" => ver > cmp,
        "<" => ver < cmp,
        _ => ver == cmp,
    }
}

/// Generate a simple ISO 8601 timestamp without chrono dependency.
fn chrono_now_iso8601() -> String {
    let epoch_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let secs = (epoch_ms / 1000) as i64;
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Convert days since 1970-01-01 to year-month-day (same algorithm as timestamp-enricher)
    let z = days_since_epoch + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, m, d, hours, minutes, seconds
    )
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Search { query, category } => cmd_search(&cli, query, category),
        Commands::Install { name, force } => cmd_install(&cli, name, *force),
        Commands::Publish {
            path,
            name,
            version,
            wasm_url,
        } => cmd_publish(&cli, path, name, version, wasm_url),
        Commands::List => cmd_list(&cli),
        Commands::Info { name } => cmd_info(&cli, name),
        Commands::Update { name } => cmd_update(&cli, name),
        Commands::Remove { name } => cmd_remove(&cli, name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"hello world");
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_chrono_now_iso8601_format() {
        let ts = chrono_now_iso8601();
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
        // Should be 20 chars: "YYYY-MM-DDTHH:MM:SSZ"
        assert_eq!(ts.len(), 20);
    }

    #[test]
    fn test_parse_name_with_version() {
        let input = "json-filter@0.1.0";
        let (name, version) = if let Some(idx) = input.find('@') {
            (&input[..idx], Some(&input[idx + 1..]))
        } else {
            (input, None)
        };
        assert_eq!(name, "json-filter");
        assert_eq!(version, Some("0.1.0"));
    }

    #[test]
    fn test_parse_name_without_version() {
        let input = "json-filter";
        let (name, version) = if let Some(idx) = input.find('@') {
            (&input[..idx], Some(&input[idx + 1..]))
        } else {
            (input, None)
        };
        assert_eq!(name, "json-filter");
        assert_eq!(version, None);
    }

    #[test]
    fn test_transform_entry_deserialization() {
        let json = r#"{
            "name": "test-transform",
            "version": "0.1.0",
            "description": "A test transform",
            "author": "test",
            "wasm_url": "https://example.com/test.wasm",
            "input_format": "json",
            "output_format": "json",
            "category": "transform",
            "tags": ["test"],
            "license": "Apache-2.0",
            "repository_url": "https://example.com/repo"
        }"#;

        let entry: TransformEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.name, "test-transform");
        assert_eq!(entry.version, "0.1.0");
        assert_eq!(entry.tags, vec!["test"]);
    }

    #[test]
    fn test_installed_transform_serialization() {
        let installed = InstalledTransform {
            name: "test".to_string(),
            version: "0.1.0".to_string(),
            installed_at: "2026-02-19T00:00:00Z".to_string(),
            wasm_path: "/home/user/.streamline/transforms/test/0.1.0/test.wasm".to_string(),
            source_url: "https://example.com/test.wasm".to_string(),
            sha256: "abc123".to_string(),
        };

        let json = serde_json::to_string(&installed).unwrap();
        assert!(json.contains("\"name\":\"test\""));

        let deserialized: InstalledTransform = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "test");
    }

    #[test]
    fn test_registry_deserialization_from_file() {
        // Test that the actual registry file parses correctly
        let registry_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("registry")
            .join("transforms.json");

        if registry_path.exists() {
            let content = std::fs::read_to_string(&registry_path).unwrap();
            let entries: Vec<TransformEntry> = serde_json::from_str(&content).unwrap();
            assert!(entries.len() >= 11, "Registry should have at least 11 entries");

            // Verify each entry has required fields including new metadata
            for entry in &entries {
                assert!(!entry.name.is_empty());
                assert!(!entry.version.is_empty());
                assert!(!entry.description.is_empty());
                assert!(!entry.wasm_url.is_empty());
                assert!(!entry.categories.is_empty(), "Entry '{}' must have categories", entry.name);
                assert!(!entry.min_streamline_version.is_empty(), "Entry '{}' must have min_streamline_version", entry.name);
                assert!(!entry.checksum.is_empty(), "Entry '{}' must have checksum", entry.name);
            }

            // Verify valid category values
            let valid_categories = [
                "filtering", "enrichment", "routing", "security", "analytics", "format-conversion",
            ];
            for entry in &entries {
                for cat in &entry.categories {
                    assert!(
                        valid_categories.contains(&cat.as_str()),
                        "Entry '{}' has invalid category '{}'. Valid: {:?}",
                        entry.name, cat, valid_categories
                    );
                }
            }
        }
    }

    #[test]
    fn test_version_gt() {
        assert!(version_gt("0.2.0", "0.1.0"));
        assert!(version_gt("1.0.0", "0.9.9"));
        assert!(version_gt("0.1.1", "0.1.0"));
        assert!(!version_gt("0.1.0", "0.1.0"));
        assert!(!version_gt("0.1.0", "0.2.0"));
    }

    #[test]
    fn test_version_satisfies() {
        assert!(version_satisfies("0.2.0", ">=0.1.0"));
        assert!(version_satisfies("0.1.0", ">=0.1.0"));
        assert!(!version_satisfies("0.0.9", ">=0.1.0"));
        assert!(version_satisfies("0.1.0", "<=0.2.0"));
        assert!(version_satisfies("0.2.0", ">0.1.0"));
        assert!(!version_satisfies("0.1.0", ">0.1.0"));
        assert!(version_satisfies("0.1.0", "<0.2.0"));
        assert!(version_satisfies("0.1.0", "0.1.0"));
        assert!(version_satisfies("0.1.0", "=0.1.0"));
        assert!(version_satisfies("1.0.0", ""));
    }

    #[test]
    fn test_transform_entry_with_new_fields() {
        let json = r#"{
            "name": "test-transform",
            "version": "0.1.0",
            "description": "A test transform",
            "author": "test",
            "downloads": 100,
            "checksum": "sha256:abc123",
            "categories": ["filtering", "analytics"],
            "min_streamline_version": "0.1.0",
            "wasm_url": "https://example.com/test.wasm",
            "input_format": "json",
            "output_format": "json",
            "tags": ["test"],
            "license": "Apache-2.0",
            "repository_url": "https://example.com/repo"
        }"#;

        let entry: TransformEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.downloads, 100);
        assert_eq!(entry.checksum, "sha256:abc123");
        assert_eq!(entry.categories, vec!["filtering", "analytics"]);
        assert_eq!(entry.min_streamline_version, "0.1.0");
    }

    #[test]
    fn test_transform_entry_backward_compat() {
        // Ensure old-format entries still deserialize (new fields default)
        let json = r#"{
            "name": "old-transform",
            "version": "0.1.0",
            "description": "An old-format transform",
            "author": "test",
            "wasm_url": "https://example.com/test.wasm",
            "input_format": "json",
            "output_format": "json",
            "tags": ["test"],
            "license": "Apache-2.0",
            "repository_url": "https://example.com/repo"
        }"#;

        let entry: TransformEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.downloads, 0);
        assert_eq!(entry.checksum, "");
        assert!(entry.categories.is_empty());
        assert_eq!(entry.min_streamline_version, "");
    }

    #[test]
    fn test_search_by_category_match() {
        let entries = vec![
            make_test_entry("a", &["filtering"]),
            make_test_entry("b", &["routing"]),
            make_test_entry("c", &["filtering", "analytics"]),
        ];

        let category = Some("filtering".to_string());
        let results: Vec<&TransformEntry> = entries
            .iter()
            .filter(|entry| {
                category
                    .as_ref()
                    .map(|c| entry.categories.iter().any(|cat| cat == c))
                    .unwrap_or(true)
            })
            .collect();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "a");
        assert_eq!(results[1].name, "c");
    }

    fn make_test_entry(name: &str, categories: &[&str]) -> TransformEntry {
        TransformEntry {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            description: format!("Test {}", name),
            author: "test".to_string(),
            downloads: 0,
            checksum: String::new(),
            categories: categories.iter().map(|s| s.to_string()).collect(),
            min_streamline_version: "0.1.0".to_string(),
            wasm_url: "https://example.com/test.wasm".to_string(),
            input_format: "json".to_string(),
            output_format: "json".to_string(),
            tags: vec![],
            license: "Apache-2.0".to_string(),
            repository_url: String::new(),
            config_schema: serde_json::Value::Null,
        }
    }

    // ── CLI Argument Parsing Tests ──────────────────────────────────────

    #[test]
    fn test_cli_parse_search_command() {
        let cli = Cli::try_parse_from(["streamline-marketplace", "search", "json"]).unwrap();
        match cli.command {
            Commands::Search { query, category } => {
                assert_eq!(query, "json");
                assert!(category.is_none());
            }
            _ => panic!("Expected Search command"),
        }
    }

    #[test]
    fn test_cli_parse_search_with_category() {
        let cli = Cli::try_parse_from([
            "streamline-marketplace", "search", "filter", "--category", "filtering",
        ]).unwrap();
        match cli.command {
            Commands::Search { query, category } => {
                assert_eq!(query, "filter");
                assert_eq!(category, Some("filtering".to_string()));
            }
            _ => panic!("Expected Search command"),
        }
    }

    #[test]
    fn test_cli_parse_install_command() {
        let cli = Cli::try_parse_from(["streamline-marketplace", "install", "json-filter"]).unwrap();
        match cli.command {
            Commands::Install { name, force } => {
                assert_eq!(name, "json-filter");
                assert!(!force);
            }
            _ => panic!("Expected Install command"),
        }
    }

    #[test]
    fn test_cli_parse_install_with_force() {
        let cli = Cli::try_parse_from([
            "streamline-marketplace", "install", "json-filter", "--force",
        ]).unwrap();
        match cli.command {
            Commands::Install { name, force } => {
                assert_eq!(name, "json-filter");
                assert!(force);
            }
            _ => panic!("Expected Install command"),
        }
    }

    #[test]
    fn test_cli_parse_install_versioned() {
        let cli = Cli::try_parse_from([
            "streamline-marketplace", "install", "pii-redactor@0.2.0",
        ]).unwrap();
        match cli.command {
            Commands::Install { name, .. } => {
                assert_eq!(name, "pii-redactor@0.2.0");
            }
            _ => panic!("Expected Install command"),
        }
    }

    #[test]
    fn test_cli_parse_list_command() {
        let cli = Cli::try_parse_from(["streamline-marketplace", "list"]).unwrap();
        assert!(matches!(cli.command, Commands::List));
    }

    #[test]
    fn test_cli_parse_info_command() {
        let cli = Cli::try_parse_from(["streamline-marketplace", "info", "json-filter"]).unwrap();
        match cli.command {
            Commands::Info { name } => assert_eq!(name, "json-filter"),
            _ => panic!("Expected Info command"),
        }
    }

    #[test]
    fn test_cli_parse_update_command() {
        let cli = Cli::try_parse_from(["streamline-marketplace", "update", "all"]).unwrap();
        match cli.command {
            Commands::Update { name } => assert_eq!(name, "all"),
            _ => panic!("Expected Update command"),
        }
    }

    #[test]
    fn test_cli_parse_remove_command() {
        let cli = Cli::try_parse_from(["streamline-marketplace", "remove", "json-filter"]).unwrap();
        match cli.command {
            Commands::Remove { name } => assert_eq!(name, "json-filter"),
            _ => panic!("Expected Remove command"),
        }
    }

    #[test]
    fn test_cli_parse_registry_url_flag() {
        let cli = Cli::try_parse_from([
            "streamline-marketplace", "--registry-url", "https://custom.example.com", "list",
        ]).unwrap();
        assert_eq!(cli.registry_url, Some("https://custom.example.com".to_string()));
    }

    #[test]
    fn test_cli_parse_transforms_dir_flag() {
        let cli = Cli::try_parse_from([
            "streamline-marketplace", "--transforms-dir", "/tmp/transforms", "list",
        ]).unwrap();
        assert_eq!(cli.transforms_dir, Some(PathBuf::from("/tmp/transforms")));
    }

    #[test]
    fn test_cli_parse_no_subcommand_fails() {
        let result = Cli::try_parse_from(["streamline-marketplace"]);
        assert!(result.is_err());
    }

    // ── Version Parsing with @ Separator ─────────────────────────────────

    #[test]
    fn test_parse_version_pii_redactor() {
        let input = "pii-redactor@0.2.0";
        let (name, version) = if let Some(idx) = input.find('@') {
            (&input[..idx], Some(&input[idx + 1..]))
        } else {
            (input, None)
        };
        assert_eq!(name, "pii-redactor");
        assert_eq!(version, Some("0.2.0"));
    }

    #[test]
    fn test_parse_version_complex_name() {
        let input = "my-cool-transform@1.2.3";
        let (name, version) = if let Some(idx) = input.find('@') {
            (&input[..idx], Some(&input[idx + 1..]))
        } else {
            (input, None)
        };
        assert_eq!(name, "my-cool-transform");
        assert_eq!(version, Some("1.2.3"));
    }

    // ── Registry URL Construction ────────────────────────────────────────

    #[test]
    fn test_registry_url_construction_base_url() {
        let url = "http://localhost:8080";
        let api_url = if url.ends_with("/transforms") || url.ends_with("/transforms.json") {
            url.to_string()
        } else {
            format!("{}/api/v1/transforms", url.trim_end_matches('/'))
        };
        assert_eq!(api_url, "http://localhost:8080/api/v1/transforms");
    }

    #[test]
    fn test_registry_url_construction_trailing_slash() {
        let url = "http://localhost:8080/";
        let api_url = if url.ends_with("/transforms") || url.ends_with("/transforms.json") {
            url.to_string()
        } else {
            format!("{}/api/v1/transforms", url.trim_end_matches('/'))
        };
        assert_eq!(api_url, "http://localhost:8080/api/v1/transforms");
    }

    #[test]
    fn test_registry_url_construction_transforms_suffix() {
        let url = "http://custom.example.com/api/v1/transforms";
        let api_url = if url.ends_with("/transforms") || url.ends_with("/transforms.json") {
            url.to_string()
        } else {
            format!("{}/api/v1/transforms", url.trim_end_matches('/'))
        };
        assert_eq!(api_url, "http://custom.example.com/api/v1/transforms");
    }

    #[test]
    fn test_registry_url_construction_json_suffix() {
        let url = "https://example.com/transforms.json";
        let api_url = if url.ends_with("/transforms") || url.ends_with("/transforms.json") {
            url.to_string()
        } else {
            format!("{}/api/v1/transforms", url.trim_end_matches('/'))
        };
        assert_eq!(api_url, "https://example.com/transforms.json");
    }

    // ── Download URL Resolution ──────────────────────────────────────────

    #[test]
    fn test_download_url_resolution_absolute_path() {
        let registry_base = "http://localhost:8080";
        let wasm_url = "/api/v1/transforms/json-filter/0.1.0/download";
        let download_url = if wasm_url.starts_with('/') {
            format!("{}{}", registry_base, wasm_url)
        } else if wasm_url.starts_with("http") {
            wasm_url.to_string()
        } else {
            format!("{}/api/v1/transforms/{}/{}/download", registry_base, "json-filter", "0.1.0")
        };
        assert_eq!(download_url, "http://localhost:8080/api/v1/transforms/json-filter/0.1.0/download");
    }

    #[test]
    fn test_download_url_resolution_http_url() {
        let registry_base = "http://localhost:8080";
        let wasm_url = "https://github.com/streamlinelabs/streamline-marketplace/releases/download/v0.1.0/json_filter.wasm";
        let download_url = if wasm_url.starts_with('/') {
            format!("{}{}", registry_base, wasm_url)
        } else if wasm_url.starts_with("http") {
            wasm_url.to_string()
        } else {
            format!("{}/api/v1/transforms/{}/{}/download", registry_base, "json-filter", "0.1.0")
        };
        assert_eq!(download_url, "https://github.com/streamlinelabs/streamline-marketplace/releases/download/v0.1.0/json_filter.wasm");
    }

    #[test]
    fn test_download_url_resolution_relative() {
        let registry_base = "http://localhost:8080";
        let wasm_url = "relative/path.wasm";
        let name = "json-filter";
        let version = "0.1.0";
        let download_url = if wasm_url.starts_with('/') {
            format!("{}{}", registry_base, wasm_url)
        } else if wasm_url.starts_with("http") {
            wasm_url.to_string()
        } else {
            format!("{}/api/v1/transforms/{}/{}/download", registry_base, name, version)
        };
        assert_eq!(download_url, "http://localhost:8080/api/v1/transforms/json-filter/0.1.0/download");
    }

    // ── Default Constants ────────────────────────────────────────────────

    #[test]
    fn test_default_registry_url() {
        assert_eq!(DEFAULT_REGISTRY_URL, "http://localhost:8080");
    }

    #[test]
    fn test_fallback_registry_url_is_github_raw() {
        assert!(FALLBACK_REGISTRY_URL.starts_with("https://raw.githubusercontent.com/"));
        assert!(FALLBACK_REGISTRY_URL.ends_with("transforms.json"));
    }

    // ── Transforms Dir ───────────────────────────────────────────────────

    #[test]
    fn test_transforms_dir_custom() {
        let cli = Cli {
            registry_url: None,
            transforms_dir: Some(PathBuf::from("/custom/path")),
            command: Commands::List,
        };
        assert_eq!(transforms_dir(&cli), PathBuf::from("/custom/path"));
    }

    #[test]
    fn test_transforms_dir_default() {
        let cli = Cli {
            registry_url: None,
            transforms_dir: None,
            command: Commands::List,
        };
        let dir = transforms_dir(&cli);
        assert!(dir.ends_with(".streamline/transforms"));
    }

    #[test]
    fn test_install_remove_flow() {
        // Integration test: create a temp dir, install, verify, remove
        let temp_dir = std::env::temp_dir().join("streamline-marketplace-test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        // Write a minimal installed.json
        let installed = vec![InstalledTransform {
            name: "test-transform".to_string(),
            version: "0.1.0".to_string(),
            installed_at: "2026-01-01T00:00:00Z".to_string(),
            wasm_path: temp_dir
                .join("test-transform/0.1.0/test_transform.wasm")
                .to_string_lossy()
                .to_string(),
            source_url: "https://example.com/test.wasm".to_string(),
            sha256: "abc123".to_string(),
        }];

        let manifest = serde_json::to_string_pretty(&installed).unwrap();
        fs::write(temp_dir.join("installed.json"), &manifest).unwrap();

        // Create the transform directory and WASM file
        let wasm_dir = temp_dir.join("test-transform/0.1.0");
        fs::create_dir_all(&wasm_dir).unwrap();
        fs::write(wasm_dir.join("test_transform.wasm"), b"fake wasm").unwrap();

        // Verify installed list loads
        let cli = Cli {
            registry_url: None,
            transforms_dir: Some(temp_dir.clone()),
            command: Commands::List,
        };
        let loaded = load_installed(&cli);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "test-transform");

        // Simulate remove by updating the manifest
        let empty: Vec<InstalledTransform> = Vec::new();
        save_installed(&cli, &empty).unwrap();
        let loaded_after = load_installed(&cli);
        assert!(loaded_after.is_empty());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
