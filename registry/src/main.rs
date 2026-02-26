//! Streamline WASM Transform Marketplace — Registry Server
//!
//! An HTTP API for discovering, downloading, and publishing WASM transforms.

use axum::{
    extract::{Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

mod portal;
mod security;
mod store;

use store::DataStore;

/// Categories recognized by the marketplace.
#[allow(dead_code)]
const VALID_CATEGORIES: &[&str] = &[
    "filter",
    "transform",
    "aggregate",
    "enrich",
    "route",
    // Legacy aliases (kept for backward-compat with existing registry data)
    "filtering",
    "enrichment",
    "routing",
    "security",
    "analytics",
    "format-conversion",
];

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A transform entry stored in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformEntry {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    #[serde(default)]
    pub downloads: u64,
    #[serde(default)]
    pub checksum: String,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub min_streamline_version: String,
    #[serde(default)]
    pub wasm_url: String,
    #[serde(default)]
    pub input_format: String,
    #[serde(default)]
    pub output_format: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub repository_url: String,
    #[serde(default)]
    pub config_schema: serde_json::Value,
}

/// Version summary returned by the versions endpoint.
#[derive(Debug, Serialize)]
struct VersionInfo {
    version: String,
    checksum: String,
    downloads: u64,
}

/// Payload for publishing a transform (metadata part).
#[derive(Debug, Deserialize)]
struct PublishMeta {
    name: String,
    version: String,
    description: String,
    author: String,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    min_streamline_version: String,
    #[serde(default)]
    input_format: String,
    #[serde(default)]
    output_format: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    license: String,
    #[serde(default)]
    repository_url: String,
    #[serde(default)]
    config_schema: serde_json::Value,
}

/// Search / filter query parameters.
#[derive(Debug, Deserialize)]
struct SearchParams {
    q: Option<String>,
    category: Option<String>,
    author: Option<String>,
    sort: Option<String>,
}

type AppState = Arc<RwLock<DataStore>>;

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "streamline_registry=info,tower_http=info".into()),
        )
        .init();

    let data_dir = std::env::var("REGISTRY_DATA_DIR").unwrap_or_else(|_| {
        // Default: <binary-dir>/data  or  registry/data
        let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
        format!("{}/data", manifest)
    });

    let store = DataStore::load(&data_dir);
    let state: AppState = Arc::new(RwLock::new(store));

    let app = Router::new()
        .route("/api/v1/transforms", get(list_transforms))
        .route("/api/v1/transforms", post(publish_transform))
        .route("/api/v1/transforms/{name}", get(get_transform))
        .route(
            "/api/v1/transforms/{name}/versions",
            get(get_transform_versions),
        )
        .route(
            "/api/v1/transforms/{name}/{version}/download",
            get(download_transform),
        )
        .route("/api/v1/categories", get(list_categories))
        .route("/healthz", get(healthz))
        .layer(
            tower_http::cors::CorsLayer::permissive()
        )
        .with_state(state);

    let bind = std::env::var("REGISTRY_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    tracing::info!("Marketplace registry listening on {}", bind);

    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn healthz() -> &'static str {
    "ok"
}

/// `GET /api/v1/transforms?q=...&category=...&author=...&sort=...`
async fn list_transforms(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> Json<Vec<TransformEntry>> {
    let store = state.read().await;
    let mut results: Vec<TransformEntry> = store
        .transforms
        .values()
        .filter_map(|versions| versions.values().last().cloned())
        .collect();

    // Deduplicate: keep only latest version per name
    let mut latest: HashMap<String, TransformEntry> = HashMap::new();
    for entry in &results {
        let existing = latest.get(&entry.name);
        if existing.is_none() || version_gt(&entry.version, &existing.unwrap().version) {
            latest.insert(entry.name.clone(), entry.clone());
        }
    }
    results = latest.into_values().collect();

    if let Some(ref q) = params.q {
        let q = q.to_lowercase();
        results.retain(|e| {
            e.name.to_lowercase().contains(&q)
                || e.description.to_lowercase().contains(&q)
                || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
        });
    }

    if let Some(ref cat) = params.category {
        let cat = cat.to_lowercase();
        results.retain(|e| e.categories.iter().any(|c| c.to_lowercase() == cat));
    }

    if let Some(ref author) = params.author {
        let author = author.to_lowercase();
        results.retain(|e| e.author.to_lowercase() == author);
    }

    match params.sort.as_deref() {
        Some("downloads") => results.sort_by(|a, b| b.downloads.cmp(&a.downloads)),
        Some("name") => results.sort_by(|a, b| a.name.cmp(&b.name)),
        _ => results.sort_by(|a, b| b.downloads.cmp(&a.downloads)),
    }

    Json(results)
}

/// `GET /api/v1/transforms/{name}`
async fn get_transform(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<TransformEntry>, StatusCode> {
    let store = state.read().await;
    let versions = store.transforms.get(&name).ok_or(StatusCode::NOT_FOUND)?;
    let latest = versions
        .values()
        .max_by(|a, b| cmp_version(&a.version, &b.version))
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(latest.clone()))
}

/// `GET /api/v1/transforms/{name}/versions`
async fn get_transform_versions(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Vec<VersionInfo>>, StatusCode> {
    let store = state.read().await;
    let versions = store.transforms.get(&name).ok_or(StatusCode::NOT_FOUND)?;
    let infos: Vec<VersionInfo> = versions
        .values()
        .map(|e| VersionInfo {
            version: e.version.clone(),
            checksum: e.checksum.clone(),
            downloads: e.downloads,
        })
        .collect();
    Ok(Json(infos))
}

/// `GET /api/v1/transforms/{name}/{version}/download`
async fn download_transform(
    State(state): State<AppState>,
    Path((name, version)): Path<(String, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut store = state.write().await;
    let versions = store
        .transforms
        .get_mut(&name)
        .ok_or(StatusCode::NOT_FOUND)?;
    let entry = versions.get_mut(&version).ok_or(StatusCode::NOT_FOUND)?;

    // Increment download count
    entry.downloads += 1;

    let wasm_path = store.wasm_path(&name, &version);
    if !wasm_path.exists() {
        return Err(StatusCode::NOT_FOUND);
    }

    let bytes = tokio::fs::read(&wasm_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Persist updated download count (best-effort)
    let _ = store.save();

    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/wasm".to_string(),
        )],
        bytes,
    ))
}

/// `POST /api/v1/transforms` (multipart: `metadata` JSON + `wasm` binary)
async fn publish_transform(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<TransformEntry>), (StatusCode, String)> {
    // Simple Bearer token auth
    let expected_token =
        std::env::var("REGISTRY_AUTH_TOKEN").unwrap_or_else(|_| "streamline-dev".into());
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !auth.starts_with("Bearer ") || &auth[7..] != expected_token {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid or missing Authorization header".into(),
        ));
    }

    let mut meta: Option<PublishMeta> = None;
    let mut wasm_bytes: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    {
        match field.name() {
            Some("metadata") => {
                let data = field
                    .text()
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
                meta = Some(
                    serde_json::from_str(&data)
                        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid metadata: {}", e)))?,
                );
            }
            Some("wasm") => {
                wasm_bytes = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
                        .to_vec(),
                );
            }
            _ => {}
        }
    }

    let meta = meta.ok_or((StatusCode::BAD_REQUEST, "Missing 'metadata' field".into()))?;
    let wasm_bytes =
        wasm_bytes.ok_or((StatusCode::BAD_REQUEST, "Missing 'wasm' field".into()))?;

    // Validate name
    if meta.name.is_empty() || meta.version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "name and version are required".into(),
        ));
    }

    // Compute checksum
    let mut hasher = Sha256::new();
    hasher.update(&wasm_bytes);
    let checksum = format!("sha256:{}", hex::encode(hasher.finalize()));

    let mut store = state.write().await;

    // Check for duplicate version
    if let Some(versions) = store.transforms.get(&meta.name) {
        if versions.contains_key(&meta.version) {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "Version {} of '{}' already exists",
                    meta.version, meta.name
                ),
            ));
        }
    }

    // Save WASM binary
    let wasm_path = store.wasm_path(&meta.name, &meta.version);
    if let Some(parent) = wasm_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    tokio::fs::write(&wasm_path, &wasm_bytes)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let entry = TransformEntry {
        name: meta.name.clone(),
        version: meta.version.clone(),
        description: meta.description,
        author: meta.author,
        downloads: 0,
        checksum,
        categories: meta.categories,
        min_streamline_version: meta.min_streamline_version,
        wasm_url: format!(
            "/api/v1/transforms/{}/{}/download",
            meta.name, meta.version
        ),
        input_format: meta.input_format,
        output_format: meta.output_format,
        tags: meta.tags,
        license: meta.license,
        repository_url: meta.repository_url,
        config_schema: meta.config_schema,
    };

    store
        .transforms
        .entry(meta.name.clone())
        .or_default()
        .insert(meta.version.clone(), entry.clone());

    store
        .save()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::info!("Published {} v{}", meta.name, meta.version);

    Ok((StatusCode::CREATED, Json(entry)))
}

/// `GET /api/v1/categories`
async fn list_categories() -> Json<Vec<CategoryInfo>> {
    let cats = vec![
        CategoryInfo {
            name: "filter".into(),
            description: "Filter, drop, or deduplicate messages".into(),
        },
        CategoryInfo {
            name: "transform".into(),
            description: "Reshape, rename, or convert message formats".into(),
        },
        CategoryInfo {
            name: "aggregate".into(),
            description: "Window-based aggregations and rollups".into(),
        },
        CategoryInfo {
            name: "enrich".into(),
            description: "Add metadata, timestamps, or external data".into(),
        },
        CategoryInfo {
            name: "route".into(),
            description: "Route messages to different topics by field values".into(),
        },
        // Legacy categories
        CategoryInfo {
            name: "filtering".into(),
            description: "Filter and validate messages (legacy alias for 'filter')".into(),
        },
        CategoryInfo {
            name: "enrichment".into(),
            description: "Enrich messages with additional data (legacy alias for 'enrich')".into(),
        },
        CategoryInfo {
            name: "routing".into(),
            description: "Content-based message routing (legacy alias for 'route')".into(),
        },
        CategoryInfo {
            name: "security".into(),
            description: "PII redaction, encryption, and compliance transforms".into(),
        },
        CategoryInfo {
            name: "analytics".into(),
            description: "Metrics, aggregation, and analytical transforms".into(),
        },
        CategoryInfo {
            name: "format-conversion".into(),
            description: "Convert between data formats (JSON, Avro, CSV, etc.)".into(),
        },
    ];
    Json(cats)
}

#[derive(Serialize)]
struct CategoryInfo {
    name: String,
    description: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_version(v: &str) -> (u64, u64, u64) {
    let parts: Vec<u64> = v.split('.').filter_map(|p| p.parse().ok()).collect();
    (
        parts.first().copied().unwrap_or(0),
        parts.get(1).copied().unwrap_or(0),
        parts.get(2).copied().unwrap_or(0),
    )
}

fn version_gt(a: &str, b: &str) -> bool {
    parse_version(a) > parse_version(b)
}

fn cmp_version(a: &str, b: &str) -> std::cmp::Ordering {
    parse_version(a).cmp(&parse_version(b))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_gt() {
        assert!(version_gt("0.2.0", "0.1.0"));
        assert!(version_gt("1.0.0", "0.9.9"));
        assert!(!version_gt("0.1.0", "0.1.0"));
    }

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("1.2.3"), (1, 2, 3));
        assert_eq!(parse_version("0.1.0"), (0, 1, 0));
    }

    #[test]
    fn test_transform_entry_serde() {
        let entry = TransformEntry {
            name: "test".into(),
            version: "0.1.0".into(),
            description: "desc".into(),
            author: "me".into(),
            downloads: 10,
            checksum: "sha256:abc".into(),
            categories: vec!["filter".into()],
            min_streamline_version: "0.1.0".into(),
            wasm_url: "http://localhost/test.wasm".into(),
            input_format: "json".into(),
            output_format: "json".into(),
            tags: vec!["test".into()],
            license: "Apache-2.0".into(),
            repository_url: "".into(),
            config_schema: serde_json::Value::Null,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: TransformEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.downloads, 10);
    }

    #[test]
    fn test_valid_categories_list() {
        assert!(VALID_CATEGORIES.contains(&"filter"));
        assert!(VALID_CATEGORIES.contains(&"transform"));
        assert!(VALID_CATEGORIES.contains(&"aggregate"));
        assert!(VALID_CATEGORIES.contains(&"enrich"));
        assert!(VALID_CATEGORIES.contains(&"route"));
    }
}
