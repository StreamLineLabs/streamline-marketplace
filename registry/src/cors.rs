//! CORS policy for the registry server.
//!
//! Cross-origin access is deny-by-default. Origins must be listed explicitly in
//! `REGISTRY_ALLOWED_ORIGINS` (comma-separated); methods and headers are fixed
//! to what the API actually needs. Invalid configuration is a startup failure,
//! never a silent fallback to a permissive policy.

use axum::http::{header, HeaderValue, Method};
use tower_http::cors::CorsLayer;

/// Environment variable listing permitted browser origins.
pub const ORIGINS_ENV: &str = "REGISTRY_ALLOWED_ORIGINS";

/// Invalid CORS configuration.
#[derive(Debug, PartialEq, Eq)]
pub enum CorsConfigError {
    /// An origin entry is not a usable HTTP origin value.
    InvalidOrigin(String),
}

impl std::fmt::Display for CorsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOrigin(o) => write!(
                f,
                "{ORIGINS_ENV} contains an invalid origin '{o}'; expected values like \
                 'https://example.com' (scheme + host, no path, no wildcard)"
            ),
        }
    }
}

impl std::error::Error for CorsConfigError {}

/// Parse a comma-separated origin list into validated header values.
pub fn parse_origins(raw: &str) -> Result<Vec<HeaderValue>, CorsConfigError> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            if !is_valid_origin(entry) {
                return Err(CorsConfigError::InvalidOrigin(entry.to_string()));
            }
            HeaderValue::from_str(entry)
                .map_err(|_| CorsConfigError::InvalidOrigin(entry.to_string()))
        })
        .collect()
}

/// An origin is `scheme "://" host [":" port]` with no path, wildcard, or
/// credentials. `*` and `null` are rejected on purpose.
fn is_valid_origin(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    if !matches!(scheme, "http" | "https") {
        return false;
    }
    if rest.is_empty()
        || rest.contains('/')
        || rest.contains('*')
        || rest.contains('@')
        || rest.contains(' ')
        || !rest.is_ascii()
    {
        return false;
    }
    let host = rest.split(':').next().unwrap_or("");
    !host.is_empty()
}

/// Build the CORS layer for the configured origins.
///
/// An empty list yields a layer that allows no cross-origin request.
pub fn layer(origins: Vec<HeaderValue>) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(vec![Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(vec![header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(std::time::Duration::from_secs(600))
}

/// Read the configured origins from the environment.
pub fn origins_from_env() -> Result<Vec<HeaderValue>, CorsConfigError> {
    match std::env::var(ORIGINS_ENV) {
        Ok(raw) => parse_origins(&raw),
        Err(_) => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_explicit_origins() {
        let origins = parse_origins("https://portal.example.com, http://localhost:3000").unwrap();
        assert_eq!(origins.len(), 2);
        assert_eq!(origins[0], "https://portal.example.com");
        assert_eq!(origins[1], "http://localhost:3000");
    }

    #[test]
    fn empty_configuration_allows_no_origin() {
        assert!(parse_origins("").unwrap().is_empty());
        assert!(parse_origins("  , ").unwrap().is_empty());
    }

    #[test]
    fn rejects_wildcards_paths_and_bad_schemes() {
        for bad in [
            "*",
            "null",
            "https://*.example.com",
            "https://example.com/path",
            "ftp://example.com",
            "example.com",
            "https://",
            "https://exa mple.com",
            "https://exämple.com",
        ] {
            assert_eq!(
                parse_origins(bad).unwrap_err(),
                CorsConfigError::InvalidOrigin(bad.to_string()),
                "expected rejection for {bad}"
            );
        }
    }

    #[test]
    fn one_invalid_entry_fails_the_whole_configuration() {
        assert!(parse_origins("https://ok.example.com,*").is_err());
    }

    #[test]
    fn layer_builds_for_valid_and_empty_origins() {
        let _ = layer(parse_origins("https://ok.example.com").unwrap());
        let _ = layer(Vec::new());
    }
}
