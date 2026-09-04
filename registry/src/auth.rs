//! Publish authentication for the registry server.
//!
//! The registry requires an explicit `REGISTRY_AUTH_TOKEN`. There is no
//! development fallback: a server without a configured token refuses to start.

use axum::http::HeaderMap;

use crate::checksum::constant_time_eq;

/// Environment variable holding the publish token.
pub const TOKEN_ENV: &str = "REGISTRY_AUTH_TOKEN";

/// Minimum accepted token length; short tokens are trivially guessable.
pub const MIN_TOKEN_LEN: usize = 16;

/// Configuration errors that must prevent the server from starting.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthConfigError {
    /// `REGISTRY_AUTH_TOKEN` is unset or empty.
    Missing,
    /// `REGISTRY_AUTH_TOKEN` is set but too short to be safe.
    TooShort(usize),
    /// `REGISTRY_AUTH_TOKEN` contains bytes that cannot appear in a header.
    NotHeaderSafe,
}

impl std::fmt::Display for AuthConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(
                f,
                "{TOKEN_ENV} is not set. The registry refuses to start without an explicit publish token."
            ),
            Self::TooShort(len) => write!(
                f,
                "{TOKEN_ENV} is {len} characters; at least {MIN_TOKEN_LEN} are required."
            ),
            Self::NotHeaderSafe => write!(
                f,
                "{TOKEN_ENV} must contain only printable ASCII characters and no whitespace."
            ),
        }
    }
}

impl std::error::Error for AuthConfigError {}

/// Reasons a publish request is rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    /// No `Authorization` header was supplied.
    MissingHeader,
    /// The header value is not visible ASCII (e.g. contains Unicode).
    NonAsciiHeader,
    /// The header does not use the `Bearer` scheme with a credential.
    MalformedHeader,
    /// The credential does not match the configured token.
    InvalidToken,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately uniform and non-specific for clients.
        write!(f, "Invalid or missing Authorization header")
    }
}

/// A validated publish token.
#[derive(Clone)]
pub struct AuthConfig {
    token: String,
}

impl std::fmt::Debug for AuthConfig {
    /// Never print the token itself.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("token", &"<redacted>")
            .finish()
    }
}

impl AuthConfig {
    /// Build a config from an explicit token value.
    pub fn new(token: impl Into<String>) -> Result<Self, AuthConfigError> {
        let token: String = token.into();
        if token.is_empty() {
            return Err(AuthConfigError::Missing);
        }
        if !token
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
        {
            return Err(AuthConfigError::NotHeaderSafe);
        }
        if token.len() < MIN_TOKEN_LEN {
            return Err(AuthConfigError::TooShort(token.len()));
        }
        Ok(Self { token })
    }

    /// Read the token from the environment. Fails when unset or empty.
    pub fn from_env() -> Result<Self, AuthConfigError> {
        match std::env::var(TOKEN_ENV) {
            Ok(token) => Self::new(token),
            Err(_) => Err(AuthConfigError::Missing),
        }
    }

    /// Authorize a request from its headers.
    ///
    /// Parsing never indexes into the header value, so malformed or non-ASCII
    /// input is rejected rather than panicking.
    pub fn authorize(&self, headers: &HeaderMap) -> Result<(), AuthError> {
        let raw = headers
            .get(axum::http::header::AUTHORIZATION)
            .ok_or(AuthError::MissingHeader)?;
        let value = raw.to_str().map_err(|_| AuthError::NonAsciiHeader)?;
        let credential = bearer_credential(value).ok_or(AuthError::MalformedHeader)?;
        if constant_time_eq(credential.as_bytes(), self.token.as_bytes()) {
            Ok(())
        } else {
            Err(AuthError::InvalidToken)
        }
    }
}

/// Extract the credential from an `Authorization: Bearer <token>` value.
///
/// The scheme is matched case-insensitively per RFC 7235; a missing scheme,
/// missing credential, or extra whitespace-separated parameters yield `None`.
fn bearer_credential(value: &str) -> Option<&str> {
    let value = value.trim();
    let (scheme, rest) = value.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let credential = rest.trim();
    if credential.is_empty() || credential.split_whitespace().count() != 1 {
        return None;
    }
    Some(credential)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    const TOKEN: &str = "test-token-0123456789";

    fn config() -> AuthConfig {
        AuthConfig::new(TOKEN).unwrap()
    }

    fn headers_with(raw: &[u8]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Ok(value) = HeaderValue::from_bytes(raw) {
            headers.insert(axum::http::header::AUTHORIZATION, value);
        }
        headers
    }

    #[test]
    fn accepts_exact_bearer_token_case_insensitive_scheme() {
        let cfg = config();
        cfg.authorize(&headers_with(format!("Bearer {TOKEN}").as_bytes()))
            .unwrap();
        cfg.authorize(&headers_with(format!("bearer {TOKEN}").as_bytes()))
            .unwrap();
        cfg.authorize(&headers_with(format!("  BEARER   {TOKEN}  ").as_bytes()))
            .unwrap();
    }

    #[test]
    fn rejects_missing_and_malformed_headers_without_panicking() {
        let cfg = config();
        assert_eq!(
            cfg.authorize(&HeaderMap::new()).unwrap_err(),
            AuthError::MissingHeader
        );
        for raw in [
            "",
            "Bearer",
            "Bearer ",
            "Bear",
            "Be",
            "B",
            "Basic dXNlcjpwYXNz",
            "Bearer  ",
            "Token abc",
        ] {
            let err = cfg.authorize(&headers_with(raw.as_bytes())).unwrap_err();
            assert!(
                matches!(
                    err,
                    AuthError::MalformedHeader | AuthError::MissingHeader | AuthError::InvalidToken
                ),
                "unexpected error for {raw:?}: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_unicode_and_non_ascii_headers() {
        let cfg = config();
        // Valid UTF-8 but non-visible-ASCII header bytes.
        let headers = headers_with("Bearer ünïcödé-tökén".as_bytes());
        assert_eq!(
            cfg.authorize(&headers).unwrap_err(),
            AuthError::NonAsciiHeader
        );

        // A multi-byte prefix shorter than "Bearer " must not be sliced.
        let headers = headers_with("Béa".as_bytes());
        assert!(cfg.authorize(&headers).is_err());
    }

    #[test]
    fn rejects_wrong_tokens_including_prefixes_and_suffixes() {
        let cfg = config();
        for candidate in [
            "wrong-token-0123456789",
            "test-token-012345678",
            "test-token-01234567890",
            "TEST-TOKEN-0123456789",
        ] {
            assert_eq!(
                cfg.authorize(&headers_with(format!("Bearer {candidate}").as_bytes()))
                    .unwrap_err(),
                AuthError::InvalidToken
            );
        }
        // Extra parameters after the credential are not accepted.
        assert_eq!(
            cfg.authorize(&headers_with(format!("Bearer {TOKEN} extra").as_bytes()))
                .unwrap_err(),
            AuthError::MalformedHeader
        );
    }

    #[test]
    fn config_rejects_missing_short_and_unsafe_tokens() {
        assert_eq!(AuthConfig::new("").unwrap_err(), AuthConfigError::Missing);
        assert_eq!(
            AuthConfig::new("short").unwrap_err(),
            AuthConfigError::TooShort(5)
        );
        assert_eq!(
            AuthConfig::new("token with spaces 123456").unwrap_err(),
            AuthConfigError::NotHeaderSafe
        );
        assert_eq!(
            AuthConfig::new("tökén-0123456789abcdef").unwrap_err(),
            AuthConfigError::NotHeaderSafe
        );
        assert!(AuthConfig::new("a-perfectly-fine-token").is_ok());
    }
}
