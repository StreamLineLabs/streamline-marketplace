//! Checksum policy for downloaded marketplace artifacts.
//!
//! The only supported artifact digest format is `sha256:<64 lowercase hex>`.
//! Catalog entries whose artifact has not been released yet carry the explicit
//! [`PENDING`] sentinel; a pending checksum is never treated as verified.

use sha2::{Digest, Sha256};

/// Prefix of the only supported digest algorithm.
pub const SHA256_PREFIX: &str = "sha256:";

/// Sentinel used by catalog entries whose artifact has not been published yet.
pub const PENDING: &str = "pending";

/// Why a checksum value cannot be used for verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChecksumError {
    /// The checksum field is empty.
    Missing,
    /// The artifact has not been released; no digest exists yet.
    Pending,
    /// A digest algorithm other than SHA-256 was requested.
    UnsupportedAlgorithm(String),
    /// The value has the right prefix but is not 64 hex characters.
    Malformed(String),
    /// The digest is well-formed but does not match the artifact bytes.
    Mismatch { expected: String, actual: String },
}

impl std::fmt::Display for ChecksumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "checksum is empty; expected 'sha256:<64 hex chars>'"),
            Self::Pending => write!(
                f,
                "checksum is '{PENDING}': the artifact has not been released yet"
            ),
            Self::UnsupportedAlgorithm(v) => {
                write!(
                    f,
                    "unsupported checksum algorithm in '{v}'; expected 'sha256:'"
                )
            }
            Self::Malformed(v) => write!(
                f,
                "malformed checksum '{v}'; expected 'sha256:' followed by 64 hex chars"
            ),
            Self::Mismatch { expected, actual } => {
                write!(
                    f,
                    "checksum mismatch: expected {expected}, computed {actual}"
                )
            }
        }
    }
}

impl std::error::Error for ChecksumError {}

/// True when the value is the explicit "artifact not released yet" sentinel.
pub fn is_pending(value: &str) -> bool {
    value == PENDING || value == concat!("sha256:", "pending")
}

/// Parse a `sha256:<64 hex>` checksum into its raw 32 digest bytes.
///
/// Fails closed: empty, pending, non-SHA-256, or malformed values never parse.
pub fn parse_sha256(value: &str) -> Result<[u8; 32], ChecksumError> {
    if value.is_empty() {
        return Err(ChecksumError::Missing);
    }
    if is_pending(value) {
        return Err(ChecksumError::Pending);
    }
    let hex_part = value
        .strip_prefix(SHA256_PREFIX)
        .ok_or_else(|| ChecksumError::UnsupportedAlgorithm(value.to_string()))?;
    if hex_part.len() != 64 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ChecksumError::Malformed(value.to_string()));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_part.to_ascii_lowercase(), &mut out)
        .map_err(|_| ChecksumError::Malformed(value.to_string()))?;
    Ok(out)
}

/// Render digest bytes in the canonical catalog format.
pub fn format_sha256(digest: &[u8]) -> String {
    format!("{SHA256_PREFIX}{}", hex::encode(digest))
}

/// Compute the canonical checksum string for artifact bytes.
pub fn compute(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format_sha256(&hasher.finalize())
}

/// Constant-time byte comparison (no early return on first difference).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify artifact bytes against an expected catalog checksum.
pub fn verify(expected: &str, data: &[u8]) -> Result<(), ChecksumError> {
    let expected_digest = parse_sha256(expected)?;
    let mut hasher = Sha256::new();
    hasher.update(data);
    let actual_digest = hasher.finalize();
    if constant_time_eq(&expected_digest, &actual_digest) {
        Ok(())
    } else {
        Err(ChecksumError::Mismatch {
            expected: format_sha256(&expected_digest),
            actual: format_sha256(&actual_digest),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO: &str = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    #[test]
    fn parses_valid_lowercase_and_uppercase_hex() {
        let lower = parse_sha256(HELLO).unwrap();
        let upper = parse_sha256(&HELLO.to_uppercase().replace("SHA256:", "sha256:")).unwrap();
        assert_eq!(lower, upper);
    }

    #[test]
    fn rejects_empty_pending_and_bad_prefix() {
        assert_eq!(parse_sha256("").unwrap_err(), ChecksumError::Missing);
        assert_eq!(parse_sha256("pending").unwrap_err(), ChecksumError::Pending);
        assert_eq!(
            parse_sha256("sha256:pending").unwrap_err(),
            ChecksumError::Pending
        );
        assert!(matches!(
            parse_sha256("sha512:00").unwrap_err(),
            ChecksumError::UnsupportedAlgorithm(_)
        ));
        // Bare hex without an algorithm prefix is not supported.
        assert!(matches!(
            parse_sha256(&HELLO[7..]).unwrap_err(),
            ChecksumError::UnsupportedAlgorithm(_)
        ));
    }

    #[test]
    fn rejects_malformed_hex() {
        assert!(matches!(
            parse_sha256("sha256:zz").unwrap_err(),
            ChecksumError::Malformed(_)
        ));
        assert!(matches!(
            parse_sha256(&format!("sha256:{}", "g".repeat(64))).unwrap_err(),
            ChecksumError::Malformed(_)
        ));
        // Non-ASCII must not panic or slice mid-character.
        assert!(matches!(
            parse_sha256("sha256:é").unwrap_err(),
            ChecksumError::Malformed(_)
        ));
        assert!(matches!(
            parse_sha256(" sha256:00").unwrap_err(),
            ChecksumError::UnsupportedAlgorithm(_)
        ));
    }

    #[test]
    fn verifies_matching_bytes_and_detects_induced_mismatch() {
        assert_eq!(compute(b"hello world"), HELLO);
        verify(HELLO, b"hello world").unwrap();
        let err = verify(HELLO, b"hello worlD").unwrap_err();
        assert!(matches!(err, ChecksumError::Mismatch { .. }));
        assert!(verify("", b"hello world").is_err());
        assert!(verify(PENDING, b"hello world").is_err());
    }

    #[test]
    fn constant_time_eq_matches_semantics_of_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
