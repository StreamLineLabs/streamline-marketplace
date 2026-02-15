//! PII Redactor Transform
//!
//! Detects and redacts personally identifiable information (PII) from JSON messages
//! using regex-based pattern matching.
//!
//! ## Supported PII Types
//!
//! - **Email addresses**: user@example.com
//! - **Phone numbers**: +1-555-123-4567, (555) 123-4567, 555.123.4567
//! - **Social Security Numbers**: 123-45-6789, 123456789
//! - **Credit card numbers**: 4111-1111-1111-1111 (common formats)
//! - **IP addresses**: 192.168.1.1 (IPv4)
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "patterns": ["email", "phone", "ssn"],
//!   "replacement": "***REDACTED***",
//!   "fields": ["email", "phone_number", "ssn"]
//! }
//! ```
//!
//! If `fields` is empty or omitted, all string fields in the JSON object are scanned.

use regex::Regex;
use serde_json::Value;

/// Global redactor configuration.
static mut CONFIG: Option<RedactorConfig> = None;

/// Redactor configuration.
struct RedactorConfig {
    /// Compiled regex patterns for each PII type.
    patterns: Vec<PiiPattern>,
    /// Replacement string for redacted values.
    replacement: String,
    /// Specific fields to scan (empty = scan all string fields).
    fields: Vec<String>,
}

/// A compiled PII detection pattern.
struct PiiPattern {
    /// Human-readable name (e.g., "email", "phone").
    #[allow(dead_code)]
    name: String,
    /// Compiled regex.
    regex: Regex,
}

/// Build PII patterns from the requested types.
fn build_patterns(types: &[String]) -> Vec<PiiPattern> {
    let mut patterns = Vec::new();

    let all = types.is_empty();

    if all || types.iter().any(|t| t == "email") {
        if let Ok(re) = Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}") {
            patterns.push(PiiPattern {
                name: "email".to_string(),
                regex: re,
            });
        }
    }

    if all || types.iter().any(|t| t == "phone") {
        // Matches various phone formats:
        // +1-555-123-4567, (555) 123-4567, 555.123.4567, 5551234567
        if let Ok(re) = Regex::new(
            r"(\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}",
        ) {
            patterns.push(PiiPattern {
                name: "phone".to_string(),
                regex: re,
            });
        }
    }

    if all || types.iter().any(|t| t == "ssn") {
        // Matches SSN: 123-45-6789 or 123456789
        if let Ok(re) = Regex::new(r"\b\d{3}-?\d{2}-?\d{4}\b") {
            patterns.push(PiiPattern {
                name: "ssn".to_string(),
                regex: re,
            });
        }
    }

    if types.iter().any(|t| t == "credit_card") {
        // Matches common credit card formats (13-19 digits, optionally separated)
        if let Ok(re) = Regex::new(r"\b(?:\d[ -]*?){13,19}\b") {
            patterns.push(PiiPattern {
                name: "credit_card".to_string(),
                regex: re,
            });
        }
    }

    if types.iter().any(|t| t == "ip_address") {
        // Matches IPv4 addresses
        if let Ok(re) = Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        ) {
            patterns.push(PiiPattern {
                name: "ip_address".to_string(),
                regex: re,
            });
        }
    }

    patterns
}

/// Redact PII from a string value.
fn redact_string(input: &str, config: &RedactorConfig) -> String {
    let mut result = input.to_string();
    for pattern in &config.patterns {
        result = pattern.regex.replace_all(&result, config.replacement.as_str()).to_string();
    }
    result
}

/// Recursively redact PII from a JSON value.
fn redact_value(value: &mut Value, config: &RedactorConfig) {
    match value {
        Value::String(s) => {
            *s = redact_string(s, config);
        }
        Value::Object(map) => {
            if config.fields.is_empty() {
                // Scan all fields
                for (_key, val) in map.iter_mut() {
                    redact_value(val, config);
                }
            } else {
                // Scan only specified fields
                for field in &config.fields {
                    if let Some(val) = map.get_mut(field) {
                        redact_value(val, config);
                    }
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_value(item, config);
            }
        }
        _ => {} // Numbers, booleans, nulls: no PII to redact
    }
}

/// Initialize the redactor with configuration JSON.
///
/// Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn init(config_ptr: *const u8, config_len: u32) -> u32 {
    let config_bytes = unsafe { std::slice::from_raw_parts(config_ptr, config_len as usize) };

    let config: Value = match serde_json::from_slice(config_bytes) {
        Ok(v) => v,
        Err(_) => {
            // Default: redact email, phone, SSN from all fields
            let patterns = build_patterns(&[]);
            unsafe {
                CONFIG = Some(RedactorConfig {
                    patterns,
                    replacement: "***REDACTED***".to_string(),
                    fields: Vec::new(),
                });
            }
            return 1;
        }
    };

    let pattern_types: Vec<String> = config
        .get("patterns")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let replacement = config
        .get("replacement")
        .and_then(|v| v.as_str())
        .unwrap_or("***REDACTED***")
        .to_string();

    let fields: Vec<String> = config
        .get("fields")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let patterns = build_patterns(&pattern_types);

    unsafe {
        CONFIG = Some(RedactorConfig {
            patterns,
            replacement,
            fields,
        });
    }

    1
}

/// Filter function: accept all messages.
#[no_mangle]
pub extern "C" fn filter(_input_ptr: *const u8, _input_len: u32) -> u32 {
    1
}

/// Transform a message by redacting PII from string fields.
#[no_mangle]
pub extern "C" fn transform(input_ptr: *const u8, input_len: u32, output_ptr: *mut u8) -> u32 {
    let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len as usize) };

    let config = unsafe {
        match CONFIG.as_ref() {
            Some(c) => c,
            None => {
                // No config: pass through
                std::ptr::copy_nonoverlapping(input.as_ptr(), output_ptr, input.len());
                return input_len;
            }
        }
    };

    // Parse JSON
    let mut value: Value = match serde_json::from_slice(input) {
        Ok(v) => v,
        Err(_) => {
            // Not valid JSON: pass through unchanged
            unsafe {
                std::ptr::copy_nonoverlapping(input.as_ptr(), output_ptr, input.len());
            }
            return input_len;
        }
    };

    // Redact PII
    redact_value(&mut value, config);

    // Serialize back
    let output = match serde_json::to_vec(&value) {
        Ok(v) => v,
        Err(_) => {
            unsafe {
                std::ptr::copy_nonoverlapping(input.as_ptr(), output_ptr, input.len());
            }
            return input_len;
        }
    };

    let len = output.len();
    unsafe {
        std::ptr::copy_nonoverlapping(output.as_ptr(), output_ptr, len);
    }
    len as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> RedactorConfig {
        RedactorConfig {
            patterns: build_patterns(&[]),
            replacement: "***REDACTED***".to_string(),
            fields: Vec::new(),
        }
    }

    #[test]
    fn test_redact_email() {
        let config = default_config();
        let result = redact_string("contact me at alice@example.com please", &config);
        assert!(!result.contains("alice@example.com"));
        assert!(result.contains("***REDACTED***"));
    }

    #[test]
    fn test_redact_phone() {
        let config = default_config();

        let result = redact_string("Call me at 555-123-4567", &config);
        assert!(!result.contains("555-123-4567"));
        assert!(result.contains("***REDACTED***"));

        let result2 = redact_string("Phone: (555) 123-4567", &config);
        assert!(!result2.contains("(555) 123-4567"));
    }

    #[test]
    fn test_redact_ssn() {
        let config = default_config();
        let result = redact_string("SSN: 123-45-6789", &config);
        assert!(!result.contains("123-45-6789"));
        assert!(result.contains("***REDACTED***"));
    }

    #[test]
    fn test_redact_json_all_fields() {
        let config = default_config();
        let mut json: Value = serde_json::json!({
            "name": "Alice",
            "email": "alice@example.com",
            "phone": "555-123-4567",
            "ssn": "123-45-6789",
            "age": 30
        });

        redact_value(&mut json, &config);

        assert_eq!(json["name"], "Alice"); // no PII
        assert!(json["email"].as_str().unwrap().contains("***REDACTED***"));
        assert!(json["phone"].as_str().unwrap().contains("***REDACTED***"));
        assert!(json["ssn"].as_str().unwrap().contains("***REDACTED***"));
        assert_eq!(json["age"], 30); // number untouched
    }

    #[test]
    fn test_redact_json_specific_fields() {
        let config = RedactorConfig {
            patterns: build_patterns(&[]),
            replacement: "[HIDDEN]".to_string(),
            fields: vec!["email".to_string()],
        };

        let mut json: Value = serde_json::json!({
            "email": "alice@example.com",
            "phone": "555-123-4567"
        });

        redact_value(&mut json, &config);

        // Only email should be redacted (it is in the specified fields)
        assert!(json["email"].as_str().unwrap().contains("[HIDDEN]"));
        // Phone is not in the fields list, so it should remain
        assert_eq!(json["phone"], "555-123-4567");
    }

    #[test]
    fn test_redact_nested_json() {
        let config = default_config();
        let mut json: Value = serde_json::json!({
            "user": {
                "contact": {
                    "email": "bob@test.org"
                }
            }
        });

        redact_value(&mut json, &config);

        let email = json["user"]["contact"]["email"].as_str().unwrap();
        assert!(email.contains("***REDACTED***"));
    }

    #[test]
    fn test_custom_replacement() {
        let config = RedactorConfig {
            patterns: build_patterns(&["email".to_string()]),
            replacement: "[EMAIL_REMOVED]".to_string(),
            fields: Vec::new(),
        };

        let result = redact_string("Email: test@foo.bar", &config);
        assert!(result.contains("[EMAIL_REMOVED]"));
    }

    #[test]
    fn test_no_pii_passthrough() {
        let config = default_config();
        let input = "Hello, this has no PII at all";
        let result = redact_string(input, &config);
        assert_eq!(result, input);
    }

    #[test]
    fn test_build_patterns_default() {
        let patterns = build_patterns(&[]);
        // Default should include email, phone, ssn
        assert_eq!(patterns.len(), 3);
    }

    #[test]
    fn test_build_patterns_specific() {
        let patterns = build_patterns(&["email".to_string(), "ip_address".to_string()]);
        assert_eq!(patterns.len(), 2);
    }
}
