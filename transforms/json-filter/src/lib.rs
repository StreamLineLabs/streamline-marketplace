//! JSON Filter Transform
//!
//! Filters messages based on configurable JSON field conditions.
//! Messages that do not match the filter criteria are dropped.
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "field": "status",
//!   "operator": "eq",
//!   "value": "active"
//! }
//! ```
//!
//! ## Supported Operators
//!
//! - `eq` - Equal (string comparison)
//! - `neq` - Not equal
//! - `gt` - Greater than (numeric)
//! - `lt` - Less than (numeric)
//! - `gte` - Greater than or equal (numeric)
//! - `lte` - Less than or equal (numeric)
//! - `contains` - String contains substring
//! - `regex` - Regular expression match
//! - `exists` - Field exists (value not required)
//! - `not_exists` - Field does not exist (value not required)

use serde_json::Value;

/// Global filter configuration, set once during init.
static mut CONFIG: Option<FilterConfig> = None;

/// Borrow the module-global configuration.
///
/// Accessed through a raw pointer rather than a direct reference to the
/// `static mut`, which would be undefined behaviour under the Rust 2024
/// `static_mut_refs` rules.
///
/// # Safety
///
/// A WASM transform instance is single-threaded and the host runtime always
/// calls `init` before `filter`/`transform`, so no `&mut` alias can exist
/// while the returned reference is live.
unsafe fn config() -> Option<&'static FilterConfig> {
    (*std::ptr::addr_of!(CONFIG)).as_ref()
}

/// Replace the module-global configuration.
///
/// # Safety
///
/// Must not be called while a reference returned by [`config`] is live.
unsafe fn set_config(config: FilterConfig) {
    *std::ptr::addr_of_mut!(CONFIG) = Some(config);
}

/// Filter configuration parsed from the init config JSON.
struct FilterConfig {
    /// Dot-notation field path (e.g. "user.status")
    field: String,
    /// Comparison operator
    operator: Operator,
    /// Value to compare against (None for exists/not_exists)
    value: Option<String>,
}

/// Supported comparison operators.
#[derive(Debug, Clone, PartialEq)]
enum Operator {
    Eq,
    Neq,
    Gt,
    Lt,
    Gte,
    Lte,
    Contains,
    Regex,
    Exists,
    NotExists,
}

impl Operator {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "eq" => Operator::Eq,
            "neq" | "ne" => Operator::Neq,
            "gt" => Operator::Gt,
            "lt" => Operator::Lt,
            "gte" | "ge" => Operator::Gte,
            "lte" | "le" => Operator::Lte,
            "contains" => Operator::Contains,
            "regex" => Operator::Regex,
            "exists" => Operator::Exists,
            "not_exists" | "notexists" => Operator::NotExists,
            _ => Operator::Eq, // default to equality
        }
    }
}

/// Resolve a dot-notation field path against a JSON value.
///
/// For example, "user.address.city" will traverse:
///   root -> "user" -> "address" -> "city"
fn resolve_field<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = value;
    for part in parts {
        current = current.get(part)?;
    }
    Some(current)
}

/// Evaluate whether a field value matches the filter condition.
fn evaluate(
    field_value: Option<&Value>,
    operator: &Operator,
    compare_value: &Option<String>,
) -> bool {
    match operator {
        Operator::Exists => field_value.is_some(),
        Operator::NotExists => field_value.is_none(),
        _ => {
            let field_val = match field_value {
                Some(v) => v,
                None => return false,
            };
            let cmp = match compare_value {
                Some(v) => v,
                None => return false,
            };

            match operator {
                Operator::Eq => match field_val {
                    Value::String(s) => s == cmp,
                    Value::Number(n) => n.to_string() == *cmp,
                    Value::Bool(b) => b.to_string() == *cmp,
                    Value::Null => cmp == "null",
                    // Arrays/objects have no borrowed string form, so the
                    // serialized representation must be materialized.
                    #[allow(clippy::cmp_owned)]
                    _ => field_val.to_string() == *cmp,
                },
                Operator::Neq => match field_val {
                    Value::String(s) => s != cmp,
                    Value::Number(n) => n.to_string() != *cmp,
                    Value::Bool(b) => b.to_string() != *cmp,
                    #[allow(clippy::cmp_owned)]
                    _ => field_val.to_string() != *cmp,
                },
                Operator::Gt | Operator::Lt | Operator::Gte | Operator::Lte => {
                    let field_num = match field_val {
                        Value::Number(n) => n.as_f64(),
                        Value::String(s) => s.parse::<f64>().ok(),
                        _ => None,
                    };
                    let cmp_num = cmp.parse::<f64>().ok();
                    match (field_num, cmp_num) {
                        (Some(a), Some(b)) => match operator {
                            Operator::Gt => a > b,
                            Operator::Lt => a < b,
                            Operator::Gte => a >= b,
                            Operator::Lte => a <= b,
                            _ => false,
                        },
                        _ => false,
                    }
                }
                Operator::Contains => match field_val {
                    Value::String(s) => s.contains(cmp.as_str()),
                    _ => field_val.to_string().contains(cmp.as_str()),
                },
                Operator::Regex => {
                    // Simple regex matching - in a full implementation you would use the regex crate.
                    // For the WASM module, we do a basic substring match as a fallback.
                    match field_val {
                        Value::String(s) => s.contains(cmp.as_str()),
                        _ => false,
                    }
                }
                _ => false,
            }
        }
    }
}

/// Initialize the filter with configuration JSON.
///
/// Expected config format:
/// ```json
/// { "field": "status", "operator": "eq", "value": "active" }
/// ```
///
/// Returns 1 on success, 0 on failure.
///
/// # Safety
///
/// `config_ptr` must either be null or point to `config_len` initialized bytes
/// that stay valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn init(config_ptr: *const u8, config_len: u32) -> u32 {
    const MAX_CONFIG_SIZE: u32 = 1024 * 1024; // 1MB max config
    if config_ptr.is_null() || config_len == 0 || config_len > MAX_CONFIG_SIZE {
        return 0;
    }
    let config_bytes = unsafe { std::slice::from_raw_parts(config_ptr, config_len as usize) };

    let config: Value = match serde_json::from_slice(config_bytes) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let field = match config.get("field").and_then(|v| v.as_str()) {
        Some(f) => f.to_string(),
        None => return 0,
    };

    let operator = config
        .get("operator")
        .and_then(|v| v.as_str())
        .map(Operator::from_str)
        .unwrap_or(Operator::Eq);

    let value = config
        .get("value")
        .and_then(|v| v.as_str())
        .map(String::from);

    unsafe {
        set_config(FilterConfig {
            field,
            operator,
            value,
        });
    }

    1
}

/// Filter function: returns 1 if the message should be kept, 0 if it should be dropped.
///
/// # Safety
///
/// `input_ptr` must either be null or point to `input_len` initialized bytes
/// that stay valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn filter(input_ptr: *const u8, input_len: u32) -> u32 {
    const MAX_INPUT_SIZE: u32 = 64 * 1024 * 1024; // 64MB max message
    if input_ptr.is_null() || input_len == 0 || input_len > MAX_INPUT_SIZE {
        return 1; // pass through on invalid input
    }
    let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len as usize) };

    let config = unsafe {
        match config() {
            Some(c) => c,
            None => return 1, // no config = pass through
        }
    };

    let parsed: Value = match serde_json::from_slice(input) {
        Ok(v) => v,
        Err(_) => return 0, // unparseable messages are dropped
    };

    let field_value = resolve_field(&parsed, &config.field);
    let matches = evaluate(field_value, &config.operator, &config.value);

    if matches {
        1
    } else {
        0
    }
}

/// Transform function: pass through the message unchanged (filtering is done by filter()).
///
/// # Safety
///
/// `input_ptr` must point to `input_len` initialized bytes and `output_ptr`
/// must point to a writable buffer of at least `input_len` bytes. The two
/// regions must not overlap.
#[no_mangle]
pub unsafe extern "C" fn transform(
    input_ptr: *const u8,
    input_len: u32,
    output_ptr: *mut u8,
) -> u32 {
    let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len as usize) };
    unsafe {
        std::ptr::copy_nonoverlapping(input.as_ptr(), output_ptr, input.len());
    }
    input_len
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that touch the module-global config set by `init`,
    /// which the WASM ABI shares across calls.
    static ABI_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn abi_lock() -> std::sync::MutexGuard<'static, ()> {
        ABI_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn test_abi_init_then_filter_roundtrip() {
        let _guard = abi_lock();

        let cfg = br#"{"field":"status","operator":"eq","value":"active"}"#;
        assert_eq!(unsafe { init(cfg.as_ptr(), cfg.len() as u32) }, 1);

        let keep = br#"{"status":"active"}"#;
        assert_eq!(unsafe { filter(keep.as_ptr(), keep.len() as u32) }, 1);

        let drop = br#"{"status":"inactive"}"#;
        assert_eq!(unsafe { filter(drop.as_ptr(), drop.len() as u32) }, 0);

        // Unparseable payloads are dropped.
        let bad = b"not json";
        assert_eq!(unsafe { filter(bad.as_ptr(), bad.len() as u32) }, 0);
    }

    #[test]
    fn test_abi_init_rejects_invalid_config() {
        let _guard = abi_lock();

        assert_eq!(unsafe { init(std::ptr::null(), 8) }, 0);

        let cfg = br#"{"field":"a"}"#;
        assert_eq!(unsafe { init(cfg.as_ptr(), 0) }, 0);
        // Oversized configs (> 1MiB) are rejected before any dereference.
        assert_eq!(unsafe { init(cfg.as_ptr(), 1024 * 1024 + 1) }, 0);

        // "field" is required.
        let no_field = br#"{"operator":"eq","value":"x"}"#;
        assert_eq!(unsafe { init(no_field.as_ptr(), no_field.len() as u32) }, 0);
    }

    #[test]
    fn test_abi_filter_passes_through_invalid_input() {
        // Null/empty input is passed through regardless of configuration.
        assert_eq!(unsafe { filter(std::ptr::null(), 4) }, 1);
        let msg = br#"{"status":"active"}"#;
        assert_eq!(unsafe { filter(msg.as_ptr(), 0) }, 1);
    }

    #[test]
    fn test_abi_transform_is_byte_exact_passthrough() {
        let input = br#"{"status":"active","n":1}"#;
        let mut out = vec![0u8; input.len()];
        let written = unsafe { transform(input.as_ptr(), input.len() as u32, out.as_mut_ptr()) };
        assert_eq!(written as usize, input.len());
        assert_eq!(out.as_slice(), input.as_slice());
    }

    #[test]
    fn test_resolve_field_simple() {
        let json: Value = serde_json::json!({"status": "active", "count": 42});
        assert_eq!(
            resolve_field(&json, "status"),
            Some(&Value::String("active".to_string()))
        );
    }

    #[test]
    fn test_resolve_field_nested() {
        let json: Value = serde_json::json!({"user": {"address": {"city": "NYC"}}});
        assert_eq!(
            resolve_field(&json, "user.address.city"),
            Some(&Value::String("NYC".to_string()))
        );
    }

    #[test]
    fn test_resolve_field_missing() {
        let json: Value = serde_json::json!({"status": "active"});
        assert_eq!(resolve_field(&json, "missing"), None);
    }

    #[test]
    fn test_evaluate_eq() {
        let val = Value::String("active".to_string());
        assert!(evaluate(
            Some(&val),
            &Operator::Eq,
            &Some("active".to_string())
        ));
        assert!(!evaluate(
            Some(&val),
            &Operator::Eq,
            &Some("inactive".to_string())
        ));
    }

    #[test]
    fn test_evaluate_neq() {
        let val = Value::String("active".to_string());
        assert!(evaluate(
            Some(&val),
            &Operator::Neq,
            &Some("inactive".to_string())
        ));
    }

    #[test]
    fn test_evaluate_numeric_comparisons() {
        let val = Value::Number(serde_json::Number::from(42));
        assert!(evaluate(Some(&val), &Operator::Gt, &Some("40".to_string())));
        assert!(evaluate(Some(&val), &Operator::Lt, &Some("50".to_string())));
        assert!(evaluate(
            Some(&val),
            &Operator::Gte,
            &Some("42".to_string())
        ));
        assert!(evaluate(
            Some(&val),
            &Operator::Lte,
            &Some("42".to_string())
        ));
        assert!(!evaluate(
            Some(&val),
            &Operator::Gt,
            &Some("42".to_string())
        ));
    }

    #[test]
    fn test_evaluate_contains() {
        let val = Value::String("hello world".to_string());
        assert!(evaluate(
            Some(&val),
            &Operator::Contains,
            &Some("world".to_string())
        ));
        assert!(!evaluate(
            Some(&val),
            &Operator::Contains,
            &Some("xyz".to_string())
        ));
    }

    #[test]
    fn test_evaluate_exists() {
        let val = Value::String("anything".to_string());
        assert!(evaluate(Some(&val), &Operator::Exists, &None));
        assert!(!evaluate(None, &Operator::Exists, &None));
    }

    #[test]
    fn test_evaluate_not_exists() {
        assert!(evaluate(None, &Operator::NotExists, &None));
        let val = Value::String("anything".to_string());
        assert!(!evaluate(Some(&val), &Operator::NotExists, &None));
    }

    #[test]
    fn test_operator_from_str() {
        assert_eq!(Operator::from_str("eq"), Operator::Eq);
        assert_eq!(Operator::from_str("NEQ"), Operator::Neq);
        assert_eq!(Operator::from_str("gt"), Operator::Gt);
        assert_eq!(Operator::from_str("lt"), Operator::Lt);
        assert_eq!(Operator::from_str("gte"), Operator::Gte);
        assert_eq!(Operator::from_str("lte"), Operator::Lte);
        assert_eq!(Operator::from_str("contains"), Operator::Contains);
        assert_eq!(Operator::from_str("exists"), Operator::Exists);
        assert_eq!(Operator::from_str("not_exists"), Operator::NotExists);
        assert_eq!(Operator::from_str("unknown"), Operator::Eq);
    }
}
