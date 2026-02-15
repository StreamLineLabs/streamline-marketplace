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
        match current.get(part) {
            Some(v) => current = v,
            None => return None,
        }
    }
    Some(current)
}

/// Evaluate whether a field value matches the filter condition.
fn evaluate(field_value: Option<&Value>, operator: &Operator, compare_value: &Option<String>) -> bool {
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
                    _ => field_val.to_string() == *cmp,
                },
                Operator::Neq => match field_val {
                    Value::String(s) => s != cmp,
                    Value::Number(n) => n.to_string() != *cmp,
                    Value::Bool(b) => b.to_string() != *cmp,
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
#[no_mangle]
pub extern "C" fn init(config_ptr: *const u8, config_len: u32) -> u32 {
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
        CONFIG = Some(FilterConfig {
            field,
            operator,
            value,
        });
    }

    1
}

/// Filter function: returns 1 if the message should be kept, 0 if it should be dropped.
#[no_mangle]
pub extern "C" fn filter(input_ptr: *const u8, input_len: u32) -> u32 {
    let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len as usize) };

    let config = unsafe {
        match CONFIG.as_ref() {
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

    if matches { 1 } else { 0 }
}

/// Transform function: pass through the message unchanged (filtering is done by filter()).
#[no_mangle]
pub extern "C" fn transform(input_ptr: *const u8, input_len: u32, output_ptr: *mut u8) -> u32 {
    let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len as usize) };
    unsafe {
        std::ptr::copy_nonoverlapping(input.as_ptr(), output_ptr, input.len());
    }
    input_len
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(evaluate(Some(&val), &Operator::Gte, &Some("42".to_string())));
        assert!(evaluate(Some(&val), &Operator::Lte, &Some("42".to_string())));
        assert!(!evaluate(Some(&val), &Operator::Gt, &Some("42".to_string())));
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
