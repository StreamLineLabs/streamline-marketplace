//! Schema Validator Transform
//!
//! Validates JSON messages against a JSON Schema definition. Messages that fail
//! validation are dropped, routed to a dead-letter topic, or tagged with an error.
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "schema": "{\"type\":\"object\",\"required\":[\"id\",\"name\"]}",
//!   "on_invalid": "drop"
//! }
//! ```
//!
//! ## Validation Rules
//!
//! Supports a subset of JSON Schema Draft 7:
//! - `type` validation (string, number, integer, boolean, object, array, null)
//! - `required` fields on objects
//! - `properties` with nested type validation
//! - `minLength` / `maxLength` for strings
//! - `minimum` / `maximum` for numbers
//! - `enum` value sets

use serde_json::Value;

/// Global validator configuration, set once during init.
static mut CONFIG: Option<ValidatorConfig> = None;

/// Validator configuration.
struct ValidatorConfig {
    /// Parsed JSON Schema.
    schema: Value,
    /// Action on invalid messages.
    on_invalid: OnInvalid,
}

/// Action to take when a message fails validation.
#[derive(Clone, Copy, Debug, PartialEq)]
enum OnInvalid {
    /// Drop the message (filter returns 0).
    Drop,
    /// Tag the message with a `_validation_error` field.
    Tag,
}

impl OnInvalid {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "tag" => OnInvalid::Tag,
            _ => OnInvalid::Drop,
        }
    }
}

/// Validate a JSON value against a schema. Returns a list of error messages.
fn validate(value: &Value, schema: &Value) -> Vec<String> {
    let mut errors = Vec::new();

    // Check "type" constraint
    if let Some(expected_type) = schema.get("type").and_then(|v| v.as_str()) {
        let actual_type = json_type_name(value);
        if expected_type == "integer" {
            // integer is a subset of number in JSON
            if !value.is_i64() && !value.is_u64() {
                errors.push(format!("expected type integer, got {}", actual_type));
            }
        } else if actual_type != expected_type {
            errors.push(format!("expected type {}, got {}", expected_type, actual_type));
        }
    }

    // Check "required" fields (only for objects)
    if let (Some(required), Some(obj)) = (
        schema.get("required").and_then(|v| v.as_array()),
        value.as_object(),
    ) {
        for req in required {
            if let Some(field_name) = req.as_str() {
                if !obj.contains_key(field_name) {
                    errors.push(format!("missing required field '{}'", field_name));
                }
            }
        }
    }

    // Check "properties" (nested validation)
    if let (Some(properties), Some(obj)) = (
        schema.get("properties").and_then(|v| v.as_object()),
        value.as_object(),
    ) {
        for (prop_name, prop_schema) in properties {
            if let Some(prop_value) = obj.get(prop_name) {
                let sub_errors = validate(prop_value, prop_schema);
                for err in sub_errors {
                    errors.push(format!("{}.{}", prop_name, err));
                }
            }
        }
    }

    // Check "enum" constraint
    if let Some(enum_values) = schema.get("enum").and_then(|v| v.as_array()) {
        if !enum_values.contains(value) {
            errors.push(format!("value not in enum: {:?}", value));
        }
    }

    // Check "minLength" / "maxLength" for strings
    if let Some(s) = value.as_str() {
        if let Some(min) = schema.get("minLength").and_then(|v| v.as_u64()) {
            if (s.len() as u64) < min {
                errors.push(format!("string length {} < minLength {}", s.len(), min));
            }
        }
        if let Some(max) = schema.get("maxLength").and_then(|v| v.as_u64()) {
            if (s.len() as u64) > max {
                errors.push(format!("string length {} > maxLength {}", s.len(), max));
            }
        }
    }

    // Check "minimum" / "maximum" for numbers
    if let Some(n) = value.as_f64() {
        if let Some(min) = schema.get("minimum").and_then(|v| v.as_f64()) {
            if n < min {
                errors.push(format!("value {} < minimum {}", n, min));
            }
        }
        if let Some(max) = schema.get("maximum").and_then(|v| v.as_f64()) {
            if n > max {
                errors.push(format!("value {} > maximum {}", n, max));
            }
        }
    }

    errors
}

/// Get the JSON Schema type name for a value.
fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Initialize the validator with configuration JSON.
///
/// Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn init(config_ptr: *const u8, config_len: u32) -> u32 {
    let config_bytes = unsafe { std::slice::from_raw_parts(config_ptr, config_len as usize) };

    let config: Value = match serde_json::from_slice(config_bytes) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    // Parse the embedded schema (may be a JSON string or an object)
    let schema = match config.get("schema") {
        Some(Value::String(s)) => match serde_json::from_str(s) {
            Ok(v) => v,
            Err(_) => return 0,
        },
        Some(v) if v.is_object() => v.clone(),
        _ => return 0,
    };

    let on_invalid = config
        .get("on_invalid")
        .and_then(|v| v.as_str())
        .map(OnInvalid::from_str)
        .unwrap_or(OnInvalid::Drop);

    unsafe {
        CONFIG = Some(ValidatorConfig { schema, on_invalid });
    }

    1
}

/// Filter function: returns 1 if the message passes validation, 0 if it should be dropped.
///
/// Only applies when `on_invalid` is `drop`. When `tag` mode is used, all messages
/// pass the filter and are annotated in the transform step.
#[no_mangle]
pub extern "C" fn filter(input_ptr: *const u8, input_len: u32) -> u32 {
    let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len as usize) };

    let config = unsafe {
        match CONFIG.as_ref() {
            Some(c) => c,
            None => return 1,
        }
    };

    // In tag mode, pass all messages through
    if config.on_invalid == OnInvalid::Tag {
        return 1;
    }

    let parsed: Value = match serde_json::from_slice(input) {
        Ok(v) => v,
        Err(_) => return 0, // unparseable = invalid
    };

    let errors = validate(&parsed, &config.schema);
    if errors.is_empty() { 1 } else { 0 }
}

/// Transform function: in tag mode, adds `_validation_error` to invalid messages.
/// In drop mode, passes through unchanged (filtering is done in filter()).
#[no_mangle]
pub extern "C" fn transform(input_ptr: *const u8, input_len: u32, output_ptr: *mut u8) -> u32 {
    let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len as usize) };

    let config = unsafe {
        match CONFIG.as_ref() {
            Some(c) => c,
            None => {
                std::ptr::copy_nonoverlapping(input.as_ptr(), output_ptr, input.len());
                return input_len;
            }
        }
    };

    // In drop mode, just pass through (invalid messages are already filtered)
    if config.on_invalid == OnInvalid::Drop {
        unsafe {
            std::ptr::copy_nonoverlapping(input.as_ptr(), output_ptr, input.len());
        }
        return input_len;
    }

    // In tag mode, validate and add error info
    let mut value: Value = match serde_json::from_slice(input) {
        Ok(v) => v,
        Err(_) => {
            unsafe {
                std::ptr::copy_nonoverlapping(input.as_ptr(), output_ptr, input.len());
            }
            return input_len;
        }
    };

    let errors = validate(&value, &config.schema);
    if !errors.is_empty() {
        if let Value::Object(ref mut map) = value {
            map.insert(
                "_validation_errors".to_string(),
                Value::Array(errors.into_iter().map(Value::String).collect()),
            );
        }
    }

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

    #[test]
    fn test_validate_type_object() {
        let schema: Value = serde_json::json!({"type": "object"});
        let valid: Value = serde_json::json!({"key": "value"});
        let invalid: Value = serde_json::json!("a string");

        assert!(validate(&valid, &schema).is_empty());
        assert!(!validate(&invalid, &schema).is_empty());
    }

    #[test]
    fn test_validate_required_fields() {
        let schema: Value = serde_json::json!({
            "type": "object",
            "required": ["id", "name"]
        });

        let valid: Value = serde_json::json!({"id": 1, "name": "test"});
        let missing_name: Value = serde_json::json!({"id": 1});
        let empty: Value = serde_json::json!({});

        assert!(validate(&valid, &schema).is_empty());
        assert_eq!(validate(&missing_name, &schema).len(), 1);
        assert_eq!(validate(&empty, &schema).len(), 2);
    }

    #[test]
    fn test_validate_nested_properties() {
        let schema: Value = serde_json::json!({
            "type": "object",
            "properties": {
                "age": {"type": "number", "minimum": 0, "maximum": 150}
            }
        });

        let valid: Value = serde_json::json!({"age": 30});
        let too_high: Value = serde_json::json!({"age": 200});

        assert!(validate(&valid, &schema).is_empty());
        assert!(!validate(&too_high, &schema).is_empty());
    }

    #[test]
    fn test_validate_enum() {
        let schema: Value = serde_json::json!({
            "type": "string",
            "enum": ["active", "inactive", "pending"]
        });

        let valid = Value::String("active".to_string());
        let invalid = Value::String("deleted".to_string());

        assert!(validate(&valid, &schema).is_empty());
        assert!(!validate(&invalid, &schema).is_empty());
    }

    #[test]
    fn test_validate_string_length() {
        let schema: Value = serde_json::json!({
            "type": "string",
            "minLength": 3,
            "maxLength": 10
        });

        let valid = Value::String("hello".to_string());
        let too_short = Value::String("hi".to_string());
        let too_long = Value::String("hello world!".to_string());

        assert!(validate(&valid, &schema).is_empty());
        assert!(!validate(&too_short, &schema).is_empty());
        assert!(!validate(&too_long, &schema).is_empty());
    }

    #[test]
    fn test_validate_number_range() {
        let schema: Value = serde_json::json!({
            "type": "number",
            "minimum": 0,
            "maximum": 100
        });

        let valid: Value = serde_json::json!(50);
        let too_low: Value = serde_json::json!(-1);
        let too_high: Value = serde_json::json!(101);

        assert!(validate(&valid, &schema).is_empty());
        assert!(!validate(&too_low, &schema).is_empty());
        assert!(!validate(&too_high, &schema).is_empty());
    }

    #[test]
    fn test_json_type_name() {
        assert_eq!(json_type_name(&Value::Null), "null");
        assert_eq!(json_type_name(&Value::Bool(true)), "boolean");
        assert_eq!(json_type_name(&serde_json::json!(42)), "number");
        assert_eq!(json_type_name(&Value::String("s".into())), "string");
        assert_eq!(json_type_name(&serde_json::json!([])), "array");
        assert_eq!(json_type_name(&serde_json::json!({})), "object");
    }

    #[test]
    fn test_on_invalid_from_str() {
        assert_eq!(OnInvalid::from_str("drop"), OnInvalid::Drop);
        assert_eq!(OnInvalid::from_str("tag"), OnInvalid::Tag);
        assert_eq!(OnInvalid::from_str("unknown"), OnInvalid::Drop);
    }
}
