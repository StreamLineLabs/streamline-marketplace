//! Field Router Transform
//!
//! Routes messages to different output topics based on the value of a configurable
//! JSON field. The routing decision is encoded in a `_route_topic` metadata field
//! that the Streamline server reads to determine the destination topic.
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "field": "level",
//!   "routes": [
//!     {"match": "error", "topic": "errors"},
//!     {"match": "warn", "topic": "warnings"}
//!   ],
//!   "default_topic": "other"
//! }
//! ```
//!
//! Messages whose field value matches a route's `match` string are annotated with
//! `_route_topic` set to that route's `topic`. If no route matches and `default_topic`
//! is set, it is used; otherwise the message is dropped.

use serde_json::Value;

/// Global router configuration, set once during init.
static mut CONFIG: Option<RouterConfig> = None;

/// Router configuration.
struct RouterConfig {
    /// Dot-notation field path to evaluate.
    field: String,
    /// Routing rules.
    routes: Vec<Route>,
    /// Default topic for unmatched messages (None = drop).
    default_topic: Option<String>,
}

/// A single routing rule.
struct Route {
    /// Value to match against (exact string match).
    match_value: String,
    /// Destination topic name.
    topic: String,
}

/// Resolve a dot-notation field path against a JSON value.
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

/// Get the string representation of a JSON value for matching.
fn value_as_match_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        _ => value.to_string(),
    }
}

/// Find the matching route topic for a given field value.
fn find_route(config: &RouterConfig, field_value: Option<&Value>) -> Option<String> {
    let field_str = field_value.map(value_as_match_string);

    if let Some(ref val) = field_str {
        for route in &config.routes {
            if route.match_value == *val {
                return Some(route.topic.clone());
            }
        }
    }

    config.default_topic.clone()
}

/// Initialize the router with configuration JSON.
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

    let routes = config
        .get("routes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    let match_value = r.get("match").and_then(|v| v.as_str())?.to_string();
                    let topic = r.get("topic").and_then(|v| v.as_str())?.to_string();
                    Some(Route { match_value, topic })
                })
                .collect()
        })
        .unwrap_or_default();

    let default_topic = config
        .get("default_topic")
        .and_then(|v| v.as_str())
        .map(String::from);

    unsafe {
        CONFIG = Some(RouterConfig {
            field,
            routes,
            default_topic,
        });
    }

    1
}

/// Filter function: drops messages that match no route and have no default_topic.
#[no_mangle]
pub extern "C" fn filter(input_ptr: *const u8, input_len: u32) -> u32 {
    let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len as usize) };

    let config = unsafe {
        match CONFIG.as_ref() {
            Some(c) => c,
            None => return 1,
        }
    };

    let parsed: Value = match serde_json::from_slice(input) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let field_value = resolve_field(&parsed, &config.field);
    let route = find_route(config, field_value);

    if route.is_some() { 1 } else { 0 }
}

/// Transform function: annotates the message with `_route_topic`.
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

    let mut value: Value = match serde_json::from_slice(input) {
        Ok(v) => v,
        Err(_) => {
            unsafe {
                std::ptr::copy_nonoverlapping(input.as_ptr(), output_ptr, input.len());
            }
            return input_len;
        }
    };

    let field_value = resolve_field(&value, &config.field).cloned();
    if let Some(topic) = find_route(config, field_value.as_ref()) {
        if let Value::Object(ref mut map) = value {
            map.insert("_route_topic".to_string(), Value::String(topic));
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

    fn test_config() -> RouterConfig {
        RouterConfig {
            field: "level".to_string(),
            routes: vec![
                Route {
                    match_value: "error".to_string(),
                    topic: "errors".to_string(),
                },
                Route {
                    match_value: "warn".to_string(),
                    topic: "warnings".to_string(),
                },
                Route {
                    match_value: "info".to_string(),
                    topic: "info-logs".to_string(),
                },
            ],
            default_topic: Some("other".to_string()),
        }
    }

    #[test]
    fn test_resolve_field_simple() {
        let json: Value = serde_json::json!({"level": "error"});
        assert_eq!(
            resolve_field(&json, "level"),
            Some(&Value::String("error".to_string()))
        );
    }

    #[test]
    fn test_resolve_field_nested() {
        let json: Value = serde_json::json!({"log": {"level": "warn"}});
        assert_eq!(
            resolve_field(&json, "log.level"),
            Some(&Value::String("warn".to_string()))
        );
    }

    #[test]
    fn test_resolve_field_missing() {
        let json: Value = serde_json::json!({"status": "ok"});
        assert_eq!(resolve_field(&json, "level"), None);
    }

    #[test]
    fn test_find_route_exact_match() {
        let config = test_config();
        let val = Value::String("error".to_string());
        assert_eq!(find_route(&config, Some(&val)), Some("errors".to_string()));
    }

    #[test]
    fn test_find_route_default() {
        let config = test_config();
        let val = Value::String("debug".to_string());
        assert_eq!(find_route(&config, Some(&val)), Some("other".to_string()));
    }

    #[test]
    fn test_find_route_no_default() {
        let config = RouterConfig {
            field: "level".to_string(),
            routes: vec![Route {
                match_value: "error".to_string(),
                topic: "errors".to_string(),
            }],
            default_topic: None,
        };
        let val = Value::String("debug".to_string());
        assert_eq!(find_route(&config, Some(&val)), None);
    }

    #[test]
    fn test_find_route_missing_field() {
        let config = test_config();
        assert_eq!(find_route(&config, None), Some("other".to_string()));
    }

    #[test]
    fn test_find_route_numeric_match() {
        let config = RouterConfig {
            field: "status".to_string(),
            routes: vec![
                Route {
                    match_value: "200".to_string(),
                    topic: "success".to_string(),
                },
                Route {
                    match_value: "500".to_string(),
                    topic: "errors".to_string(),
                },
            ],
            default_topic: None,
        };
        let val = serde_json::json!(200);
        assert_eq!(find_route(&config, Some(&val)), Some("success".to_string()));
    }

    #[test]
    fn test_value_as_match_string() {
        assert_eq!(
            value_as_match_string(&Value::String("hello".into())),
            "hello"
        );
        assert_eq!(value_as_match_string(&serde_json::json!(42)), "42");
        assert_eq!(value_as_match_string(&Value::Bool(true)), "true");
        assert_eq!(value_as_match_string(&Value::Null), "null");
    }
}
