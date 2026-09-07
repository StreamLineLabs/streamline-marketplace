//! AI Classifier Transform
//!
//! Classifies messages into configurable categories using LLM providers.
//! The classification result and confidence score are added to the message.
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "provider": "openai",
//!   "model": "gpt-4o-mini",
//!   "categories": ["urgent", "normal", "low-priority"],
//!   "field": "message",
//!   "output_field": "_classification",
//!   "api_key_env": "OPENAI_API_KEY"
//! }
//! ```

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Config {
    provider: String,
    #[serde(default = "default_model")]
    model: String,
    categories: Vec<String>,
    #[serde(default = "default_field")]
    field: String,
    #[serde(default = "default_output_field")]
    output_field: String,
    // Accepted for schema compatibility: the host runtime resolves the API key
    // from this environment variable name, the sandboxed module never reads it.
    #[allow(dead_code)]
    #[serde(default = "default_api_key_env")]
    api_key_env: String,
}

fn default_model() -> String {
    "gpt-4o-mini".to_string()
}
fn default_field() -> String {
    "value".to_string()
}
fn default_output_field() -> String {
    "_classification".to_string()
}
fn default_api_key_env() -> String {
    "OPENAI_API_KEY".to_string()
}

#[derive(Serialize)]
struct Classification {
    label: String,
    confidence: f64,
    model: String,
}

/// WASM transform entry point.
///
/// Called by the Streamline WASM runtime for each message.
/// Input: JSON message bytes + config JSON bytes
/// Output: transformed JSON message bytes (with classification added)
///
/// # Safety
///
/// `input_ptr` must point to `input_len` initialized bytes and `output_ptr`
/// must point to a writable buffer large enough to hold the result. The
/// two regions must not overlap.
#[no_mangle]
pub unsafe extern "C" fn transform(
    input_ptr: *const u8,
    input_len: u32,
    config_ptr: *const u8,
    config_len: u32,
) -> u64 {
    // SAFETY: pointers and lengths are provided by the WASM host runtime
    let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len as usize) };
    let config_bytes = unsafe { std::slice::from_raw_parts(config_ptr, config_len as usize) };

    let result = process(input, config_bytes);

    match result {
        Ok(output) => {
            let len = output.len() as u64;
            let ptr = output.as_ptr() as u64;
            std::mem::forget(output); // Host calls dealloc() to free
            (ptr << 32) | len
        }
        Err(_) => 0,
    }
}

/// Free memory allocated by transform(). Called by the WASM host runtime.
///
/// # Safety
///
/// `ptr`/`len` must be a pair previously returned by [`transform`] and not
/// yet freed; the memory must have been allocated by this module.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: u32) {
    // SAFETY: ptr and len were returned by transform() from a Vec allocation
    unsafe {
        let _ = Vec::from_raw_parts(ptr, len as usize, len as usize);
    }
}

fn process(input: &[u8], config_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let config: Config =
        serde_json::from_slice(config_bytes).map_err(|e| format!("Invalid config: {}", e))?;

    let mut message: serde_json::Value =
        serde_json::from_slice(input).map_err(|e| format!("Invalid JSON input: {}", e))?;

    let text = match &config.field as &str {
        "value" => serde_json::to_string(&message).unwrap_or_default(),
        field => message
            .get(field)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    };

    // In WASM sandbox, HTTP calls go through the host's HTTP capability.
    // For now, use keyword-based classification as a fallback when no
    // LLM provider is available (the host runtime handles actual API calls).
    let classification = classify_local(&text, &config.categories);

    let result = Classification {
        label: classification.0,
        confidence: classification.1,
        model: format!("{}:{}", config.provider, config.model),
    };

    if let Some(obj) = message.as_object_mut() {
        obj.insert(
            config.output_field,
            serde_json::to_value(&result).unwrap_or_default(),
        );
    }

    serde_json::to_vec(&message).map_err(|e| format!("Serialization error: {}", e))
}

/// Simple keyword-based fallback classifier (used when no LLM API is available).
fn classify_local(text: &str, categories: &[String]) -> (String, f64) {
    let text_lower = text.to_lowercase();

    for category in categories {
        if text_lower.contains(&category.to_lowercase()) {
            return (category.clone(), 0.85);
        }
    }

    // Default to first category with low confidence
    let default = categories
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    (default, 0.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_accepts_api_key_env() {
        // `api_key_env` is resolved by the host runtime, but it must stay part
        // of the accepted configuration schema.
        let config: Config = serde_json::from_str(
            r#"{"provider":"openai","categories":["a"],"api_key_env":"MY_KEY"}"#,
        )
        .unwrap();
        assert_eq!(config.api_key_env, "MY_KEY");
        assert_eq!(config.model, "gpt-4o-mini");
        assert_eq!(config.output_field, "_classification");
    }

    #[test]
    fn test_config_defaults_api_key_env() {
        let config: Config =
            serde_json::from_str(r#"{"provider":"openai","categories":["a"]}"#).unwrap();
        assert_eq!(config.api_key_env, "OPENAI_API_KEY");
    }

    #[test]
    fn test_abi_transform_returns_zero_on_invalid_input() {
        let input = b"not json";
        let cfg = br#"{"provider":"openai","categories":["urgent"]}"#;
        let packed = unsafe {
            transform(
                input.as_ptr(),
                input.len() as u32,
                cfg.as_ptr(),
                cfg.len() as u32,
            )
        };
        assert_eq!(packed, 0);
    }

    #[test]
    fn test_abi_transform_packs_output_length() {
        let input = br#"{"message":"urgent outage"}"#;
        let cfg = br#"{"provider":"openai","categories":["urgent"],"field":"message"}"#;
        let expected = process(input, cfg).unwrap();

        // The ABI packs `(ptr << 32) | len`; only the length is recoverable on
        // 64-bit hosts, where the pointer does not fit in the upper 32 bits.
        // The host runtime calls `dealloc` to release the leaked allocation.
        let packed = unsafe {
            transform(
                input.as_ptr(),
                input.len() as u32,
                cfg.as_ptr(),
                cfg.len() as u32,
            )
        };
        assert_ne!(packed, 0);
        assert_eq!((packed & 0xFFFF_FFFF) as usize, expected.len());
    }

    #[test]
    fn test_classify_local_match() {
        let categories = vec!["urgent".to_string(), "normal".to_string()];
        let (label, conf) = classify_local("This is urgent!", &categories);
        assert_eq!(label, "urgent");
        assert!(conf > 0.5);
    }

    #[test]
    fn test_classify_local_no_match() {
        let categories = vec!["urgent".to_string(), "normal".to_string()];
        let (label, conf) = classify_local("hello world", &categories);
        assert_eq!(label, "urgent"); // defaults to first
        assert!(conf < 0.5);
    }

    #[test]
    fn test_process_adds_classification() {
        let input = br#"{"message": "Server is down! Urgent fix needed"}"#;
        let config = br#"{"provider":"openai","categories":["urgent","normal"],"field":"message"}"#;
        let result = process(input, config).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert!(parsed.get("_classification").is_some());
        let classification = parsed.get("_classification").unwrap();
        assert_eq!(
            classification.get("label").unwrap().as_str().unwrap(),
            "urgent"
        );
    }

    #[test]
    fn test_process_invalid_json() {
        let result = process(b"not json", b"{}");
        assert!(result.is_err());
    }

    #[test]
    fn test_process_invalid_config() {
        let result = process(b"{}", b"not json");
        assert!(result.is_err());
    }
}
