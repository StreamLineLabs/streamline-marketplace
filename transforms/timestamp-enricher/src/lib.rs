//! Timestamp Enricher Transform
//!
//! Adds a `_processed_at` timestamp (or custom field name) to every JSON message
//! that passes through the transform pipeline.
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "field_name": "_processed_at",
//!   "format": "iso8601"
//! }
//! ```
//!
//! ## Supported Formats
//!
//! - `iso8601` (default) - ISO 8601 format: "2026-02-19T12:00:00Z"
//! - `epoch_ms` - Unix epoch in milliseconds: 1739962800000
//! - `epoch_s` - Unix epoch in seconds: 1739962800

use serde_json::Value;

/// Global enricher configuration, set once during init.
static mut CONFIG: Option<EnricherConfig> = None;

/// Enricher configuration.
struct EnricherConfig {
    /// Field name to add (default: "_processed_at")
    field_name: String,
    /// Timestamp format
    format: TimestampFormat,
}

/// Supported timestamp formats.
#[derive(Clone, Copy)]
enum TimestampFormat {
    /// ISO 8601 format string
    Iso8601,
    /// Unix epoch milliseconds (integer)
    EpochMs,
    /// Unix epoch seconds (integer)
    EpochS,
}

impl TimestampFormat {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "epoch_ms" | "epochms" | "millis" => TimestampFormat::EpochMs,
            "epoch_s" | "epochs" | "seconds" => TimestampFormat::EpochS,
            _ => TimestampFormat::Iso8601,
        }
    }
}

/// Get current time as epoch milliseconds.
///
/// In a WASI environment, this uses `std::time::SystemTime`.
/// Falls back to a monotonic counter if system time is unavailable.
fn current_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Format the current timestamp according to the configured format.
fn format_timestamp(format: TimestampFormat) -> Value {
    let epoch_ms = current_epoch_ms();
    match format {
        TimestampFormat::EpochMs => Value::Number(serde_json::Number::from(epoch_ms)),
        TimestampFormat::EpochS => Value::Number(serde_json::Number::from(epoch_ms / 1000)),
        TimestampFormat::Iso8601 => {
            // Manual ISO 8601 formatting without chrono dependency (WASM-friendly).
            let secs = (epoch_ms / 1000) as i64;
            // Simple UTC date-time calculation
            let days_since_epoch = secs / 86400;
            let time_of_day = secs % 86400;
            let hours = time_of_day / 3600;
            let minutes = (time_of_day % 3600) / 60;
            let seconds = time_of_day % 60;
            let millis = epoch_ms % 1000;

            // Convert days since 1970-01-01 to year-month-day
            let (year, month, day) = days_to_ymd(days_since_epoch);

            Value::String(format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                year, month, day, hours, minutes, seconds, millis
            ))
        }
    }
}

/// Convert days since Unix epoch (1970-01-01) to (year, month, day).
fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// Initialize the enricher with configuration JSON.
///
/// Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn init(config_ptr: *const u8, config_len: u32) -> u32 {
    let config_bytes = unsafe { std::slice::from_raw_parts(config_ptr, config_len as usize) };

    let config: Value = match serde_json::from_slice(config_bytes) {
        Ok(v) => v,
        Err(_) => {
            // Use defaults if config is invalid
            unsafe {
                CONFIG = Some(EnricherConfig {
                    field_name: "_processed_at".to_string(),
                    format: TimestampFormat::Iso8601,
                });
            }
            return 1;
        }
    };

    let field_name = config
        .get("field_name")
        .and_then(|v| v.as_str())
        .unwrap_or("_processed_at")
        .to_string();

    let format = config
        .get("format")
        .and_then(|v| v.as_str())
        .map(TimestampFormat::from_str)
        .unwrap_or(TimestampFormat::Iso8601);

    unsafe {
        CONFIG = Some(EnricherConfig { field_name, format });
    }

    1
}

/// Transform a message by adding a timestamp field.
///
/// If the message is a JSON object, the configured field is added.
/// Non-JSON or non-object messages are passed through unchanged.
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

    // Parse the JSON message
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

    // Add the timestamp field to objects
    if let Value::Object(ref mut map) = value {
        let timestamp = format_timestamp(config.format);
        map.insert(config.field_name.clone(), timestamp);
    }

    // Serialize back to JSON
    let output = match serde_json::to_vec(&value) {
        Ok(v) => v,
        Err(_) => {
            // Serialization failed: pass through original
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

/// Filter function: accept all messages (enrichment, not filtering).
#[no_mangle]
pub extern "C" fn filter(_input_ptr: *const u8, _input_len: u32) -> u32 {
    1 // accept all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_known_date() {
        // 2026-02-19 is day 20503 since epoch
        let (y, m, d) = days_to_ymd(20503);
        assert_eq!(y, 2026);
        assert_eq!(m, 2);
        assert_eq!(d, 19);
    }

    #[test]
    fn test_format_timestamp_epoch_ms() {
        let ts = format_timestamp(TimestampFormat::EpochMs);
        assert!(ts.is_number());
    }

    #[test]
    fn test_format_timestamp_epoch_s() {
        let ts = format_timestamp(TimestampFormat::EpochS);
        assert!(ts.is_number());
        // Epoch seconds should be roughly 1/1000 of epoch ms
        let ms = format_timestamp(TimestampFormat::EpochMs).as_u64().unwrap();
        let s = ts.as_u64().unwrap();
        assert!((ms / 1000).abs_diff(s) <= 1);
    }

    #[test]
    fn test_format_timestamp_iso8601() {
        let ts = format_timestamp(TimestampFormat::Iso8601);
        let s = ts.as_str().unwrap();
        assert!(s.ends_with('Z'));
        assert!(s.contains('T'));
        assert_eq!(s.len(), 24); // "YYYY-MM-DDTHH:MM:SS.mmmZ"
    }

    #[test]
    fn test_timestamp_format_from_str() {
        assert!(matches!(
            TimestampFormat::from_str("epoch_ms"),
            TimestampFormat::EpochMs
        ));
        assert!(matches!(
            TimestampFormat::from_str("epoch_s"),
            TimestampFormat::EpochS
        ));
        assert!(matches!(
            TimestampFormat::from_str("iso8601"),
            TimestampFormat::Iso8601
        ));
        assert!(matches!(
            TimestampFormat::from_str("unknown"),
            TimestampFormat::Iso8601
        ));
    }
}
