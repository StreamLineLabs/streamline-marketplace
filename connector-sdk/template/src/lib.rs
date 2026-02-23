//! {{project-name}} — Streamline Sink Connector
//!
//! This is a template for building a custom sink connector.
//! Replace the TODO sections with your implementation.

use serde::Deserialize;
use std::cell::RefCell;

#[derive(Deserialize)]
struct Config {
    // TODO: Add your connector configuration fields
    endpoint: String,
    #[serde(default = "default_batch_size")]
    batch_size: usize,
}

fn default_batch_size() -> usize { 100 }

thread_local! {
    static CONFIG: RefCell<Option<Config>> = const { RefCell::new(None) };
}

/// Initialize the connector with configuration.
/// Called once when the connector is created.
#[no_mangle]
pub extern "C" fn init(config_ptr: *const u8, config_len: u32) -> i32 {
    let config_bytes = unsafe { std::slice::from_raw_parts(config_ptr, config_len as usize) };
    match serde_json::from_slice::<Config>(config_bytes) {
        Ok(config) => {
            CONFIG.with(|c| *c.borrow_mut() = Some(config));
            0 // success
        }
        Err(_) => -1 // invalid config
    }
}

/// Write a batch of records to the sink.
/// Called for each batch of records from the source topic.
///
/// Record format (JSON array):
/// ```json
/// [{"key": "k1", "value": "v1", "offset": 0, "timestamp": 1234567890}]
/// ```
#[no_mangle]
pub extern "C" fn write(records_ptr: *const u8, records_len: u32) -> i32 {
    let data = unsafe { std::slice::from_raw_parts(records_ptr, records_len as usize) };

    let records: Vec<serde_json::Value> = match serde_json::from_slice(data) {
        Ok(r) => r,
        Err(_) => return -1,
    };

    CONFIG.with(|c| {
        let config = c.borrow();
        let config = match config.as_ref() {
            Some(c) => c,
            None => return -2, // not initialized
        };

        // TODO: Implement your sink logic here
        // Example: send records to an HTTP endpoint
        for _record in &records {
            // http_post(&config.endpoint, record);
        }

        records.len() as i32 // return number of records written
    })
}

/// Flush any buffered records.
#[no_mangle]
pub extern "C" fn flush() -> i32 {
    // TODO: Flush any internal buffers
    0
}

/// Shutdown the connector and release resources.
#[no_mangle]
pub extern "C" fn shutdown() -> i32 {
    CONFIG.with(|c| *c.borrow_mut() = None);
    0
}

/// Free memory allocated by the WASM module.
#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, len: u32) {
    unsafe { let _ = Vec::from_raw_parts(ptr, len as usize, len as usize); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_valid_config() {
        let config = br#"{"endpoint": "http://localhost:8080", "batch_size": 50}"#;
        let result = init(config.as_ptr(), config.len() as u32);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_init_invalid_config() {
        let result = init(b"not json".as_ptr(), 8);
        assert_eq!(result, -1);
    }

    #[test]
    fn test_write_records() {
        let config = br#"{"endpoint": "http://localhost:8080"}"#;
        init(config.as_ptr(), config.len() as u32);

        let records = br#"[{"key":"k1","value":"v1","offset":0,"timestamp":1234567890}]"#;
        let result = write(records.as_ptr(), records.len() as u32);
        assert_eq!(result, 1); // 1 record written
    }

    #[test]
    fn test_shutdown() {
        assert_eq!(shutdown(), 0);
    }
}
