//! PyO3 Python bindings for akash-deploy-rs proto types.
//!
//! Exposes protobuf encode/decode functions that bridge between Python dicts
//! (via JSON) and the Rust prost message types.
//!
//! Enabled with `--features python`. Build with `just py-build`.

#![allow(clippy::all)]

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

mod registry {
    include!("py_gen.rs");
}

/// Encode a proto message from a JSON string to protobuf binary.
#[pyfunction]
pub fn encode_message(type_url: &str, json_data: &[u8]) -> PyResult<Vec<u8>> {
    registry::encode(type_url, json_data)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Decode protobuf binary to JSON bytes.
#[pyfunction]
pub fn decode_message(type_url: &str, proto_data: &[u8]) -> PyResult<Vec<u8>> {
    registry::decode(type_url, proto_data)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Return all registered proto type URLs.
#[pyfunction]
pub fn registered_types() -> Vec<String> {
    registry::TYPE_URLS.iter().map(|s| s.to_string()).collect()
}

/// The akash_deploy native extension module.
#[pymodule]
pub fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encode_message, m)?)?;
    m.add_function(wrap_pyfunction!(decode_message, m)?)?;
    m.add_function(wrap_pyfunction!(registered_types, m)?)?;
    Ok(())
}
