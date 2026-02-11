//! Canonical JSON serialization for deterministic hashing.
//!
//! The manifest hash computed on-chain uses Go's encoding/json which sorts
//! object keys alphabetically. We must produce identical JSON to match.
//!
//! This is CRITICAL for provider validation - if our hash doesn't match the
//! on-chain manifest hash, deployment will be rejected.

use crate::error::DeployError;
use std::collections::BTreeMap;

/// Serialize to canonical JSON with sorted keys.
///
/// All object keys are sorted alphabetically to produce deterministic JSON
/// that matches Go's json.Marshal() behavior.
///
/// # Why this matters
///
/// The provider computes: `hash = SHA256(json.Marshal(manifest))`
/// Go's json.Marshal sorts object keys. If we don't sort, hash mismatch -> rejected deployment.
pub fn to_canonical_json<T: serde::Serialize + ?Sized>(value: &T) -> Result<String, DeployError> {
    let json_value = serde_json::to_value(value)
        .map_err(|e| DeployError::Manifest(format!("json error: {}", e)))?;
    let sorted = sort_json_value(json_value);
    serde_json::to_string(&sorted).map_err(|e| DeployError::Manifest(format!("json error: {}", e)))
}

/// Recursively sort all object keys alphabetically.
///
/// BTreeMap gives us sorted keys for free. Arrays and scalars pass through unchanged.
fn sort_json_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> = map
                .into_iter()
                .map(|(k, v)| (k, sort_json_value(v)))
                .collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sort_json_value).collect())
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonical_json_sorts_keys() {
        let unsorted = json!({
            "zebra": 1,
            "apple": 2,
            "middle": 3
        });

        let result = to_canonical_json(&unsorted).unwrap();

        // Keys should be alphabetically sorted
        assert!(result.starts_with(r#"{"apple""#));
        assert!(result.contains(r#""middle""#));
        assert!(result.ends_with(r#""zebra":1}"#));
    }

    #[test]
    fn test_canonical_json_nested_objects() {
        let nested = json!({
            "outer": {
                "z": 1,
                "a": 2
            }
        });

        let result = to_canonical_json(&nested).unwrap();

        // Nested keys should also be sorted
        assert!(result.contains(r#"{"a":2,"z":1}"#));
    }

    #[test]
    fn test_canonical_json_preserves_arrays() {
        let with_array = json!({
            "list": [3, 1, 2]
        });

        let result = to_canonical_json(&with_array).unwrap();

        // Arrays should preserve order (not sorted)
        assert!(result.contains(r#"[3,1,2]"#));
    }
}
