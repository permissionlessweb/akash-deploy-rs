//! Canonical JSON serialization for deterministic hashing.
//!
//! The manifest hash computed on-chain uses Go's encoding/json which sorts
//! object keys alphabetically AND escapes &, <, > in string values.
//! We must produce identical JSON to match.
//!
//! This is CRITICAL for provider validation - if our hash doesn't match the
//! on-chain manifest hash, deployment will be rejected.

use crate::error::DeployError;
use std::collections::BTreeMap;

/// Serialize to canonical JSON with sorted keys and Go-compatible escaping.
///
/// All object keys are sorted alphabetically to produce deterministic JSON
/// that matches Go's json.Marshal() behavior. Additionally, &, <, > are
/// escaped as \u0026, \u003c, \u003e to match Go's HTML-safe default.
///
/// # Why this matters
///
/// The provider computes: `hash = SHA256(json.Marshal(manifest))`
/// Go's json.Marshal sorts object keys AND HTML-escapes certain characters.
/// If we don't match both behaviors, hash mismatch -> rejected deployment.
pub fn to_canonical_json<T: serde::Serialize + ?Sized>(value: &T) -> Result<String, DeployError> {
    let json_value = serde_json::to_value(value)
        .map_err(|e| DeployError::Manifest(format!("json error: {}", e)))?;
    let sorted = sort_json_value(json_value);
    let json_str = serde_json::to_string(&sorted)
        .map_err(|e| DeployError::Manifest(format!("json error: {}", e)))?;
    // Go's encoding/json escapes &, <, > in string values for HTML safety.
    // Provider re-serializes with json.Marshal, so we must match this behavior
    // or the hash will differ.
    Ok(go_html_escape(&json_str))
}

/// Apply Go-compatible HTML escaping to a JSON string.
///
/// Go's `encoding/json` escapes these characters in ALL string values:
///   & -> \u0026
///   < -> \u003c
///   > -> \u003e
///
/// Rust's serde_json outputs them literally. Since the Akash provider
/// re-serializes manifests with Go's json.Marshal before hashing,
/// we must produce identical bytes.
fn go_html_escape(json: &str) -> String {
    let mut result = String::with_capacity(json.len());
    let mut in_string = false;
    let mut chars = json.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' && in_string {
            // Escaped character inside string - pass through both chars
            result.push(ch);
            if let Some(next) = chars.next() {
                result.push(next);
            }
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            result.push(ch);
            continue;
        }
        if in_string {
            match ch {
                '&' => result.push_str(r"\u0026"),
                '<' => result.push_str(r"\u003c"),
                '>' => result.push_str(r"\u003e"),
                _ => result.push(ch),
            }
        } else {
            result.push(ch);
        }
    }
    result
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

    #[test]
    fn test_go_html_escape_ampersand() {
        // Go escapes & in string values as \u0026
        let input = json!({"cmd": "a && b"});
        let result = to_canonical_json(&input).unwrap();
        assert!(result.contains(r"a \u0026\u0026 b"), "got: {}", result);
        assert!(!result.contains("&&"), "literal && should be escaped, got: {}", result);
    }

    #[test]
    fn test_go_html_escape_angle_brackets() {
        let input = json!({"html": "<script>alert(1)</script>"});
        let result = to_canonical_json(&input).unwrap();
        assert!(result.contains(r"\u003cscript\u003e"), "got: {}", result);
        assert!(!result.contains("<script>"), "literal < should be escaped, got: {}", result);
    }

    #[test]
    fn test_go_html_escape_preserves_backslash_escapes() {
        // Strings with backslash escapes should not be double-escaped
        let input = json!({"path": "a\\b&c"});
        let result = to_canonical_json(&input).unwrap();
        // serde_json outputs a\\b as a\\b in JSON, the & becomes \u0026
        assert!(result.contains(r"\u0026c"), "got: {}", result);
    }

    #[test]
    fn test_go_html_escape_does_not_affect_non_strings() {
        // Numbers, booleans, nulls should not be affected
        let input = json!({"count": 1, "flag": true, "nothing": null});
        let result = to_canonical_json(&input).unwrap();
        assert!(result.contains(r#""count":1"#));
        assert!(result.contains(r#""flag":true"#));
        assert!(result.contains(r#""nothing":null"#));
    }

    #[test]
    fn test_go_html_escape_shell_command() {
        // Real-world: shell commands in SDL args contain &&
        let input = json!({"args": ["sh", "-c", "cmd1 && cmd2 | grep foo > /dev/null"]});
        let result = to_canonical_json(&input).unwrap();
        assert!(result.contains(r"cmd1 \u0026\u0026 cmd2 | grep foo \u003e /dev/null"),
            "got: {}", result);
    }
}
