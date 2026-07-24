# Quick Reference Card

Critical serialization rules for the akash-deploy Rust crate.

## The 7 Golden Rules

### 1. Field Names: camelCase Only

```rust
#[serde(rename = "externalPort")]    // ✓
pub external_port: u32

pub external_port: u32                 // ✗ Wrong
```

**All renames:**

- `externalPort`, `httpOptions`, `endpointSequenceNumber`
- `maxBodySize`, `readTimeout`, `sendTimeout`, `nextTries`, `nextTimeout`, `nextCases`
- `readOnly`

### 2. Empty Arrays → null

```rust
// Convert empty vecs to None
let command = if cmd.is_empty() { None } else { Some(cmd) };
```

```json
{"command": null}     // ✓ Correct
{"command": []}       // ✗ Provider rejects
```

### 3. Resource Values: STRING Numbers

```rust
pub struct ManifestResourceValue {
    pub val: String,  // Always string!
}
```

```json
{"units": {"val": "1000"}}    // ✓ Correct
{"units": {"val": 1000}}      // ✗ Wrong type
```

### 4. Sort Services by Name

```rust
services.sort_by(|a, b| a.name.cmp(&b.name));
```

### 5. Sort Attributes by Key

```rust
attributes.sort_by(|a, b| {
    let ak = a["key"].as_str().unwrap_or("");
    let bk = b["key"].as_str().unwrap_or("");
    ak.cmp(bk)
});
```

### 6. Sort JSON Keys (Canonical)

```rust
use std::collections::BTreeMap;

// Recursively sort all object keys
fn sort_json_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<_, _> = map
                .into_iter()
                .map(|(k, v)| (k, sort_json_value(v)))
                .collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(
                arr.into_iter().map(sort_json_value).collect()
            )
        }
        other => other,
    }
}
```

### 7. GPU Composite Keys

```rust
let key = format!("vendor/{}/model/{}", vendor, model);
if let Some(ram) = ram_value {
    key.push_str(&format!("/ram/{}", ram));
}
```

Format: `vendor/nvidia/model/h100/ram/80Gi`

## Type Conversions

| SDL Input | Manifest Output | Type |
|-----------|-----------------|------|
| `"100m"` (CPU) | `"100"` | String millicores |
| `1.5` (CPU cores) | `"1500"` | String millicores |
| `"512Mi"` (memory) | `"536870912"` | String bytes |
| `"1Gi"` (storage) | `"1073741824"` | String bytes |
| `2` (GPU units) | `"2"` | String |
| `true` (persistent) | `"true"` | String |

## Size Conversion

```rust
fn parse_size(s: &str) -> u64 {
    let (num, mult) = match s {
        s if s.ends_with("Gi") => (&s[..s.len()-2], 1073741824),
        s if s.ends_with("Mi") => (&s[..s.len()-2], 1048576),
        s if s.ends_with("Ki") => (&s[..s.len()-2], 1024),
        s => (s, 1),
    };
    num.parse::<u64>().unwrap() * mult
}
```

## Default Values

```rust
// Always include on every service
ManifestServiceExpose {
    service: String::new(),           // ""
    ip: String::new(),                // ""
    endpoint_sequence_number: 0,
    http_options: ManifestHttpOptions::default(),
}

// Always include on every resource
ManifestResources {
    id: 1,
    endpoints: Vec::new(),
    gpu: ManifestGpu {
        units: ManifestResourceValue { val: "0".to_string() },
        attributes: Vec::new(),
    },
}

// HTTP options defaults
ManifestHttpOptions {
    max_body_size: 1_048_576,    // 1MB
    read_timeout: 60_000,         // 60s
    send_timeout: 60_000,         // 60s
    next_tries: 3,
    next_timeout: 0,
    next_cases: vec!["error".to_string(), "timeout".to_string()],
}
```

## Proto vs JSON Field Names

| Proto | Go JSON | Use in Rust |
|-------|---------|-------------|
| `quantity` | `size` | `size` ✓ |
| `external_port` | `externalPort` | `externalPort` ✓ |
| `http_options` | `httpOptions` | `httpOptions` ✓ |

**Rule:** Use Go JSON names, NOT proto names.

## Hash Computation

```rust
use sha2::{Sha256, Digest};

// 1. Canonical JSON (sorted keys)
let json = to_canonical_json(&manifest)?;

// 2. SHA-256 hash
let mut hasher = Sha256::new();
hasher.update(json.as_bytes());
let hash = hasher.finalize();

// 3. Hex encode for comparison
let hash_hex = hex::encode(hash);
```

## Validation Test

```bash
# Generate manifest with Rust
cargo run -- input.yaml output/

# Validate with provider code
cd tests
./provider-validate manifest \
  output/manifest.json \
  $(cat output/manifest-hash.txt)
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| `"command": []` | `"command": null` |
| `"units": 1000` | `"units": {"val": "1000"}` |
| `"external_port"` | `"externalPort"` |
| `"quantity"` | `"size"` |
| Unsorted services | `services.sort_by(...)` |
| Unsorted JSON keys | Use `to_canonical_json()` |
| GPU key: `"h100"` | `"vendor/nvidia/model/h100/ram/80Gi"` |

## Memory Aids

**NULL not EMPTY** - Empty vecs become null
**STRING not NUMBER** - Resource values are strings
**CAMEL not SNAKE** - externalPort not external_port
**SIZE not QUANTITY** - Memory uses "size" field
**SORT EVERYTHING** - Services, attributes, JSON keys
