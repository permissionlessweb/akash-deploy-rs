# Manifest Serialization Specification

Authoritative specification for SDL-to-manifest serialization in `akash-deploy-rs`.

## Why Byte-For-Byte Compatibility

1. Rust code generates manifest JSON from SDL
2. Manifest is hashed and stored on-chain
3. Provider's Go binary validates manifest using `github.com/akash-network/provider`
4. Provider computes `SHA256(sorted_json)` and compares to on-chain hash
5. **Any byte difference = deployment rejected** ("manifest version validation failed")

## Validation Strategy

Use actual provider validation code at `tests/`:
```bash
cd tests && just test           # Full suite
just test-one input.yaml        # Single SDL
./provider-validate manifest output/manifest.json $(cat output/manifest-hash.txt)
```

## The 7 Critical Rules

### 1. Field Names: camelCase

Use `#[serde(rename)]` for all multi-word fields:

```rust
#[serde(rename = "externalPort")]  pub external_port: u32
#[serde(rename = "httpOptions")]   pub http_options: ManifestHttpOptions
#[serde(rename = "endpointSequenceNumber")] pub endpoint_sequence_number: u32
#[serde(rename = "maxBodySize")]   pub max_body_size: u32
#[serde(rename = "readTimeout")]   pub read_timeout: u32
#[serde(rename = "sendTimeout")]   pub send_timeout: u32
#[serde(rename = "nextTries")]     pub next_tries: u32
#[serde(rename = "nextTimeout")]   pub next_timeout: u32
#[serde(rename = "nextCases")]     pub next_cases: Vec<String>
#[serde(rename = "readOnly")]      pub read_only: bool
```

### 2. Empty Arrays → null

Go's `omitempty` serializes zero-value slices as `null`:

```rust
let command = if command_vec.is_empty() { None } else { Some(command_vec) };
```

Correct: `{"command": null}` — Wrong: `{"command": []}`

### 3. Resource Values: Strings

All resource quantities are strings:

| Resource | Input | Output |
|----------|-------|--------|
| CPU | `"100m"` / `1.5` | `"100"` / `"1500"` (millicores) |
| Memory | `"512Mi"` | `"536870912"` (bytes) |
| Storage | `"1Gi"` | `"1073741824"` (bytes) |
| GPU | `2` | `"2"` |

### 4. Services: Sorted by Name

```rust
services.sort_by(|a, b| a.name.cmp(&b.name));
```

### 5. Attributes: Sorted by Key

```rust
attributes.sort_by(|a, b| {
    let ak = a.get("key").and_then(|k| k.as_str()).unwrap_or("");
    let bk = b.get("key").and_then(|k| k.as_str()).unwrap_or("");
    ak.cmp(bk)
});
```

### 6. JSON Keys: Canonical Sorting

All object keys sorted recursively before hashing. Use `BTreeMap`. See `src/canonical.rs`.

### 7. GPU Keys: Composite Format

`vendor/{vendor}/model/{model}[/ram/{size}][/interface/{iface}]`

Example: `vendor/nvidia/model/h100/ram/80Gi`

## HTTP Options Defaults

Include on EVERY expose entry (even UDP):

- `maxBodySize: 1048576` (1MB)
- `readTimeout: 60000` (60s)
- `sendTimeout: 60000` (60s)
- `nextTries: 3`
- `nextTimeout: 0`
- `nextCases: ["error", "timeout"]`

## Required Default Values

- `service: ""` (expose)
- `ip: ""` (expose)
- `endpointSequenceNumber: 0` (expose)
- `id: 1` (resources)
- `endpoints: []` (resources)
- GPU always present with `units: "0"` if not used

## Debugging Decision Tree

### "manifest version validation failed"
Hash mismatch. Generate manifest → validate with Go binary → tool shows first byte difference.
Common: unsorted JSON keys, unsorted services/attributes, wrong field names.

### "failed to parse manifest JSON"
Check camelCase field names, resource string types, empty arrays vs null.

### "manifest.Validate() failed"
Missing required fields, invalid CPU "0", invalid protocol, empty service name.

### Hash matches but deployment fails
Likely JWT auth issue. Debug: `./provider-validate jwt <token> <pubkey_hex>`

## Proto vs JSON

| Proto Field | Go JSON Field | Notes |
|-------------|---------------|-------|
| `quantity` | `size` | Memory/storage use "size" |
| All fields | camelCase | Go JSON tags override proto |
| Empty arrays | `null` | Go omits empty slices |

**Use Go JSON format, NOT proto field names.**
