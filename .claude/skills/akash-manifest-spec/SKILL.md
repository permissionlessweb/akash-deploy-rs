---
name: akash-manifest-spec
description: Specification for SDL-to-manifest serialization in akash-deploy Rust crate. Rust output must match Go provider code byte-for-byte. Defines 7 critical rules (camelCase fields, null arrays, string numbers, sorting), verification procedures using actual provider validation code, debugging decision trees, and task-specific implementation checklists. Use when implementing manifest features, debugging hash mismatches, or validating against provider code.
---

# Akash Manifest Serialization Specification

Authoritative specification for SDL-to-manifest serialization in the `akash-deploy` Rust crate.

## Root Cause: Why Byte-For-Byte Compatibility Matters

**The Rust crate must generate manifests that are byte-for-byte identical to what the Go provider code produces.**

When you deploy to Akash:
1. Your Rust code generates a manifest JSON from an SDL
2. The manifest is hashed and stored on-chain
3. **The provider's Go binary validates the manifest** using `github.com/akash-network/provider` code
4. The provider computes `SHA256(sorted_json)` and compares to the on-chain hash
5. **Any byte difference = deployment rejected** with "manifest version validation failed"

This isn't a "compatibility layer" - it's reverse-engineering Go's JSON marshaling behavior in Rust. The Go provider code is the source of truth, and we must match its output exactly.

## Validation Strategy: Use Actual Provider Code

**Don't guess. Use the exact validation logic providers use.**

At `~/ergors/tests/scripts/jwt-verify`, there's a minimal Go binary that imports:
- `pkg.akt.dev/go/manifest/v2beta3` - Manifest types and validation
- `github.com/akash-network/provider/gateway/utils` - JWT authentication

This tool uses **the exact same functions** providers call:
```go
manifest.Validate()  // Structural validation
manifest.Version()   // Hash computation (SHA256 of canonical JSON)
```

**Workflow:**
1. Generate manifest JSON with Rust
2. Validate with Go binary using actual provider code
3. Compare byte-for-byte and fix differences
4. Repeat until hashes match

See `references/validation.md` for complete testing procedures.

## The 7 Critical Rules

Every manifest must follow these rules or the provider will reject it:

1. **Field names: camelCase** - `externalPort`, not `external_port` (use `#[serde(rename)]`)
2. **Empty arrays: null** - `{"command": null}`, not `{"command": []}` (convert empty Vec to None)
3. **Resource values: strings** - `{"val": "1000"}`, not `{"val": 1000}` (always .to_string())
4. **Services: sorted by name** - `services.sort_by(|a, b| a.name.cmp(&b.name))`
5. **Attributes: sorted by key** - Same for GPU and storage attributes
6. **JSON keys: sorted alphabetically** - Use canonical JSON for hash computation
7. **GPU keys: composite format** - `vendor/nvidia/model/h100/ram/80Gi`, not just `"h100"`

**Verify all rules:**
```bash
cd ~/ergors/tests/scripts/jwt-verify
just test
```

If all tests pass, your implementation is correct. If any fail, see the debugging decision tree below.

## 1. Field Naming: camelCase Required

**Why:** Go JSON tags serialize to camelCase (e.g., `json:"externalPort"`), not snake_case.

**Rule:** Use `#[serde(rename = "camelCase")]` for all multi-word fields.

### Required Renames

```rust
// ServiceExpose
#[serde(rename = "externalPort")]
pub external_port: u32

#[serde(rename = "httpOptions")]
pub http_options: ManifestHttpOptions

#[serde(rename = "endpointSequenceNumber")]
pub endpoint_sequence_number: u32

// HttpOptions
#[serde(rename = "maxBodySize")]
pub max_body_size: u32

#[serde(rename = "readTimeout")]
pub read_timeout: u32

#[serde(rename = "sendTimeout")]
pub send_timeout: u32

#[serde(rename = "nextTries")]
pub next_tries: u32

#[serde(rename = "nextTimeout")]
pub next_timeout: u32

#[serde(rename = "nextCases")]
pub next_cases: Vec<String>

// StorageParams
#[serde(rename = "readOnly")]
pub read_only: bool
```

### Verify

```bash
# Generate manifest
cargo run -- test.yaml output/

# Check field names (should see camelCase, not snake_case)
jq '.[] | .services[0] | .expose[0]' output/manifest.json | grep -E '(externalPort|httpOptions|endpointSequenceNumber)'

# Validate with provider code
cd ~/ergors/tests/scripts/jwt-verify
./provider-validate manifest output/manifest.json $(cat output/manifest-hash.txt)
```

## 2. Null vs Empty Array Semantics

**Why:** Go's JSON marshaling with `omitempty` serializes zero-value slices as `null`, not `[]`.

**Rule:** Convert empty `Vec` to `Option::None` before serialization.

```rust
// Command/args/env - convert empty to None
let command = if command_vec.is_empty() {
    None
} else {
    Some(command_vec)
};
```

**Correct output:**
```json
{"command": null, "args": null, "env": ["FOO=bar"]}
```

**Wrong output (provider rejects):**
```json
{"command": [], "args": [], "env": []}
```

### Verify

```bash
# Check for empty arrays (should find nothing)
jq '.. | select(type == "array" and length == 0)' output/manifest.json

# Should output nothing if correct. If you see [], you have a bug.
```

## 3. Resource Values: String Numbers

**Why:** Go proto types use `string` for resource quantities (not `int` or `uint64`).

**Rule:** All resource values must be strings containing numeric values.

| Resource | Input | Output String |
|----------|-------|---------------|
| CPU | `"100m"` or `1.5` | `"100"` or `"1500"` (millicores) |
| Memory | `"512Mi"` | `"536870912"` (bytes) |
| Storage | `"1Gi"` | `"1073741824"` (bytes) |
| GPU | `2` | `"2"` |

**Implementation:**
```rust
pub struct ManifestResourceValue {
    pub val: String,  // Always string!
}

// CPU millicores: 1.5 cores = "1500", "100m" = "100"
// Memory/Storage bytes: "512Mi" = "536870912"
// GPU units: 2 = "2"
```

See `references/quick-reference.md` for size parsing implementation.

### Verify

```bash
# All resource values should be strings, not numbers
jq '.. | .val? | select(. != null) | type' output/manifest.json

# Should output only "string" (never "number")
```

## 4. Sorting Requirements

**Why:** Hash computation requires deterministic ordering. Provider sorts before hashing.

### Services: Alphabetical by Name

```rust
services.sort_by(|a, b| a.name.cmp(&b.name));
```

### Attributes: Alphabetical by Key

```rust
attributes.sort_by(|a, b| {
    let ak = a.get("key").and_then(|k| k.as_str()).unwrap_or("");
    let bk = b.get("key").and_then(|k| k.as_str()).unwrap_or("");
    ak.cmp(bk)
});
```

### JSON Keys: Canonical Sorting

All object keys must be sorted recursively before hashing. Use `BTreeMap` or sort explicitly.

See `src/canonical.rs` for complete implementation.

### Verify

```bash
# Check service order
jq '.[] | .services | .[].name' output/manifest.json
# Should be alphabetically sorted

# Check attribute order
jq '.. | .attributes? | select(. != null) | .[].key' output/manifest.json
# Should be alphabetically sorted

# Verify hash matches
cd ~/ergors/tests/scripts/jwt-verify
./provider-validate manifest output/manifest.json $(cat output/manifest-hash.txt)
# Should output: ✓ Hash matches
```

## 5. GPU Attributes: Composite Keys

**Why:** Provider uses hierarchical GPU matching, not simple model names.

**Format:** `vendor/{vendor}/model/{model}[/ram/{size}][/interface/{iface}]`

Example: `vendor/nvidia/model/h100/ram/80Gi`

**Implementation:**
```rust
let key = format!("vendor/{}/model/{}", vendor, model_name);
// Optionally append /ram/ and /interface/ segments
```

See `references/checklists.md#implementing-gpu-support` for complete checklist.

### Verify

```bash
# Check GPU attribute format
jq '.[] | .services[].resources.gpu.attributes[]?.key' output/manifest.json

# Should match pattern: vendor/*/model/*[/ram/*][/interface/*]
```

## 6. HTTP Options: Default Values

**Why:** Provider has hardcoded defaults that must match exactly.

**Rule:** Include httpOptions on EVERY expose entry (even UDP).

**Defaults:**
- `maxBodySize: 1048576` (1MB)
- `readTimeout: 60000` (60s in ms)
- `sendTimeout: 60000` (60s in ms)
- `nextTries: 3`
- `nextTimeout: 0`
- `nextCases: ["error", "timeout"]`

See `references/checklists.md#adding-http-options-customization` for implementation details.

### Verify

```bash
# Every expose must have httpOptions
jq '.[] | .services[].expose[] | has("httpOptions")' output/manifest.json
# Should output only "true"
```

## 7. Required Default Values

**Why:** Provider expects specific default values for certain fields.

**Non-negotiable defaults:**
- `service: ""` (expose)
- `ip: ""` (expose)
- `endpointSequenceNumber: 0` (expose)
- `id: 1` (resources)
- `endpoints: []` (resources, always empty)
- GPU always present with `units: "0"` if not used

See `references/quick-reference.md` for complete defaults list.

## 8. Storage Params: Volume Mounts

**Why:** Connects storage resources to container mount points.

**Rule:** Name must match a storage resource. Mount must be absolute path. Use `readOnly` (camelCase).

```json
{
  "params": {
    "storage": [
      {"name": "data", "mount": "/root/.cache", "readOnly": false}
    ]
  }
}
```

See `references/checklists.md#implementing-service-params` for complete guide.

### Verify

```bash
# Check field name is readOnly not readonly
jq '.[] | .services[].params?.storage[]? | keys' output/manifest.json | grep -i readonly
# Should see "readOnly" (camelCase)
```

## 9. Hash Computation

**Why:** On-chain hash must match provider's computed hash for validation.

**Process:**
1. Canonical JSON (all keys sorted recursively)
2. SHA-256 hash of the JSON bytes
3. Compare to on-chain manifest hash

**Implementation:** See `src/canonical.rs`

### Verify

```bash
# Compute hash with provider code and compare
./provider-validate manifest output/manifest.json $(cat output/manifest-hash.txt)

# Should output: ✓ Hash matches
# If not, see debugging decision tree below
```

## 10. Debugging Decision Tree

When your manifest is rejected, follow this decision tree:

### Provider says: "manifest version validation failed"

**Cause:** Hash mismatch (your JSON ≠ provider's expected JSON)

**Debug steps:**
1. Generate manifest with Rust: `cargo run -- input.yaml output/`
2. Validate with provider code: `./provider-validate manifest output/manifest.json <hash>`
3. Tool shows first byte difference → investigate that field
4. Common culprits:
   - Unsorted JSON keys → check canonical JSON implementation
   - Unsorted services → add `services.sort_by(|a, b| a.name.cmp(&b.name))`
   - Unsorted attributes → add attribute sorting by key
   - Wrong field names → check `#[serde(rename)]`

### Provider says: "failed to parse manifest JSON"

**Cause:** Invalid JSON structure or field types

**Debug steps:**
1. Check field names (should be camelCase): `jq 'keys' output/manifest.json`
2. Check resource types (should be strings): `jq '.. | .val? | type' output/manifest.json`
3. Look for empty arrays: `jq '.. | select(type == "array" and length == 0)' output/manifest.json`

### Provider says: "manifest.Validate() failed"

**Cause:** Structural validation failed

**Common issues:**
- Missing required fields (cpu, memory, storage)
- Invalid resource values (e.g., CPU "0")
- Invalid protocol (must be "TCP" or "UDP")
- Empty service name

### Hash matches but deployment still fails

**Cause:** Likely JWT authentication issue, not manifest

**Debug:**
```bash
./provider-validate jwt <token> <pubkey_hex>
```

See `references/validation.md` for complete JWT debugging.

## Testing Against Provider

**Use the exact validation logic providers use.** Don't guess if your manifest is correct.

At `~/ergors/tests/scripts/jwt-verify`:

```bash
# Full test suite (all fixtures)
just test

# Test single SDL
just test-one input.yaml

# Manual validation
./provider-validate manifest output/manifest.json $(cat output/manifest-hash.txt)
```

**What gets validated:**
1. JSON structure (can provider parse it?)
2. Field types (strings vs numbers)
3. Required fields present
4. Hash computation (byte-for-byte match)

See `references/validation.md` for complete testing guide.

## Task-Specific Guides

When implementing specific features, use these checklists:

- **Adding new fields** → `references/checklists.md#adding-a-new-field`
- **GPU support** → `references/checklists.md#implementing-gpu-support`
- **Storage attributes** → `references/checklists.md#adding-storage-attributes`
- **Hash mismatch debugging** → `references/checklists.md#debugging-hash-mismatch`

## Reference Examples

See `references/examples.md` for complete SDL → Manifest transformations:

- Simple service (nginx) - basic structure
- Multi-service deployment - command/args/env, multiple services
- GPU deployment - storage attributes, volume mounts, composite keys

## Proto vs JSON Differences

Provider uses `akash.manifest.v2beta3` protos but serializes via Go's `json.Marshal`:

| Proto Field | Go JSON Field | Notes |
|-------------|---------------|-------|
| `quantity` | `size` | Memory/storage use "size" in JSON |
| All fields | camelCase | Go JSON tags override proto names |
| Empty arrays | `null` | Go omits empty slices |

**Use Go JSON format, NOT proto field names.**
