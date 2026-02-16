# Validation and Testing

Guide for validating manifest serialization against actual provider code.

## Validation Tool

Location: `tests/`

This tool uses **actual Akash provider code** to validate manifests:

- `github.com/akash-network/provider/manifest/v2beta3.Manifest.Version()`
- `github.com/akash-network/provider/gateway/utils.AuthProcess()`

## Building the Validator

```bash
cd tests

# Build Go provider validator
just build-go

# Or manually
go build -o provider-validate .
```

## Validation Commands

### 1. Validate Manifest Hash

```bash
./provider-validate manifest <manifest.json> <expected_hash_hex>
```

**What it does:**

1. Parses manifest JSON into `maniv2beta3.Manifest` type
2. Validates structure with `manifest.Validate()`
3. Computes hash with `manifest.Version()` (same as provider)
4. Compares to expected hash

**Example:**

```bash
./provider-validate manifest testdata/fixtures/simple/manifest.json \
  $(cat testdata/fixtures/simple/manifest-hash.txt)
```

### 2. Validate JWT

```bash
./provider-validate jwt <token> <pubkey_hex>
```

**What it does:**

1. Calls `gwutils.AuthProcess()` (actual provider auth)
2. Verifies ES256K signature
3. Validates claims (issuer, timestamps, version, access)

**Example:**

```bash
./provider-validate jwt \
  "eyJhbGciOiJFUzI1NksiLC..." \
  "02a1b2c3d4e5f6..."
```

### 3. Validate Both

```bash
./provider-validate all <token> <pubkey_hex> <manifest.json> <expected_hash>
```

## Test Workflow

### Full Integration Test

```bash
cd tests

# Run all tests (builds Rust client, generates manifests, validates with Go)
just test
```

**What it does:**

1. Builds Rust JWT/manifest generator
2. Builds Go provider validator
3. For each SDL in `testdata/`:
   - Generates manifest + JWT with Rust
   - Validates with Go provider code
4. Reports pass/fail for each SDL

### Test Single SDL

```bash
just test-one path/to/your.yaml
```

### Test Only Manifests

```bash
just test-sdl
```

### Test Only JWT

```bash
just test-jwt-only
```

## Debugging Hash Mismatches

When validation fails with "hash mismatch", the tool shows:

```sh
❌ FAILED: hash mismatch: computed abc123..., expected def456...

First diff at byte 4: expected 'd', got 'c'

Sorted JSON (what gets hashed):
{"name":"dcloud","services":[...]}
```

### Debug Steps

1. **Check JSON key ordering**
   - All object keys must be alphabetically sorted
   - Use `to_canonical_json()` before hashing

2. **Check field names**
   - Must be camelCase: `externalPort`, not `external_port`
   - Check all `#[serde(rename)]` attributes

3. **Check null vs empty array**
   - Empty command/args/env must be `null`, not `[]`

4. **Check number types**
   - CPU/memory/storage must be STRING: `"1000"`, not `1000`

5. **Compare byte-for-byte**

   ```bash
   # Generate with Rust
   cargo run -- input.yaml output/

   # Generate with Go (golden)
   cd tests
   ./provider-validate gen-fixture input.yaml golden/

   # Compare
   diff output/manifest.json golden/manifest.json
   jq --sort-keys . output/manifest.json > output-sorted.json
   jq --sort-keys . golden/manifest.json > golden-sorted.json
   diff output-sorted.json golden-sorted.json
   ```

## Common Validation Failures

### "manifest version validation failed"

**Cause:** Hash doesn't match on-chain manifest hash

**Debug:**

1. Ensure canonical JSON (sorted keys)
2. Verify no extra/missing fields
3. Check string vs number types
4. Validate service ordering

### "failed to parse manifest JSON"

**Cause:** Invalid JSON structure or field types

**Debug:**

1. Check field names (camelCase)
2. Verify resource values are strings
3. Ensure proper nesting

### "manifest.Validate() failed"

**Cause:** Provider structural validation failed

**Common issues:**

- Missing required fields
- Invalid resource values (e.g., "0" for CPU)
- Invalid protocol (must be "TCP" or "UDP")
- Empty service name

### "provider AuthProcess() rejected"

**Cause:** JWT validation failed

**Debug:**

1. Check ES256K signature format (64 bytes: r || s)
2. Verify issuer format (akash1 + 38 chars)
3. Check timestamps (nbf <= iat <= exp)
4. Ensure version is "v1"
5. Validate access type ("full", "scoped", "granular")

### "over-utilized replicas (N) > group spec resources count (M)"

**Cause:** Service count in manifest doesn't match ResourceUnits in on-chain GroupSpec

**Root Issue:** Provider validates by matching services to ResourceUnits **by position/index**, not by name. If ordering doesn't match, validation fails.

**Example Error:**

```
group "dcloud": service "qwen-coder": over-utilized replicas (1) > group spec resources count (0)
```

**What This Means:**

- Manifest has service "qwen-coder" with count=1
- Provider tried to find a matching ResourceUnit but failed
- The GroupSpec actually HAS ResourceUnits, but ordering is wrong

**Debug Steps:**

1. **Check service ordering in manifest:**

   ```bash
   jq '.[] | .services | map(.name)' manifest.json
   # Should be alphabetically sorted: ["glm-flash", "qwen-coder"]
   ```

2. **Check ResourceUnit order in GroupSpec:**

   ```bash
   # Query on-chain GroupSpec
   akash query deployment group <owner> <dseq> <gseq>
   # ResourceUnits must be in same order as manifest services
   ```

3. **Verify both are sorted alphabetically:**

   The manifest builder sorts services by name (line 288 in `manifest.rs`):

   ```rust
   // CRITICAL: Provider requires services sorted by name within each group
   services.sort_by(|a, b| a.name.cmp(&b.name));
   ```

   The GroupSpec builder MUST also sort services (line 100 in `groupspec.rs`):

   ```rust
   // CRITICAL: Sort services by name to match manifest service order
   // The manifest builder sorts services alphabetically, so GroupSpec must too
   services.sort_by(|a, b| a.0.cmp(&b.0));
   ```

**Why This Happens:**

Provider validation logic matches services to ResourceUnits by position:

```go
// Provider code (simplified)
for i, service := range manifest.Services {
    if i >= len(group.Resources) {
        return error("over-utilized replicas")
    }
    resourceUnit := group.Resources[i]
    // Validate service against resourceUnit
}
```

**The Fix:**

Both manifest and GroupSpec must sort services alphabetically BEFORE creating their respective data structures:

```rust
// In groupspec.rs - BEFORE creating ResourceUnits
for (group_name, mut services) in groups_map {
    // Sort services by name to match manifest order
    services.sort_by(|a, b| a.0.cmp(&b.0));

    for (service_name, profile_name, count) in services {
        // Create ResourceUnit in sorted order
        resources.push(ResourceUnit { ... });
    }
}

// In manifest.rs - BEFORE creating ManifestGroup
let mut groups: Vec<ManifestGroup> = groups_map
    .into_iter()
    .map(|(name, mut services)| {
        // Sort services by name
        services.sort_by(|a, b| a.name.cmp(&b.name));
        ManifestGroup { name, services }
    })
    .collect();
```

**Common Mistake:**

Using HashMap iteration order without sorting:

```rust
// ❌ WRONG - HashMap iteration order is non-deterministic
for (group_name, services) in groups_map {
    for service in services {
        // ResourceUnits created in random order!
    }
}

// ✅ CORRECT - Explicitly sort before creating ResourceUnits
for (group_name, mut services) in groups_map {
    services.sort_by(|a, b| a.0.cmp(&b.0));  // Sort first!
    for service in services {
        // ResourceUnits now in consistent order
    }
}
```

## Fixture Generation

Generate golden reference fixtures from SDL:

```bash
./provider-validate gen-fixture input.yaml output_dir/
```

**Creates:**

- `output_dir/manifest.json` - Provider-generated manifest
- `output_dir/manifest-hash.txt` - Computed hash (hex)

Use these as reference for Rust implementation.

## Test Fixtures

Pre-validated fixtures at: `tests/testdata/fixtures/`

```sh
testdata/fixtures/
├── simple/          - Basic nginx service
│   ├── manifest.json
│   └── manifest-hash.txt
├── comprehensive/   - Multi-service with env vars
│   ├── manifest.json
│   └── manifest-hash.txt
└── gpu/             - GPU deployment with storage
    ├── manifest.json
    └── manifest-hash.txt
```

All fixtures validated against provider code.

## Continuous Validation

Add to CI/CD:

```yaml
# .github/workflows/validate.yml
- name: Validate Manifests
  run: |
    cd tests
    just test
```

## Manual Hash Computation

For debugging, compute hash manually:

```rust
use sha2::{Sha256, Digest};
use std::collections::BTreeMap;

// 1. Load manifest
let manifest: Vec<ManifestGroup> = serde_json::from_str(json_str)?;

// 2. Canonical JSON (sorted keys)
let canonical = to_canonical_json(&manifest)?;
println!("Canonical JSON:\n{}", canonical);

// 3. Hash
let mut hasher = Sha256::new();
hasher.update(canonical.as_bytes());
let hash = hasher.finalize();
println!("Hash: {}", hex::encode(hash));
```

## Provider Source Code References

For deep debugging, check provider source:

**Manifest validation:**

- `pkg.akt.dev/go/manifest/v2beta3/manifest.go`
- Method: `Manifest.Validate()`
- Method: `Manifest.Version()` (hash computation)

**JWT validation:**

- `github.com/akash-network/provider/gateway/utils/auth.go`
- Function: `AuthProcess()`

**SDL parsing:**

- `pkg.akt.dev/go/sdl/sdl.go`
- Method: `SDL.Manifest()`

## Hash Algorithm Details

Provider uses:

```go
func (m Manifest) Version() ([]byte, error) {
    data, err := json.Marshal(m)
    if err != nil {
        return nil, err
    }
    // SortJSON sorts keys alphabetically
    sortedJSON, err := sdk.SortJSON(data)
    if err != nil {
        return nil, err
    }
    hash := sha256.Sum256(sortedJSON)
    return hash[:], nil
}
```

Rust equivalent:

```rust
pub fn compute_hash(manifest: &[ManifestGroup]) -> Result<Vec<u8>, Error> {
    let canonical_json = to_canonical_json(manifest)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical_json.as_bytes());
    Ok(hasher.finalize().to_vec())
}
```

## Troubleshooting Checklist

Before deploying:

- [ ] Services sorted alphabetically by name **within each group**
- [ ] GroupSpec ResourceUnits sorted in **same order** as manifest services
- [ ] Multi-service: Both manifest.rs and groupspec.rs sort before creating structures
- [ ] Attributes sorted alphabetically by key
- [ ] All object keys sorted (canonical JSON)
- [ ] Empty command/args/env are `null`, not `[]`
- [ ] Resource values are strings: `"1000"`, not `1000`
- [ ] Field names are camelCase: `externalPort`, `httpOptions`, `readOnly`
- [ ] GPU units as string: `"2"`, not `2`
- [ ] GPU attributes use composite keys: `vendor/nvidia/model/h100/ram/80Gi`
- [ ] httpOptions present on all expose entries
- [ ] Memory/storage use `size` field, not `quantity`
- [ ] Hash matches: `hex::encode(computed_hash) == expected_hash`

### Multi-Service Deployment Checklist

For deployments with multiple services in the same placement group:

- [ ] **Service Parsing**: All services extracted from SDL deployment section
- [ ] **Grouping Logic**: Services correctly grouped by placement group name
- [ ] **Sorting in Manifest**: Services sorted alphabetically before creating ManifestGroup
- [ ] **Sorting in GroupSpec**: Services sorted alphabetically before creating ResourceUnits
- [ ] **Order Verification**: Manifest service order matches GroupSpec ResourceUnit order
- [ ] **Count Matching**: Each service's count matches its corresponding ResourceUnit count
- [ ] **Resource Matching**: Each service's resources match its corresponding ResourceUnit resources
- [ ] **Integration Test**: Run `cd tests && just test` to validate with provider code
