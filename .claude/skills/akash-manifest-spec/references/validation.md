# Validation and Testing

Guide for validating manifest serialization against actual provider code.

## Validation Tool

Location: `~/ergors/tests/scripts/jwt-verify`

This tool uses **actual Akash provider code** to validate manifests:

- `github.com/akash-network/provider/manifest/v2beta3.Manifest.Version()`
- `github.com/akash-network/provider/gateway/utils.AuthProcess()`

## Building the Validator

```bash
cd ~/ergors/tests/scripts/jwt-verify

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
./provider-validate manifest fixtures/simple/manifest.json \
  $(cat fixtures/simple/manifest-hash.txt)
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
cd ~/ergors/tests/scripts/jwt-verify

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
   cd ~/ergors/tests/scripts/jwt-verify
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

Pre-validated fixtures at: `~/ergors/tests/scripts/jwt-verify/fixtures/`

```sh
fixtures/
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
    cd tests/scripts/jwt-verify
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

- [ ] Services sorted alphabetically by name
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
