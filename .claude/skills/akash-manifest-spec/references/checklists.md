# Task-Specific Checklists

Use these checklists when implementing specific features in the akash-deploy crate.

## Adding a New Field to Manifest Types

- [ ] Check Go provider source for the field name (proto vs JSON tag)
- [ ] Add `#[serde(rename = "camelCase")]` if multi-word field
- [ ] Add `#[serde(skip_serializing_if = "Option::is_none")]` if optional
- [ ] If array type: convert empty `Vec` to `None` before serialization
- [ ] Update test fixture in `tests/fixtures/`
- [ ] Run validation: `just test` in jwt-verify directory
- [ ] Verify hash matches: `./provider-validate manifest <file> <hash>`

## Implementing GPU Support

- [ ] GPU units must be string: `{"val": "2"}`, not `{"val": 2}`
- [ ] Create composite keys: `vendor/nvidia/model/h100/ram/80Gi`
- [ ] Format: `vendor/{vendor}/model/{model}[/ram/{size}][/interface/{iface}]`
- [ ] Sort attributes by key alphabetically
- [ ] Always include GPU in resources even if units = "0"
- [ ] Test with gpu fixture: `just test-one fixtures/gpu/input.yaml`

## Adding Storage Attributes

Storage attributes (class, persistent) must be:
- [ ] Added to storage resource, not service level
- [ ] Sorted alphabetically by key
- [ ] String values: `"persistent": "true"`, not boolean
- [ ] Present in both resource storage array and params storage mounts

Example:
```json
{
  "storage": [
    {
      "name": "data",
      "size": {"val": "1073741824"},
      "attributes": [
        {"key": "class", "value": "beta3"},
        {"key": "persistent", "value": "true"}
      ]
    }
  ]
}
```

Verify:
- [ ] Attributes sorted: `jq '.. | .attributes? | .[].key'`
- [ ] Values are strings: `jq '.. | .attributes? | .[].value | type'`

## Implementing Service Params (Volume Mounts)

- [ ] Add params field to service (not resources)
- [ ] Storage name must match a storage resource name
- [ ] Mount path is absolute: `/data`, `/root/.cache`, `/dev/shm`
- [ ] Use `#[serde(rename = "readOnly")]` for read_only field (note: lowercase 'O')
- [ ] Default readOnly to false

Example:
```rust
pub struct ManifestServiceParams {
    pub storage: Vec<ManifestStorageParams>,
}

pub struct ManifestStorageParams {
    pub name: String,
    pub mount: String,
    #[serde(rename = "readOnly")]
    pub read_only: bool,
}
```

Verify:
- [ ] Field name is `readOnly` not `readonly`: `jq '.. | .readOnly'`
- [ ] Mount paths are absolute: `jq '.[] | .services[].params?.storage[]?.mount'`

## Adding HTTP Options Customization

HTTP options have specific defaults. If adding customization:
- [ ] Check Go provider defaults in `pkg.akt.dev/go/manifest/v2beta3`
- [ ] Use these exact defaults:
  - `maxBodySize: 1048576` (1MB)
  - `readTimeout: 60000` (60s in ms)
  - `sendTimeout: 60000` (60s in ms)
  - `nextTries: 3`
  - `nextTimeout: 0`
  - `nextCases: ["error", "timeout"]`
- [ ] All expose entries must have httpOptions (even UDP)
- [ ] All field names camelCase: `maxBodySize`, not `max_body_size`

Verify:
- [ ] Every expose has httpOptions: `jq '.[] | .services[].expose[] | has("httpOptions")'`
- [ ] Defaults match: `jq '.[] | .services[].expose[0].httpOptions'`

## Debugging Hash Mismatch

When `./provider-validate manifest` reports hash mismatch:

1. **Compare canonical JSON:**
   ```bash
   # Your output
   jq --sort-keys -c . output/manifest.json > rust-sorted.json

   # Generate golden reference with provider code
   ./provider-validate gen-fixture input.yaml golden/
   jq --sort-keys -c . golden/manifest.json > go-sorted.json

   # Find first difference
   diff rust-sorted.json go-sorted.json
   ```

2. **Check common issues in order:**
   - [ ] Services sorted alphabetically
   - [ ] Attributes sorted alphabetically
   - [ ] JSON keys sorted (canonical JSON)
   - [ ] Field names camelCase (not snake_case)
   - [ ] No empty arrays (convert to null)
   - [ ] Resource values are strings

3. **Byte-level comparison:**
   ```bash
   # Tool shows first byte difference
   ./provider-validate manifest output/manifest.json <expected-hash>-
   ```
   Output like `First diff at byte 42: expected 'e', got 'E'` points to exact issue.

4. **Validate structure before hash:**
   ```bash
   # This catches type errors before hash comparison
   jq 'type' output/manifest.json  # Should be "array"
   jq '.[0] | keys' output/manifest.json  # Should include "name", "services"
   ```

## Testing Against Provider Code

Before committing changes:

- [ ] Run full test suite: `cd tests && just test`
- [ ] Test all fixtures:
  - [ ] Simple (basic nginx)
  - [ ] Comprehensive (multi-service)
  - [ ] GPU (storage attributes + volume mounts)
- [ ] Test your own SDL: `just test-one path/to/your.yaml`
- [ ] Verify hash matches: should see `✓ Hash matches` for all tests
- [ ] Verify structure: should see `✓ Manifest valid` for all tests

If ANY test fails:
1. Check the diff output from the tool
2. Look at the specific fixture that failed
3. Compare your JSON to the golden reference
4. Use decision tree in SKILL.md to diagnose

## Adding a New Test Fixture

When you implement a new feature:

- [ ] Create SDL in `tests/testdata/`
- [ ] Generate golden reference: `./provider-validate gen-fixture new.yaml fixtures/new/`
- [ ] This creates:
  - `fixtures/new/manifest.json` (provider-generated)
  - `fixtures/new/manifest-hash.txt` (expected hash)
- [ ] Add to test suite in `justfile`
- [ ] Run: `just test` to validate your Rust implementation matches

The golden reference is THE source of truth - your Rust code must produce identical JSON.
