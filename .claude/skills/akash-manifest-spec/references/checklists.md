# Task-Specific Checklists

Use these checklists when implementing specific features in the akash-deploy crate.

## Adding a New Field to Manifest Types

- [ ] Check Go provider source for the field name (proto vs JSON tag)
- [ ] Add `#[serde(rename = "camelCase")]` if multi-word field
- [ ] Add `#[serde(skip_serializing_if = "Option::is_none")]` if optional
- [ ] If array type: convert empty `Vec` to `None` before serialization
- [ ] Update test fixture in `tests/testdata/fixtures/`
- [ ] Run validation: `just test` in jwt-verify directory
- [ ] Verify hash matches: `./provider-validate manifest <file> <hash>`

## Implementing GPU Support

- [ ] GPU units must be string: `{"val": "2"}`, not `{"val": 2}`
- [ ] Create composite keys: `vendor/nvidia/model/h100/ram/80Gi`
- [ ] Format: `vendor/{vendor}/model/{model}[/ram/{size}][/interface/{iface}]`
- [ ] Sort attributes by key alphabetically
- [ ] Always include GPU in resources even if units = "0"
- [ ] Test with gpu fixture: `just test-one testdata/fixtures/gpu/input.yaml`

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
- [ ] Generate golden reference: `./provider-validate gen-fixture new.yaml testdata/fixtures/new/`
- [ ] This creates:
  - `testdata/fixtures/new/manifest.json` (provider-generated)
  - `testdata/fixtures/new/manifest-hash.txt` (expected hash)
- [ ] Add to test suite in `justfile`
- [ ] Run: `just test` to validate your Rust implementation matches

The golden reference is THE source of truth - your Rust code must produce identical JSON.

## Implementing Multi-Service Deployments

When adding support for deployments with multiple services in the same placement group:

### Service Grouping Logic

- [ ] **Parse all services** from deployment section, not just first one
- [ ] **Extract placement group** name for each service (key in deployment config)
- [ ] **Group services** by placement group using HashMap
- [ ] **Store tuple** of (service_name, profile_name, count, placement_group)

Example:
```rust
// Iterate all services in deployment
for (service_name, service_deployment) in deployment_map {
    for (placement_name, placement_config) in service_deployment.as_mapping() {
        let group_name = placement_name.as_str();
        let count = placement_config.get("count");
        let profile = placement_config.get("profile");
        service_infos.push((service_name, profile, count, group_name));
        break; // Only first placement per service
    }
}

// Group by placement
let mut groups_map: HashMap<String, Vec<_>> = HashMap::new();
for (service, profile, count, group) in service_infos {
    groups_map.entry(group).or_default().push((service, profile, count));
}
```

### Critical: Service Ordering

**Provider validation matches services to ResourceUnits BY POSITION, not by name.**

- [ ] **Sort in manifest.rs** before creating ManifestGroup:
  ```rust
  let mut groups: Vec<ManifestGroup> = groups_map
      .into_iter()
      .map(|(name, mut services)| {
          // CRITICAL: Sort services alphabetically
          services.sort_by(|a, b| a.name.cmp(&b.name));
          ManifestGroup { name, services }
      })
      .collect();
  ```

- [ ] **Sort in groupspec.rs** before creating ResourceUnits:
  ```rust
  for (group_name, mut services) in groups_map {
      // CRITICAL: Sort to match manifest service order
      services.sort_by(|a, b| a.0.cmp(&b.0));

      for (service_name, profile_name, count) in services {
          resources.push(ResourceUnit { ... });
      }
  }
  ```

- [ ] **DO NOT rely on HashMap iteration order** - it's non-deterministic
- [ ] **Both builders must sort** - sorting only one causes position mismatch

### Validation Logic

Provider validates like this:

```go
// Simplified provider logic
for i, service := range manifest.Services {
    if i >= len(group.Resources) {
        return fmt.Errorf("service %q: over-utilized replicas (%d) > group spec resources count (%d)",
            service.Name, service.Count, len(group.Resources))
    }

    resourceUnit := group.Resources[i]  // Match by INDEX, not name!

    if service.Count > resourceUnit.Count {
        return fmt.Errorf("service count exceeds resource unit count")
    }
}
```

**Key insight:** Provider uses `i` to index into `group.Resources`, not service name lookup.

### Common Errors

**Error: "over-utilized replicas (1) > group spec resources count (0)"**

This means:
- Manifest has service at position N
- GroupSpec has < N ResourceUnits OR
- GroupSpec ResourceUnit order doesn't match manifest service order

Debug:
```bash
# Check manifest service order
jq '.[] | .services | map(.name)' manifest.json

# Check on-chain ResourceUnit order
akash query deployment group <owner> <dseq> <gseq>

# They MUST be in same order!
```

### Testing Multi-Service

- [ ] Create test SDL with 2+ services in same placement group
- [ ] Add to `tests/testdata/multi-service.yaml`
- [ ] Services should have different:
  - Names (alphabetically ordered: glm-flash, qwen-coder)
  - Images
  - Exposed ports
  - But SAME placement group
- [ ] Run: `cd tests && just test`
- [ ] Verify both services appear in manifest
- [ ] Verify ResourceUnits match service count (2 services = 2 ResourceUnits)
- [ ] Verify ordering: `jq '.[] | .services | map(.name)'` shows alphabetical order

### Implementation Checklist

- [ ] Parse all services from deployment (not just first)
- [ ] Group services by placement group
- [ ] Sort services alphabetically in manifest builder
- [ ] Sort services alphabetically in groupspec builder
- [ ] Create one ResourceUnit per service
- [ ] Verify ResourceUnit count = service count in group
- [ ] Test with multi-service SDL
- [ ] Verify provider validation passes
- [ ] Check debug output shows correct ordering:
  ```
  DEBUG: Grouping service 'glm-flash' into group 'dcloud'
  DEBUG: Grouping service 'qwen-coder' into group 'dcloud'
  DEBUG: Building GroupSpec for group 'dcloud' with 2 services
  DEBUG:   Creating ResourceUnit for service 'glm-flash'
  DEBUG:   Creating ResourceUnit for service 'qwen-coder'
  DEBUG: GroupSpec 'dcloud' final has 2 ResourceUnits
  ```

### Files to Modify

When implementing multi-service support:

1. **`src/groupspec.rs`**
   - Parse all services from deployment section
   - Group by placement
   - Sort before creating ResourceUnits
   - Create one ResourceUnit per service

2. **`src/manifest.rs`**
   - Parse all services
   - Group by placement
   - Sort before creating ManifestGroup
   - Ensure service order matches GroupSpec

3. **`tests/testdata/multi-service.yaml`**
   - Add test case with 2+ services
   - Same placement group
   - Different service names (alphabetical)

4. **Run validation:**
   ```bash
   cd tests
   just test  # Must pass for all SDLs including multi-service
   ```
