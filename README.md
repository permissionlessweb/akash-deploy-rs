# akash-deploy-rs

[![Crates.io](https://img.shields.io/crates/v/akash-deploy-rs.svg)](https://crates.io/crates/akash-deploy-rs)
[![Documentation](https://docs.rs/akash-deploy-rs/badge.svg)](https://docs.rs/akash-deploy-rs)
[![License](https://img.shields.io/crates/l/akash-deploy-rs.svg)](https://github.com/permissionlessweb/akash-deploy-rs)
[![GitHub](https://img.shields.io/badge/github-permissionlessweb-blue.svg)](https://github.com/permissionlessweb/akash-deploy-rs)

**Standalone deployment workflow engine for Akash Network.**

Build, authenticate, and deploy applications to Akash using a trait-based state machine. No storage, signing, or transport coupling — bring your own infrastructure.

---

## Features

- **SDL → Manifest** — Parse SDL YAML to provider-ready JSON with correct serialization
- **Canonical JSON** — Deterministic hashing that matches Go provider validation
- **JWT Authentication** — ES256K self-attested tokens for provider communication
- **Certificate Generation** — TLS certs with encrypted private key storage
- **Workflow Engine** — State machine for full deployment lifecycle
- **Backend Agnostic** — Single `AkashBackend` trait, you implement persistence/transport
- **SDL Templates** — Variable substitution for reusable deployment configs (default)
- **Default Client** — Integrated layer-climb client with file-backed storage (opt-in)

## Design Principles

1. **Single Trait** — `AkashBackend` is the only interface
2. **Bring Your Own Infrastructure** — No storage, HTTP, or signing coupling
3. **State Machine Focused** — Workflow orchestrates, you implement primitives
4. **Explicit Errors** — `DeployError` covers all failure modes
5. **Type Safety** — Correct manifest serialization enforced at compile time

---

## Quick Start

### Opt Out of Default Client

To use only the core workflow engine without the integrated client:

```toml
[dependencies]
akash-deploy-rs = { version = "0.0.5" }
```

### Opt-Into Deploy with Default Client

The fastest path to a working deployment. Requires the `default-client` feature (disabled by default).

```toml
[dependencies]
akash-deploy-rs = { version = "0.0.5", features = ["default-client"] }
```

Then implement `AkashBackend` yourself as shown in the architecture section.

```rust
use akash_deploy_rs::{
    AkashClient, AkashBackend, DeploymentState, DeploymentWorkflow,
    InputRequired, KeySigner, StepResult, WorkflowConfig,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = std::env::var("TEST_MNEMONIC")?;

    // 1. Create client (derives address, sets up RPC + gRPC)
    let client = AkashClient::new_from_mnemonic(
        &mnemonic,
        "https://rpc.akashnet.net:443",
        "https://grpc.akashnet.net:443",
    ).await?;

    // 2. Create signer (for transaction signing + JWT generation)
    let signer = KeySigner::new_mnemonic_str(&mnemonic, None)
        .map_err(|e| format!("signer: {e:?}"))?;

    // 3. Configure workflow
    let config = WorkflowConfig {
        auto_select_cheapest_bid: false, // prompt for provider selection
        ..Default::default()
    };
    let workflow = DeploymentWorkflow::new(&client, &signer, config);

    // 4. Create deployment state with SDL
    let sdl = std::fs::read_to_string(sdl_file)?;
    let mut state = DeploymentState::new("oline-sentries", client.address())
        .with_sdl(&sdl)
        .with_label("oline-sentries");

    // 5. Drive the workflow
    loop {
        match workflow.advance(&mut state).await? {
            StepResult::Continue => continue,
            StepResult::NeedsInput(InputRequired::SelectProvider { bids }) => {
                // Pick a provider (or auto-select with config flag)
                let provider = &bids[0].provider;
                DeploymentWorkflow::<AkashClient>::select_provider(&mut state, provider)?;
            }
            StepResult::Complete => {
                println!("Deployed! Endpoints:");
                for ep in &state.endpoints {
                    println!("  {} -> {}:{}", ep.uri, ep.service, ep.port);
                }
                break;
            }
            StepResult::Failed(reason) => return Err(reason.into()),
            _ => {}
        }
    }
    Ok(())
}
```

### JWT Authentication (How It Works)

Akash providers authenticate requests using **self-attested ES256K JWTs**. There is no challenge-response or registration — each request is independently validated.

**Flow:**

1. Client builds JWT claims with `iss` = account address, timestamps, and `"full"` lease access
2. Client signs the JWT with their secp256k1 private key (same key that signs transactions)
3. Client sends JWT in `Authorization: Bearer <token>` header
4. Provider fetches the issuer's public key from on-chain account state and verifies the signature

The workflow handles this automatically during the `EnsureAuth` step. For standalone use:

```rust
use akash_deploy_rs::{JwtBuilder, JwtClaims};

// Build claims (valid 15 minutes)
let claims = JwtClaims::new("akash1youraddress...");

// Sign with your secp256k1 key (ES256K)
let jwt = JwtBuilder::new().build_and_sign(&claims, |message| {
    // Your signing function — return DER-encoded signature
    my_keypair.sign(message)
})?;

// Use in provider requests
client.put(url)
    .header("Authorization", format!("Bearer {}", jwt))
    .send().await?;
```

### Manifest Building Only

If you only need SDL parsing without the full workflow:

```rust
use akash_deploy_rs::{ManifestBuilder, to_canonical_json};

let builder = ManifestBuilder::new(&owner, dseq);
let groups = builder.build_from_sdl(sdl_yaml)?;
let canonical_json = to_canonical_json(&groups)?;

// Hash matches what provider computes for validation
use sha2::{Digest, Sha256};
let hash = Sha256::digest(canonical_json.as_bytes());
```

### Custom Backend

Implement the `AkashBackend` trait to bring your own infrastructure:

```rust
use akash_deploy_rs::{AkashBackend, DeploymentWorkflow, DeploymentState};

struct MyBackend { /* your storage, HTTP client, etc. */ }

impl AkashBackend for MyBackend {
    type Signer = MySigner;
    // Implement query_balance, broadcast_create_deployment, send_manifest, etc.
}

let workflow = DeploymentWorkflow::new(&backend, &signer, Default::default());
let mut state = DeploymentState::new("session-1", "akash1owner...")
    .with_sdl(sdl_content)
    .with_label("my-app");

// Same advance() loop as above
```

---

## Architecture

```mermaid
flowchart TB
    SDL[SDL YAML] --> MB[ManifestBuilder]
    MB --> MG[ManifestGroup]
    MG --> CJ[to_canonical_json]
    CJ --> Hash[SHA256 Hash]

    subgraph akash-deploy-rs
        MB
        CJ
        JB[JwtBuilder]
        CG[Certificate Generator]
        WF[DeploymentWorkflow]
    end

    subgraph Consumer Implementation
        Backend[AkashBackend Trait]
        Storage[(Storage)]
        HTTP[HTTP Client]
        Signer[Key Signer]
    end

    WF --> Backend
    Backend --> Storage
    Backend --> HTTP
    WF --> Signer
    JB --> Signer
```

### Components

| Component | Purpose | Dependencies |
|-----------|---------|--------------|
| **ManifestBuilder** | SDL parsing → JSON manifest | None |
| **to_canonical_json** | Deterministic JSON serialization | None |
| **JwtBuilder** | ES256K JWT construction | Consumer provides signing |
| **CertificateGenerator** | TLS cert generation | None |
| **DeploymentWorkflow** | State machine orchestration | AkashBackend trait |

---

## Deployment Workflow

```mermaid
sequenceDiagram
    participant App as Your App
    participant WF as DeploymentWorkflow
    participant Backend as AkashBackend
    participant Chain as Akash Chain
    participant Provider as Akash Provider

    App->>WF: run_to_completion(state)

    WF->>Backend: query_balance(owner)
    Backend->>Chain: Query account
    Chain-->>Backend: Balance
    Backend-->>WF: Balance OK

    WF->>WF: generate_certificate()

    WF->>Backend: broadcast_create_deployment(msg)
    Backend->>Chain: Broadcast tx
    Chain-->>Backend: Tx hash
    Backend-->>WF: Deployment created (dseq)

    WF->>Backend: query_bids(lease_id)
    Backend->>Chain: Query market
    Chain-->>Backend: Bid list
    Backend-->>WF: Bids available

    Note over WF,App: User selects bid

    WF->>Backend: broadcast_create_lease(bid)
    Backend->>Chain: Broadcast tx
    Chain-->>Backend: Tx hash
    Backend-->>WF: Lease created

    WF->>WF: build_manifest(SDL)
    WF->>WF: generate_jwt(owner, keypair)

    WF->>Backend: send_manifest(provider, manifest, cert, key)
    Backend->>Provider: PUT /deployment/{dseq}/manifest
    Provider-->>Backend: 200 OK
    Backend-->>WF: Manifest accepted

    WF->>Backend: query_provider_status(lease_id)
    Backend->>Provider: GET /lease/{...}/status
    Provider-->>Backend: Service endpoints
    Backend-->>WF: Endpoints available

    WF-->>App: Complete (endpoints)
```

---

## Critical Serialization Details

Provider JSON API has strict requirements. `ManifestBuilder` handles these correctly:

| Requirement | Implementation |
|-------------|----------------|
| CPU units | STRING millicores: `"1000"` not `1.0` |
| Memory/storage sizes | STRING bytes: `"536870912"` not int |
| Memory/storage field name | `"size"` (Go JSON tag), **not** `"quantity"` (proto field name) |
| Empty arrays | `null` not `[]` for command/args/env |
| Field names | camelCase: `externalPort`, `httpOptions`, `readOnly`, `endpointSequenceNumber` |
| GPU attributes | Composite keys: `vendor/nvidia/model/h100/ram/80Gi` |
| Storage attributes | Sorted by key |
| Services | Sorted by name |
| Resource endpoints | Only global exposes; GroupSpec `kind = 0` (SHARED_HTTP) |

**Canonical JSON is required** — Go's `encoding/json` sorts keys, we must match for hash validation.

## SDL Templates

SDL templates are enabled by default. To opt out, disable default features:

```toml
[dependencies]
akash-deploy-rs = { version = "0.0.5", default-features = false }
```

SDL templates allow you to create reusable deployment configurations with variable placeholders using `${VAR}` syntax:

```yaml
version: "2.0"
services:
  web:
    image: ${IMAGE}:${VERSION}
    expose:
      - port: ${PORT}
        as: ${PORT}
        to:
          - global: true
profiles:
  compute:
    web:
      resources:
        cpu:
          units: ${CPU_UNITS}
        memory:
          size: ${MEMORY_SIZE}
        storage:
          size: ${STORAGE_SIZE}
  placement:
    dcloud:
      pricing:
        web:
          denom: uakt
          amount: ${PRICE}
deployment:
  web:
    dcloud:
      profile: web
      count: ${COUNT}
```

### Usage

```rust
use akash_deploy_rs::{DeploymentState, SdlTemplate, TemplateVariables, TemplateDefaults};
use std::collections::HashMap;

// Define defaults
let mut defaults = TemplateDefaults::new();
defaults.insert("IMAGE".to_string(), "nginx".to_string());
defaults.insert("VERSION".to_string(), "1.25".to_string());
defaults.insert("PORT".to_string(), "80".to_string());
defaults.insert("CPU_UNITS".to_string(), "100m".to_string());
defaults.insert("MEMORY_SIZE".to_string(), "128Mi".to_string());
defaults.insert("STORAGE_SIZE".to_string(), "1Gi".to_string());
defaults.insert("PRICE".to_string(), "100".to_string());
defaults.insert("COUNT".to_string(), "1".to_string());

// User overrides (optional)
let mut variables = TemplateVariables::new();
variables.insert("VERSION".to_string(), "1.26".to_string());
variables.insert("PORT".to_string(), "8080".to_string());

// Create deployment with template
let state = DeploymentState::new("session-1", "akash1owner...")
    .with_sdl(template_content)
    .with_template(defaults)
    .with_variables(variables);

// Workflow processes template automatically at SendManifest step
workflow.run_to_completion(&mut state).await?;
```

### Template Features

- **Variable Syntax**: `${VARIABLE_NAME}` — alphanumeric characters and underscores only
- **Strict Validation**: All variables must have defaults (enforced at processing time)
- **Priority**: User variables override defaults
- **YAML-Aware**: Preserves document structure during substitution
- **Error Handling**: Clear error messages for missing defaults, unclosed placeholders, invalid variable names

### Direct Template Processing

You can also process templates directly without the workflow:

```rust
use akash_deploy_rs::{SdlTemplate, ManifestBuilder};

let template = SdlTemplate::new(template_content)?;

// Validate all variables have defaults
template.validate(&defaults)?;

// Process with overrides
let processed_sdl = template.process(&variables, &defaults)?;

// Build manifest from processed SDL
let builder = ManifestBuilder::new("akash1owner", 123);
let manifest = builder.build_from_sdl(&processed_sdl)?;
```

---

### Storage System

The default client uses a **memory + file** persistence strategy:

**Storage Layout:**

```
~/.akash-deploy/
  sessions/
    my-app.json         # Deployment state
    production.json
  certs/
    akash1xxx.key       # Encrypted private keys
  providers.json        # Provider cache
  certificates.json     # Certificate cache
```

**Key Features:**

- **In-Memory Cache**: Fast access to active sessions
- **File Persistence**: Durable storage survives restarts
- **Export/Import**: Backup and restore sessions
- **Generic Design**: Swap storage backends via traits

### Session Management

```rust
// List all sessions
let sessions = client.storage().list_sessions().await?;

// Load a previous session
let state = client.storage().load_session("my-app").await?;

// Export sessions for backup
export_sessions(&client, "/path/to/backup").await?;

// Import sessions from backup
import_sessions(&mut client, "/path/to/backup").await?;
```

### Custom Storage Implementation

Implement the `SessionStorage` trait for custom backends:

```rust
use akash_deploy_rs::storage::SessionStorage;
use async_trait::async_trait;

struct DatabaseStorage {
    pool: sqlx::PgPool,
}

#[async_trait]
impl SessionStorage for DatabaseStorage {
    async fn save_session(&mut self, session: &DeploymentState) -> Result<(), DeployError> {
        sqlx::query!("INSERT INTO sessions (id, data) VALUES ($1, $2)")
            .bind(&session.session_id)
            .bind(serde_json::to_value(session)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn load_session(&self, session_id: &str) -> Result<Option<DeploymentState>, DeployError> {
        let row = sqlx::query!("SELECT data FROM sessions WHERE id = $1", session_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(|r| serde_json::from_value(r.data).unwrap()))
    }

    // ... implement other methods
}

// Use custom storage
let client = AkashClient::with_storage(
    layer_climb_client,
    DatabaseStorage { pool },
    address
);
```

---

## Testing

| Command | What it runs | Requires |
|---------|-------------|----------|
| `just test` | All tests (unit + e2e) | Go toolchain |
| `just test-unit` | Unit tests only (`cargo test`) | — |
| `just test-verbose` | Unit tests with stdout (`--nocapture`) | — |
| `just test-e2e` | E2E: Rust manifest/JWT vs Go provider validation | Go toolchain |
| `just test-jwt` | JWT signing verified by Go `AuthProcess()` | Go toolchain |
| `just test-manifest` | Manifest hash verified by Go `Manifest.Version` | Go toolchain |
| `just test-one <file>` | Single SDL through provider validation | Go toolchain |
| `just test-live` | Full deployment on live Akash network (`examples/deploy.rs`) | `TEST_MNEMONIC` |
| `just coverage` | Unit tests with coverage report (via `cargo-tarpaulin`) | `cargo-tarpaulin` |

### Unit test modules

| Module | Source | Covers |
|--------|--------|--------|
| `manifest::manifest` | `src/manifest/manifest.rs` | SDL parsing, resource types, size parsing, GPU attributes |
| `manifest::canonical` | `src/manifest/canonical.rs` | Deterministic JSON serialization, key sorting |
| `sdl::groupspec` | `src/sdl/groupspec.rs` | GroupSpec construction, endpoints, pricing, multi-service |
| `sdl::sdl` | `src/sdl/sdl.rs` | SDL validation |
| `sdl::template` | `src/sdl/template.rs` | Variable extraction, substitution, defaults |
| `auth::jwt` | `src/auth/jwt.rs` | Claims, ES256K signing, base64url, expiry |
| `auth::certificate` | `src/auth/certificate.rs` | TLS cert generation, key extraction |
| `workflow` | `src/workflow.rs` | State machine steps, mock backend, error paths |
| `state` | `src/state.rs` | State transitions, serialization |
| `types` | `src/types.rs` | Wire format golden tests, boundary conditions |
| `store` | `src/store/` | File-backed storage, session persistence |
| `template_tests` | `tests/template_tests.rs` | Integration: full SDL template processing |
| `test_client_live` | `tests/test_client_live.rs` | Live network: balance query, full deployment workflow |

### Environment for live tests

Copy `tests/.env.example` to `tests/.env`:

```bash
TEST_MNEMONIC=your twelve word mnemonic phrase here
TEST_RPC_ENDPOINT=https://rpc.akashnet.net:443     # optional, has default
TEST_GRPC_ENDPOINT=https://grpc.akashnet.net:443    # optional, has default
```

## Live E2E Demo

We can flex the client integration by testing deploying a mimimal instance to the live akash network. To perform this test:

```bash
just demo
```

---

## Development with Agents

This repository includes a specialized Claude skill that provides deep expertise in Akash manifest serialization and provider validation.

### Installing the Skill

The `akash-manifest-spec` skill contains:

- 7 critical serialization rules for manifest generation
- Provider validation procedures using actual Go code
- Debugging decision trees for hash mismatches
- Task-specific implementation checklists

**To install:**

```bash
# Clone the skill to your Claude skills directory
git clone https://github.com/permissionlessweb/akash-deploy-rs.git
ln -s "$(pwd)/akash-deploy-rs/.claude/skills/akash-manifest-spec" ~/.claude/skills/

# Or copy it directly
cp -r .claude/skills/akash-manifest-spec ~/.claude/skills/
```

**When to use:**

The skill activates automatically when you mention:

- "manifest serialization"
- "provider validation"
- "hash mismatch"
- "canonical JSON"
- Akash deployment debugging

It provides structured guidance for:

- Implementing new manifest features while maintaining provider compatibility
- Debugging manifest hash mismatches with actual provider validation code
- Understanding the 7 critical rules (camelCase, null arrays, string numbers, sorting)
- Verifying Rust output matches Go provider expectations byte-for-byte

### Manifest Validation Testing

The skill references the integration test suite in `tests/`:

```bash
cd tests
just test  # Run all SDL test cases through provider validation
```

This validates that your Rust code produces **identical** output to Go providers, ensuring deployments will succeed.

---

## TODO

- [ ] Add more SDL parsing examples
- [ ] Implement Storage Write And Load To File For Deployment Instances
- [ ] Document AkashBackend trait methods in detail
