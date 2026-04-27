# akash-deploy-rs Crate Reference

Standalone, trait-based Akash deployment workflow engine. No framework coupling.

## Architecture

```
AkashBackend (trait)      — chain queries, signing, provider communication
  └─ AkashClient (impl)  — default: gRPC, HD accounts, JWT, reqwest HTTP
DeploymentWorkflow        — state machine engine
DeploymentStore (trait)   — deployment record persistence
SessionStorage (trait)    — sessions, certs, provider cache
```

### State Machine Steps

```
Init → CheckBmeStatus → MintAct → CheckBalance → EnsureAuth
  → CreateDeployment → WaitForBids → SelectProvider
  → CreateLease → SendManifest → WaitForEndpoints → Complete
```

## Features

| Feature | Deps | What it enables |
|---------|------|-----------------|
| `default-client` | layer-climb, reqwest, k256 | AkashClient with gRPC, signing, provider HTTP |
| `file-storage` | tokio/fs, dirs | FileDeploymentStore, FileBackedStorage |
| `sdl-templates` | — | Template variable substitution (`${VAR}`) |
| `log-streaming` | tokio-tungstenite, futures-util | WsLogStream WebSocket log access |
| `rpc` | tonic | gRPC clients for all 21 console services |
| `python` | pyo3, pythonize | PyO3 Python bindings (55 modules) |

## AkashBackend Trait

Core interface — implement to use your own signing/storage/transport.

### Chain Queries
- `query_balance(address, denom)`
- `query_certificate(address)`
- `query_provider_info(provider)` → `ProviderInfo`
- `query_bids(owner, dseq)` → `Vec<Bid>`
- `query_lease(owner, dseq, gseq, oseq, bseq, provider)`
- `query_escrow(owner, dseq)` → `EscrowInfo`
- `query_bme_status()` → `BmeStatus`

### Transactions
- `broadcast_create_deployment(signer, owner, sdl, deposit, denom)`
- `broadcast_create_lease(signer, bid)`
- `broadcast_close_deployment(signer, owner, dseq)`
- `broadcast_deposit(signer, owner, dseq, amount)`
- `broadcast_create_certificate(signer, owner, cert, pubkey)`
- `broadcast_mint_act(signer, owner, amount)`

### Provider Communication
- `generate_jwt(owner)` → JWT string (ES256K)
- `send_manifest(provider_uri, lease, manifest, auth)` — HTTP PUT with retry
- `query_provider_status(provider_uri, lease, auth)` → `ProviderLeaseStatus`

### State Persistence
- `load_state(session_id)` / `save_state(session_id, state)`
- `load_cert_key(owner)` / `save_cert_key(owner, key)` / `delete_cert_key(owner)`
- `load_cached_provider(provider)` / `cache_provider(info)`

## Key Types

```rust
struct LeaseId { owner, dseq, gseq, oseq, provider }
struct ServiceEndpoint { service, uri, port, internal_port }
struct Bid { provider, price, price_denom, resources }
struct ProviderInfo { address, host_uri, email, website, attributes }
enum ProviderAuth { Mtls { cert_pem, key_pem }, Jwt { token } }
struct DeploymentState { session_id, step, owner, dseq, endpoints, lease_id, ... }
enum Step { Init, CheckBalance, CreateDeployment, WaitForBids, SelectProvider, CreateLease, SendManifest, WaitForEndpoints, Complete, Failed }
```

## Log Streaming

Behind `log-streaming` feature. WebSocket connection to provider's lease log endpoint.

```rust
use akash_deploy_rs::{LogStreamConfig, WsLogStream, ProviderAuth};
use futures_util::StreamExt;

let config = LogStreamConfig::new()
    .with_follow(true)
    .with_tail(100)
    .with_service("web");
let auth = ProviderAuth::Jwt { token: jwt };

let mut stream = WsLogStream::connect(&provider_uri, &lease_id, &auth, &config).await?;
while let Some(line) = stream.next().await {
    print!("{}", line?);
}
```

URL format: `wss://<provider>/lease/<dseq>/<gseq>/<oseq>/logs?follow=true&tail=100&service=web`

## Console API Proto Services (21)

Generated from Zod schemas → proto3 → prost/tonic. Access via `gen::console::<module>`.

**Core deployment:**
- `deployment` — List, Get, Create, Update, Close, Deposit, ListWithResources, WeeklyCost
- `lease` — CreateLease, GetLeaseStatus
- `deployment_settings` — Get, Update
- `bid` — ListBids
- `certificate` — CreateCertificate

**Billing & payments:**
- `billing` — GetWallet, GetBalances, SignAndBroadcastTx, GetUsageHistory, StartTrial
- `stripe` — PaymentMethods, ConfirmPayment, ApplyCoupon, GetPrices, UpdateOrganization

**User & auth:**
- `user` — GetCurrentUser, UpdateSettings, CheckUsernameAvailability
- `auth` — ListApiKeys, CreateApiKey, UpdateApiKey, DeleteApiKey

**Analytics:**
- `dashboard` — DashboardData, GraphData, NetworkCapacity, MarketData, BmeDashboardData
- `gpu` — ListGpus, ListGpuModels, GetGpuBreakdown, GetGpuPrices

**Infrastructure:**
- `provider` — ListProviders, GetProvider, ActiveLeasesGraph, GetJwtToken
- `provider_extended` — Auditors, Dashboard, Deployments, Earnings, Regions, Versions, Attributes
- `network` — GetNodes
- `pricing` — GetPricing

**Blockchain:**
- `address` — GetAddress, GetAddressTransactions
- `transaction` — ListTransactions, GetTransactionByHash
- `block` — ListBlocks, GetBlockByHeight, PredictedBlockDate, PredictedDateHeight
- `validator` — ListValidators, GetValidatorByAddress
- `proposal` — ListProposals, GetProposalById
- `template` — ListTemplates, GetTemplate

## Python Bindings

55 PyO3 modules. Build with `just py-build` (requires maturin).

```python
from akash_deploy.console_billing import GetBalancesRequest, GetBalancesResponse
from akash_deploy.console_deployment import CreateDeploymentRequest
from akash_deploy._native import registered_types, encode_message, decode_message

# Encode to protobuf
req = GetBalancesRequest(address="akash1...")
proto_bytes = req.encode()

# Decode from protobuf
resp = GetBalancesResponse.decode(response_bytes)
print(resp.to_json())
```

## Session Management

For parallel deployments using HD-derived accounts.

```
FundingMethod::HdDerived { count: 4, amount_per_child: 5_000_000 }
```

Session lifecycle:
1. Derive N child accounts at BIP44 `m/44'/118'/0'/0/{i}`
2. Fund each from master via `bank_send`
3. Each child deploys one phase (no sequence conflicts)
4. After workflow: `oline manage drain` returns funds to master

Sessions stored at `~/.oline/sessions/<id>/session.json`.

## SDL Template Variables

Templates use `${VAR}` syntax, substituted from env vars + config:

```yaml
services:
  ${SVC_NAME}:
    image: ${IMAGE}
    env:
      - SSH_PUBKEY=${SSH_PUBKEY}
```

Generate with `substitute_template_raw(&template, &vars)`.

## Error Types

```rust
enum DeployError {
    Query(String),           // Chain query failed (recoverable)
    Transaction { code, log }, // Tx failed
    Provider(String),        // Provider comm failed (recoverable)
    Sdl(String),            // Invalid SDL
    Manifest(String),       // Manifest build failed
    InvalidState(String),   // Bad workflow transition
    Storage(String),        // Persistence error
    Certificate(String),    // Cert error
    Jwt(String),            // JWT error
    Timeout(String),        // Timeout (recoverable)
    LogStream(String),      // WebSocket log error (recoverable)
    Template(String),       // Template substitution error
    Signer(String),         // Signing error
}
```
