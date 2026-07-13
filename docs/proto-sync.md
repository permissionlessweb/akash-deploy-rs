# Proto sync: chain-sdk → akash-deploy-rs → o-line

## Why this exists

`akash-deploy-rs` is the Rust gateway for **real** Akash rent/deploy workflows used by o-line (sentry/RPC arrays, etc.).  
Types in `src/gen/` must match the **live chain-sdk** packages the network actually runs.

Previously:

| Layer | State |
|-------|--------|
| `src/gen/*.rs` | Full node + provider types **checked in** |
| `proto/akash/` | Only **provider** subset (17 files) — node sources missing |
| Result | `just gen-proto` would **drop** deployment/market types and break the client |

That made orchestration tests (o-line `testnet_deploy`, live client workflow) fragile after Akash version bumps.

## Source of truth

```
crates/chain-sdk/                    ← pin / bump this first
  proto/node/akash/**                chain modules (deployment, market, escrow, …)
  proto/provider/akash/**            manifest, inventory, provider lease/status

crates/akash-deploy-rs/
  proto/akash/**                     synced merge of node + provider (190 .proto)
  proto/rust-vendored/**             cosmos / ibc / gogo / amino (include-only)
  proto/vendor/k8s.io/**             go mod vendor — Quantity for inventory/status
  proto/console/**                   Console API (Zod → proto; separate path)
  proto/src/main.rs                  prost-gen binary (`just gen-proto`)
  src/gen/**                         generated Rust (prost + tonic)
```

### What we deliberately do **not** overwrite

- **k8s** — still `just modvendor` (`go.mod` + `vendor.go` → `proto/vendor/`)
- **rust-vendored** — cosmos/ibc includes; refresh only when cosmos-sdk/ibc options break compile
- **console** — Zod generator + `just gen-console`; hand-written `mod console` block in `src/gen/mod.rs`

## Operator workflow (after chain-sdk bump)

```bash
cd crates/akash-deploy-rs

# 1) Pull/pin chain-sdk (sibling checkout under crates/)
# 2) Sync + k8s vendor + prost in one shot:
just gen-proto-fresh

# Or stepwise:
just sync-protos              # CHAIN_SDK_DIR=… if not sibling
just modvendor
just gen-proto
just gen-console              # if console schemas changed
just py-gen                   # optional Python

# 3) Sanity
cargo chec
just test-unit
just test-e2e                 # Go provider manifest hash parity
```

CI drift gate:

```bash
just sync-protos-check
```

Pin file: `proto/CHAIN_SDK_PIN` (git sha + describe of last sync).

## How prost-gen works (keep this)

`proto/src/main.rs` (`just gen-proto`):

1. Walk `proto/**/*.proto` **except** `vendor`, `rust-vendored`, `console`, `src`, `target`
2. Include paths: `proto/`, plus those excluded dirs (for imports only)
3. prost + tonic-prost-build → `src/gen/`
4. Rewrite `src/gen/mod.rs` module tree; preserve hand-written section after sentinel
5. Skip `console.*` files in auto tree (owned by hand-written console block)

## Client package versions (orchestration)

`src/client.rs` currently targets:

| Domain | Rust path | Role |
|--------|-----------|------|
| Create/close deployment msgs | `deployment::v1` | Msg type URLs for tx |
| GroupSpec / resources | `deployment::v1beta4` | SDL → group encoding |
| Market query / bids / leases | `market::v1beta5` | Bid selection, lease status |
| Provider on-chain | `provider::v1beta4` | Provider queries |
| Provider RPC / inventory | `provider::v1`, `inventory::v1`, `manifest::v2beta3` | Lease logs, status |

When chain-sdk renames the **active** deployment/market package, update these imports **after** `just gen-proto-fresh`, then re-run unit + e2e + live tests.

## o-line testing suite map (rent workflow)

| Test | What it proves | Needs |
|------|----------------|-------|
| `akash-deploy-rs` unit | SDL, manifest hash, type encode | regen protos |
| `akash-deploy-rs` `tests/` e2e | Rust manifest vs Go provider | gen + Go tools |
| `test_client_live.rs` | Real create → bid → lease → close | funded account + correct type_urls |
| `o-line/tests/testnet_deploy.rs` | OLineDeployer Phase A on local Akash | ict-rs Akash + localterp + matching protos |
| `o-line` sentry SDL templates | Render vars for omnibus sentries | independent of protos; deploy uses client |

**Sentry node path (next product work):** after protos are green,

1. `just test-unit` / `just test-e2e` in akash-deploy-rs  
2. o-line local: `just test testnet deploy` (or un-ignore `test_testnet_deploy_akash`)  
3. SDL: nginx LB + sentries (`templates/sdls`, `testnet-lb.yml` pattern)  
4. Live: `DeploymentWorkflow` / `OLineDeployer` against akashnet or sandbox  

Do **not** re-mock rent workflow — protos + Go provider validation are the real gate.

## Maintenance notes

- After regenerating, if `cargo chec` fails on missing/renamed fields in `client.rs`, that is expected: chain-sdk bump changed the wire format — fix call sites, don’t re-vendor old protos.
- If compile fails on `cosmos_proto` options (`message_added_in`), refresh `proto/rust-vendored/cosmos_proto/cosmos.proto` from `cosmos-proto` matching chain-sdk’s go.mod (`v1.0.0-beta.5` as of go/sdl/v0.4.1).
- Prefer sibling `crates/chain-sdk` over random GitHub clones so o-line + deploy-rs + chain-sdk stay one monorepo pin.
