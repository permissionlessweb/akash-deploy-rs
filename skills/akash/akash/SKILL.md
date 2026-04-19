---
name: akash
description: >
  Comprehensive Akash Network skill covering SDL generation, CLI deployments,
  Console API (21 proto services), manifest serialization (7 critical rules for
  byte-for-byte Go compatibility), akash-deploy-rs Rust crate (AkashBackend trait,
  AkashClient, log streaming, Python bindings, deployment store), o-line CLI
  (parallel validator deployment, DNS KeyStore, MinIO-IPFS sites, SSH node mgmt),
  TypeScript/Go SDKs, provider setup, and validator operations.
  Use for: "deploy to Akash", "generate SDL", "Akash provider", "Akash CLI",
  "Akash SDK", "manifest hash", "akash-deploy-rs", "o-line", "oline",
  "console API proto", "deployment workflow", "provider log streaming",
  or "Akash validator".
---

# Akash Network

Unified skill for the Akash decentralized cloud — SDL authoring, deployment orchestration, manifest serialization, and node operations.

## Critical Rules

**NEVER use `:latest` or omit image tags.** Always specify explicit versions.

**Manifest JSON must match Go provider output byte-for-byte.** See `references/manifest-spec.md` for the 7 rules.

## Quick SDL Template

```yaml
version: "2.0"
services:
  web:
    image: nginx:1.25.3
    expose:
      - port: 80
        as: 80
        to:
          - global: true
profiles:
  compute:
    web:
      resources:
        cpu:
          units: 0.5
        memory:
          size: 512Mi
        storage:
          size: 1Gi
  placement:
    dcloud:
      pricing:
        web:
          denom: uakt
          amount: 1000
deployment:
  web:
    dcloud:
      profile: web
      count: 1
```

## Skill Contents

### SDL Configuration
- `rules/sdl/schema-overview.md` — Version requirements, structure
- `rules/sdl/services.md` — Image, expose, env, credentials
- `rules/sdl/compute-resources.md` — CPU, memory, storage, GPU
- `rules/sdl/placement-pricing.md` — Provider selection, pricing (uakt/USDC)
- `rules/sdl/deployment.md` — Service-to-profile mapping
- `rules/sdl/endpoints.md` — IP endpoint config (v2.1)
- `rules/sdl/validation-rules.md` — All constraints
- `rules/sdl/examples/` — web-app, wordpress-db, gpu-workload, ip-lease

### Deployment Methods
- `rules/deploy/overview.md` — Comparison of deployment options
- `rules/deploy/cli/` — Akash CLI install, wallet, commands, lifecycle, leases
- `rules/deploy/console-api/` — Console API auth, endpoints, managed wallet
- `rules/deploy/certificates/` — JWT and mTLS authentication

### akash-deploy-rs Crate
- `references/akash-deploy-rs.md` — **Read this** for crate architecture, AkashBackend trait, AkashClient, 21 Console API proto services, log streaming, Python bindings, deployment store, session management, and feature flags

### o-line CLI
- `references/oline-cli.md` — **Read this** for o-line commands, parallel deployment workflow, DNS KeyStore, MinIO-IPFS site hosting, SSH node management, snapshot distribution

### Manifest Serialization
- `references/manifest-spec.md` — **Read this** for the 7 critical rules, field renames, debugging decision tree, hash computation
- `references/quick-reference.md` — Cheat sheet, type conversions, defaults
- `references/validation.md` — Testing procedures, Go provider validation
- `references/checklists.md` — Task-specific implementation checklists
- `references/examples.md` — Complete SDL → Manifest golden examples

### SDK
- `rules/sdk/overview.md` — SDK comparison
- `rules/sdk/typescript/` — TypeScript (install, chain-node, chain-web, provider)
- `rules/sdk/go/` — Go (install, client setup)

### Infrastructure
- `rules/provider/` — Provider setup, config (attributes, pricing, bid engine), operations
- `rules/node/` — Full node setup, state sync, validator operations
- `rules/authz/` — Fee grants and deployment authorization

### Reference
- `rules/reference/storage-classes.md` — beta2, beta3, ram
- `rules/reference/gpu-models.md` — Supported NVIDIA GPUs
- `rules/reference/ibc-denoms.md` — Payment denominations
- `rules/reference/rpc-endpoints.md` — Public RPC endpoints
- `rules/terminology.md` — Key terms (lease, bid, dseq, gseq, oseq)
- `rules/pricing.md` — Payment with uakt, USDC, IBC denoms
