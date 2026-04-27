# o-line CLI Reference

Deployment orchestrator for Akash validator sentry arrays, websites, and DNS. Built on akash-deploy-rs.

References/Documentation Workflow
Tools:
- zed-to-proto
- prost-to-pyo3
- examples embedded in binary
- cli-reference
- dedicated skill
- qmd
- githem
- trailmark


## Commands

| Command | Purpose |
|---------|---------|
| `oline encrypt` | Encrypt mnemonic → `.env` |
| `oline endpoints` | Probe RPC/gRPC, save fastest to `.env` |
| `oline deploy` | Full parallel deployment (phases A→B→C→E) |
| `oline deploy --sdl <path>` | Deploy raw SDL (create → list bids) |
| `oline deploy --sdl <path> --select <DSEQ> <PROVIDER>` | Select provider for pending deployment |
| `oline sdl` | Render SDL templates without deploying |
| `oline init` | Collect config → `deploy-config.json` |
| `oline manage sync\|logs\|status\|close\|drain\|tui` | Deployment lifecycle |
| `oline dns update\|list\|set-txt\|set-cname\|set-a\|delete` | Cloudflare DNS |
| `oline dns keys add\|list\|remove\|resolve` | Encrypted DNS credential store |
| `oline bootstrap` | Bootstrap private validator + snapshot |
| `oline sites deploy\|upload\|publish\|list` | MinIO-IPFS static websites |
| `oline refresh run\|add\|list\|status\|remove` | SSH-based node management |
| `oline node deploy\|status\|close` | Dedicated Akash full node |
| `oline firewall` | pfSense SSH key management |
| `oline relayer` | IBC relayer hot-swap and config |
| `oline vpn` | WireGuard VPN on pfSense |
| `oline providers` | Trusted provider management |
| `oline registry` | Embedded OCI container registry |
| `oline testnet-deploy` | Bootstrap fresh testnet on Akash |

## Non-Interactive Mode

Set `OLINE_NON_INTERACTIVE=1` + `OLINE_PASSWORD=<pw>` for unattended operation.

For `deploy --sdl`, also provide `OLINE_MNEMONIC=<words>` or `OLINE_ENCRYPTED_MNEMONIC`.

## Parallel Deployment Workflow

Default strategy using HD-derived child accounts to avoid sequence conflicts:

```
1. FundChildAccounts    — Derive N children at m/44'/118'/0'/0/{i}, fund from master
2. DeployAllUnits       — Concurrent MsgCreateDeployment (one per child)
3. SelectAllProviders   — Interactive provider selection per unit
4. UpdateAllDns         — Parallel Cloudflare CNAME/A record updates
5. WaitSnapshotReady    — Poll Phase A snapshot node until synced
6. DistributeSnapshot   — SSH-stream archive from snapshot to B/C/E nodes
7. SignalAllNodes       — Push TLS certs + fire start on all units
8. InjectPeers          — SSH-push peer env vars to B/C/E
9. WaitAllPeers         — Poll all nodes until peer connected
```

Phases: A (SpecialTeams: snapshot+seed+minio), B (Tackles), C (Forwards), E (Relayer)

Funding method env: `OLINE_FUNDING_METHOD=hd:4:5000000` or `direct` or `master`

## DNS KeyStore

Domain-keyed encrypted credentials (AES-256-GCM + Argon2id). Stored at `~/.oline/keys.enc`.

### Credential Resolution Order
1. CLI flags (`--token`, `--zone`) — explicit always wins
2. KeyStore lookup by domain (longest-suffix match)
3. Env vars (`OLINE_CF_API_TOKEN`, `OLINE_CF_ZONE_ID`)

### Usage

```bash
# Add credentials for a domain
oline dns keys add permissionless.money \
  --domains "permissionless.money,*.permissionless.money" \
  --cf-token "<token>" --cf-zone "<zone-id>"

# Test which key matches
oline dns keys resolve permissionless.money

# Auto-resolves credentials:
oline dns set-cname permissionless.money target.provider.com
oline dns list --name permissionless.money
oline dns set-txt _dnslink.permissionless.money "dnslink=/ipfs/bafybei..."
```

Wildcards supported: `*.terp.network` matches `www.terp.network`, `api.terp.network`.

## MinIO-IPFS Static Website Hosting

Deploy a MinIO-IPFS container to Akash, upload static files, publish via DNSLink.

### Container Architecture

- **Nginx** (:80) — host-based routing to gateway/s3/console subdomains
- **MinIO S3** (:9000) — object storage with AWS Sig V4 auth
- **MinIO Console** (:9001) — web UI for bucket management
- **IPFS Gateway** (:8081) — browse content by CID
- **IPFS Daemon** (:4001) — P2P swarm for DHT
- **Autopin Cron** — scans bucket every N seconds, pins matching files to IPFS

### Workflow

```bash
oline sites deploy                        # Deploy container, set DNS CNAMEs
oline sites upload mysite.com ./dist/     # S3 PUT files (AWS Sig V4 signed)
# Wait for autopin to pin files to IPFS...
oline sites publish mysite.com bafybei... # Set DNSLink TXT + CNAME to cloudflare-ipfs.com
```

Site records stored encrypted at `$SECRETS_PATH/sites.enc`.

## SSH Node Management

### Refresh (post-deploy updates)

```bash
oline refresh run "Phase A - Snapshot"    # Push env vars + run command on node
oline refresh add                         # Register node in encrypted store
oline refresh list                        # Show all saved nodes
oline refresh status                      # Poll RPC health for all nodes
```

### Bootstrap (private validator)

```bash
oline bootstrap                           # Interactive: SSH host, snapshot URL, peers
oline bootstrap --local                   # Local mode (no SSH)
oline bootstrap -y --host 1.2.3.4        # Non-interactive with flags
```

Snapshot resolution: `OLINE_SNAP_FULL_URL` > auto-resolve from metadata > manual input.

## Provider Log Streaming

```bash
oline manage logs <dseq> [--service <name>] [--tail <n>]
```

Uses `akash-deploy-rs::WsLogStream` — WebSocket to `wss://<provider>/lease/<dseq>/<gseq>/<oseq>/logs`.

## Configuration

Key env vars:
- `OLINE_PASSWORD` — encryption password for config, keys, sessions
- `OLINE_ENCRYPTED_MNEMONIC` / `OLINE_MNEMONIC` — wallet seed
- `OLINE_CF_API_TOKEN` / `OLINE_CF_ZONE_ID` — Cloudflare (or use KeyStore)
- `OLINE_RPC_ENDPOINT` / `OLINE_GRPC_ENDPOINT` — Akash chain endpoints
- `OLINE_CHAIN_ID` — chain ID (e.g. `akashnet-2`)
- `OLINE_NON_INTERACTIVE` — skip all prompts
- `OLINE_FUNDING_METHOD` — `master` / `direct` / `hd:N:AMOUNT`

Regenerate full CLI reference: `OLINE_BIN=./target/release/oline bash scripts/docs/gen-docs.sh`
