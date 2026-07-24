# SDK Overview

Akash provides official SDKs for programmatic integration with the network.

## Available SDKs

| SDK | Language | Package | Use Case |
|-----|----------|---------|----------|
| **TypeScript** | JS/TS | `@akashnetwork/akashjs` | Web apps, Node.js |
| **Go** | Go | `github.com/akash-network/akash-api` | Backend services |

## SDK Comparison

### TypeScript SDK

Best for:
- Web applications
- Node.js services
- Browser-based dApps
- Frontend integrations

Features:
- Chain interactions (transactions, queries)
- Provider communication
- SDL parsing and validation
- Wallet integration

### Go SDK

Best for:
- Backend services
- Custom tooling
- High-performance applications
- Provider development

Features:
- Full blockchain client
- Direct gRPC access
- Transaction building
- Provider integration

## Quick Start

### TypeScript

```typescript
import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { SigningStargateClient } from "@cosmjs/stargate";
import { getAkashTypeRegistry } from "@akashnetwork/akashjs/build/stargate";

// Create wallet
const wallet = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, {
  prefix: "akash"
});

// Connect to network
const registry = getAkashTypeRegistry();
const client = await SigningStargateClient.connectWithSigner(
  "https://rpc.akashnet.net:443",
  wallet,
  { registry }
);

// Ready to interact with Akash
```

### Go

```go
import (
    "github.com/cosmos/cosmos-sdk/client"
    "github.com/akash-network/akash-api/go/node/client/v1beta3"
)

// Create client context
clientCtx := client.Context{}.
    WithNodeURI("https://rpc.akashnet.net:443").
    WithChainID("akashnet-2")

// Create Akash client
akashClient := v1beta3.NewQueryClient(clientCtx)

// Ready to query Akash
```

## Choosing an SDK

| Scenario | Recommended |
|----------|-------------|
| Building web app | TypeScript |
| Node.js backend | TypeScript |
| Browser dApp | TypeScript |
| Go microservice | Go |
| Custom provider tooling | Go |
| High-throughput service | Go |

## SDK Architecture

```
┌─────────────────────────────────────────┐
│           Your Application              │
├─────────────────────────────────────────┤
│              Akash SDK                  │
│  ┌─────────────┐  ┌─────────────────┐  │
│  │   Chain     │  │    Provider     │  │
│  │   Module    │  │    Module       │  │
│  └─────────────┘  └─────────────────┘  │
├─────────────────────────────────────────┤
│          Cosmos SDK / gRPC             │
├─────────────────────────────────────────┤
│            Akash Network               │
└─────────────────────────────────────────┘
```

## Common Operations

### Both SDKs Support

- Create/close deployments
- Query deployments and leases
- Accept bids
- Manage certificates
- Provider communication

### SDK-Specific Features

**TypeScript:**
- SDL YAML parsing
- Browser wallet integration
- React hooks (community)

**Go:**
- Custom transaction types
- Direct protobuf access
- Provider service integration

## Related Documentation

- **@typescript/** - TypeScript SDK documentation
- **@go/** - Go SDK documentation
