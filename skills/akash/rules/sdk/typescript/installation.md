# TypeScript SDK Installation

Install and configure the Akash TypeScript SDK for your project.

## Package

```
@akashnetwork/akashjs
```

## Installation

### npm

```bash
npm install @akashnetwork/akashjs
```

### yarn

```bash
yarn add @akashnetwork/akashjs
```

### pnpm

```bash
pnpm add @akashnetwork/akashjs
```

## Dependencies

The SDK depends on CosmJS packages:

```bash
npm install @cosmjs/proto-signing @cosmjs/stargate @cosmjs/crypto
```

## Project Setup

### TypeScript Configuration

Ensure your `tsconfig.json` has appropriate settings:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "esModuleInterop": true,
    "strict": true,
    "skipLibCheck": true,
    "resolveJsonModule": true
  }
}
```

### Node.js Setup

For Node.js projects:

```javascript
// CommonJS
const { DirectSecp256k1HdWallet } = require("@cosmjs/proto-signing");
const { getAkashTypeRegistry } = require("@akashnetwork/akashjs/build/stargate");

// ES Modules
import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { getAkashTypeRegistry } from "@akashnetwork/akashjs/build/stargate";
```

### Browser Setup

For browser applications:

```html
<script type="module">
  import { DirectSecp256k1HdWallet } from "https://esm.sh/@cosmjs/proto-signing";
  import { getAkashTypeRegistry } from "https://esm.sh/@akashnetwork/akashjs/build/stargate";
</script>
```

Or with bundlers (webpack, vite, etc.):

```typescript
import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { getAkashTypeRegistry } from "@akashnetwork/akashjs/build/stargate";
```

## Quick Verification

Test your installation:

```typescript
import { getAkashTypeRegistry } from "@akashnetwork/akashjs/build/stargate";

const registry = getAkashTypeRegistry();
console.log("Akash SDK installed successfully!");
console.log("Registered types:", registry.length);
```

## Available Modules

```typescript
// Stargate client extensions
import { getAkashTypeRegistry } from "@akashnetwork/akashjs/build/stargate";

// Certificate management
import { certificateManager } from "@akashnetwork/akashjs/build/certificates";

// SDL parsing
import { SDL } from "@akashnetwork/akashjs/build/sdl";

// Provider communication
import { sendManifest } from "@akashnetwork/akashjs/build/provider";

// Protobuf types
import { MsgCreateDeployment } from "@akashnetwork/akash-api/akash/deployment/v1beta3";
```

## Environment Setup

### Environment Variables

```bash
# .env file
AKASH_MNEMONIC="your twelve word mnemonic phrase here"
AKASH_RPC_ENDPOINT="https://rpc.akashnet.net:443"
AKASH_CHAIN_ID="akashnet-2"
```

### Loading Environment

```typescript
import dotenv from "dotenv";
dotenv.config();

const MNEMONIC = process.env.AKASH_MNEMONIC!;
const RPC_ENDPOINT = process.env.AKASH_RPC_ENDPOINT || "https://rpc.akashnet.net:443";
const CHAIN_ID = process.env.AKASH_CHAIN_ID || "akashnet-2";
```

## Basic Client Setup

```typescript
import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { SigningStargateClient } from "@cosmjs/stargate";
import { getAkashTypeRegistry } from "@akashnetwork/akashjs/build/stargate";

async function createAkashClient() {
  // Create wallet from mnemonic
  const wallet = await DirectSecp256k1HdWallet.fromMnemonic(MNEMONIC, {
    prefix: "akash"
  });

  // Get account address
  const [account] = await wallet.getAccounts();
  console.log("Address:", account.address);

  // Get Akash type registry
  const registry = getAkashTypeRegistry();

  // Create signing client
  const client = await SigningStargateClient.connectWithSigner(
    RPC_ENDPOINT,
    wallet,
    { registry }
  );

  return { client, wallet, address: account.address };
}
```

## Version Compatibility

| SDK Version | Node.js | CosmJS |
|-------------|---------|--------|
| 0.6.x | 18+ | 0.32.x |
| 0.5.x | 16+ | 0.31.x |

## Troubleshooting

### Module Not Found

```
Error: Cannot find module '@akashnetwork/akashjs/build/stargate'
```

**Solution:** Ensure the package is installed and paths are correct.

### Type Errors

```
Type error: Cannot find type definition
```

**Solution:** Install TypeScript type definitions:

```bash
npm install -D @types/node
```

### Browser Polyfills

For browser environments, you may need polyfills:

```bash
npm install buffer crypto-browserify stream-browserify
```

Configure your bundler to use these polyfills for Node.js modules.

## Next Steps

- **@chain-node-sdk.md** - Using the chain SDK in Node.js
- **@chain-web-sdk.md** - Using the chain SDK in browsers
- **@provider-sdk.md** - Communicating with providers
