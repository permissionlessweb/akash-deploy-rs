# mTLS Authentication (Legacy)

Mutual TLS certificate-based authentication for Akash provider communication.

## Overview

mTLS (Mutual TLS) was the original authentication method for Akash provider communication. While still supported, JWT authentication is now preferred.

## How mTLS Works

```
1. Client generates X.509 certificate
2. Client broadcasts certificate to blockchain
3. Provider verifies certificate against on-chain record
4. Both client and provider authenticate each other
```

## Certificate Creation

### CLI

```bash
# Generate and broadcast certificate
akash tx cert create client --from wallet
```

This generates:
- Client certificate (public)
- Client private key (kept local)
- Broadcasts certificate hash to blockchain

### TypeScript SDK

```typescript
import { certificateManager } from "@akashnetwork/akashjs/build/certificates";

// Generate certificate
const cert = await certificateManager.createCertificate(address);

// cert contains:
// - cert: X.509 certificate (PEM)
// - privateKey: Private key (PEM)
// - publicKey: Public key (PEM)
```

### Broadcast Certificate

```typescript
import { MsgCreateCertificate } from "@akashnetwork/akash-api/akash/cert/v1beta3";

const msg = {
  typeUrl: "/akash.cert.v1beta3.MsgCreateCertificate",
  value: {
    owner: address,
    cert: Buffer.from(cert.cert).toString("base64"),
    pubkey: Buffer.from(cert.publicKey).toString("base64")
  }
};

await client.signAndBroadcast(address, [msg], "auto");
```

## Certificate Storage

### CLI

Certificates stored in `~/.akash/` directory.

### Application

Store securely:

```typescript
// Save to secure storage
const certData = {
  cert: cert.cert,
  privateKey: cert.privateKey,
  publicKey: cert.publicKey,
  address: address,
  createdAt: new Date().toISOString()
};

// Encrypt before persisting
```

## Using Certificates

### Provider Communication

```typescript
import https from "https";

const agent = new https.Agent({
  cert: certPem,
  key: privateKeyPem,
  rejectUnauthorized: false  // Provider uses self-signed certs
});

const response = await fetch(providerUrl, {
  agent,
  method: "PUT",
  body: JSON.stringify(manifest)
});
```

### CLI Provider Operations

Certificate is used automatically:

```bash
akash provider send-manifest deploy.yaml \
  --dseq <DSEQ> \
  --provider <PROVIDER> \
  --from wallet
```

## Certificate Lifecycle

| Operation | Command |
|-----------|---------|
| Create | `akash tx cert create client --from wallet` |
| Query | `akash query cert list --owner <address>` |
| Revoke | `akash tx cert revoke --from wallet` |

### Certificate States

```
Active → Revoked
```

Only one active certificate per address.

### Renewing Certificates

```bash
# Revoke old
akash tx cert revoke --from wallet

# Create new
akash tx cert create client --from wallet
```

## Query Certificates

### CLI

```bash
akash query cert list --owner $(akash keys show wallet -a)
```

### REST API

```bash
curl "https://api.akashnet.net/akash/cert/v1beta3/certificates/list?filter.owner=akash1..."
```

## Troubleshooting

### Certificate Mismatch

```
Error: certificate verification failed
```

**Cause:** Local certificate doesn't match on-chain record.

**Solution:** Revoke and recreate certificate.

### Expired Certificate

```
Error: certificate expired
```

**Solution:** Revoke old certificate and create new one.

### Provider Rejection

```
Error: provider rejected manifest
```

**Cause:** Certificate issue or manifest mismatch.

**Solution:**
1. Verify certificate is active on-chain
2. Check manifest matches deployment

## Migration to JWT

For new integrations, prefer JWT authentication:

- Simpler setup (no certificate management)
- Works with Console API
- Better for web applications
- No on-chain certificate needed

See **@jwt-auth.md** for JWT setup.

## When to Use mTLS

| Scenario | Recommended |
|----------|-------------|
| New projects | JWT |
| CLI usage | mTLS (automatic) |
| Existing integrations | mTLS (continue) |
| Web applications | JWT |
| Provider development | mTLS |
