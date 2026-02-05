# JWT Verification Tool

**Problem**: Rust client generates JWTs that providers reject with "manifest version validation failed"

**Solution**: Local verification tool that uses the **exact same** ES256K logic as Akash providers

## What This Actually Solves

1. Generate JWT in Rust
2. Verify with Go (same code providers use)

## Quick Start

```bash
# Build verifier
just build

# Run integration test (Rust generates → Go verifies)
just test

# Manual verification
just verify "eyJhbGc..." "02a1b2c3..."
```

## What It Does

- Takes JWT token string
- Takes public key (hex or bech32)
- Verifies using ES256K (secp256k1 + single SHA-256, per RFC 8812)
- Validates all claims (iss, iat, nbf, exp, version, leases)
- Prints clear pass/fail with details

## Usage

### Verify a specific JWT

```bash
./jwt-verify "eyJhbGciOiJFUzI1NksiLCJ0..." "02a1b2c3d4e5f6..."
```

### Integration test (recommended)

```bash
./test.sh
```
