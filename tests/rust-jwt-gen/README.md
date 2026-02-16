# Rust JWT Generation Example

Example showing how to use `JwtAuthClient` to generate provider-compatible JWTs.

## What Your JwtAuthClient Must Implement

For this example to work, your `JwtAuthClient` needs:

```rust
impl JwtAuthClient {
    /// Create a test keypair (for integration tests only)
    pub fn new_test_keypair() -> Result<Self>;

    /// Generate a JWT for manifest submission
    /// Must use ES256K (secp256k1 + single SHA-256)
    pub fn generate_manifest_jwt(&self, manifest_hash: &str) -> Result<String>;

    /// Get the public key bytes (33-byte compressed secp256k1)
    pub fn public_key_bytes(&self) -> Vec<u8>;

    /// Get the bech32 address (akash1...)
    pub fn address(&self) -> String;
}
```

## JWT Requirements

The JWT **must** match what the provider expects:

### Header
```json
{
  "alg": "ES256K",
  "typ": "JWT"
}
```

### Claims
```json
{
  "iss": "akash1...",           // Bech32 address
  "iat": 1705320000,            // IssuedAt (unix timestamp)
  "nbf": 1705320000,            // NotBefore (unix timestamp)
  "exp": 1705320900,            // ExpiresAt (iat + 15 minutes)
  "version": "v1",              // Akash-specific
  "leases": {
    "access": "full"            // or specific lease IDs
  }
}
```

### Signature
- **Algorithm**: ECDSA with secp256k1 curve
- **Hash**: Single SHA-256 (NOT double-SHA256 like Bitcoin)
- **Format**: Standard JWT signature encoding (base64url)

## Common Mistakes

1. **Using double-SHA256** - Bitcoin does this, JWT ES256K does NOT
2. **Wrong key format** - Must be compressed secp256k1 (33 bytes, starts with 0x02 or 0x03)
3. **Missing claims** - Provider requires `version` and `leases` in addition to standard JWT claims
4. **Wrong expiry** - Provider expects 15 minute window, not hours or days
5. **Base64 encoding** - Must use base64url (not standard base64)

## Testing

```bash
# Generate JWT
cargo run

# This outputs:
#   JWT=eyJhbGc...
#   PUBKEY=02a1b2c3...
#   ISSUER=akash1...

# Verify with Go tool
cd ../../
./jwt-verify "eyJhbGc..." "02a1b2c3..."
```

## If You Don't Have JwtAuthClient Yet

Implement it. Don't over-engineer it. Here's the core:

```rust
use k256::ecdsa::{SigningKey, Signature, signature::Signer};
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub struct JwtAuthClient {
    signing_key: SigningKey,
    address: String,
}

impl JwtAuthClient {
    pub fn generate_manifest_jwt(&self, manifest_hash: &str) -> Result<String> {
        let now = chrono::Utc::now().timestamp();

        // Build JWT manually (or use jsonwebtoken crate)
        let header = r#"{"alg":"ES256K","typ":"JWT"}"#;
        let claims = format!(
            r#"{{"iss":"{}","iat":{},"nbf":{},"exp":{},"version":"v1","leases":{{"access":"full"}}}}"#,
            self.address, now, now, now + 900
        );

        let header_b64 = URL_SAFE_NO_PAD.encode(header);
        let claims_b64 = URL_SAFE_NO_PAD.encode(&claims);
        let message = format!("{}.{}", header_b64, claims_b64);

        // Sign with ECDSA
        let hash = Sha256::digest(message.as_bytes());
        let signature: Signature = self.signing_key.sign(&hash);
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(format!("{}.{}", message, sig_b64))
    }
}
```

That's it. No factories, no traits, no bullshit. Just sign the damn thing.
