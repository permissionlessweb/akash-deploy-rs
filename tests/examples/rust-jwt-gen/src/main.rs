// Integration test for JWT generation AND manifest hashing.
//
// Uses the ACTUAL Rust engine code (ManifestBuilder, to_canonical_json)
// to generate JWTs and manifest fixtures, then outputs them for the
// Go verifier to validate against the actual provider logic.
//
// Usage:
//   cargo run -- <sdl_file> <output_dir>
//
// Outputs to stdout:
//   JWT=<token>
//   PUBKEY=<hex>
//   ISSUER=<bech32>
//   MANIFEST_HASH=<hex>
//
// Writes to output_dir:
//   manifest.json       - Rust-generated manifest JSON
//   manifest-hash.txt   - Rust-computed SHA256 hash
//   jwt.txt             - JWT token
//   pubkey.txt          - Public key hex

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ho_std::keys::cosmos::CosmosMnemonic;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

// Import manifest builder and canonical JSON from akash-deploy library
use akash_deploy::{to_canonical_json, ManifestBuilder};

#[derive(Debug, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtLeases {
    access: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    iss: String,
    iat: i64,
    exp: i64,
    nbf: i64,
    version: String,
    leases: JwtLeases,
}

fn main() -> Result<()> {
    let sdl_file = std::env::args().nth(1).expect("Usage: rust-jwt-gen <sdl_file> <output_dir>");
    let output_dir = std::env::args().nth(2).expect("Usage: rust-jwt-gen <sdl_file> <output_dir>");

    // ── JWT GENERATION ──────────────────────────────────────────────

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let cosmos_mnemonic = CosmosMnemonic::from_phrase(mnemonic)?;
    let keypair = cosmos_mnemonic.derive_keypair(0)?;
    let address = keypair.address("akash")?;
    let pubkey = keypair.public_key();

    let header = JwtHeader {
        alg: "ES256K".to_string(),
        typ: "JWT".to_string(),
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs() as i64;

    let claims = JwtClaims {
        iss: address.clone(),
        iat: now,
        exp: now + 900,
        nbf: now,
        version: "v1".to_string(),
        leases: JwtLeases {
            access: "full".to_string(),
        },
    };

    let header_json = serde_json::to_string(&header)?;
    let claims_json = serde_json::to_string(&claims)?;

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());

    let signing_input = format!("{}.{}", header_b64, claims_b64);
    let signature = keypair.sign_jwt_es256k(signing_input.as_bytes())?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

    let jwt = format!("{}.{}", signing_input, signature_b64);
    let pubkey_hex = hex::encode(pubkey);

    // ── MANIFEST GENERATION ─────────────────────────────────────────

    let sdl_yaml = std::fs::read_to_string(&sdl_file)
        .map_err(|e| anyhow::anyhow!("Failed to read SDL {}: {}", sdl_file, e))?;

    // Use ACTUAL ManifestBuilder from our Rust engine
    let builder = ManifestBuilder::new(&address, 1);
    let manifest_groups = builder.build_from_sdl(&sdl_yaml)?;

    // Use ACTUAL to_canonical_json from our Rust engine (sorted keys + normalization)
    let canonical_json = to_canonical_json(&manifest_groups)?;

    // Compute SHA256 hash (same as deployment_builder does)
    let mut hasher = Sha256::new();
    hasher.update(canonical_json.as_bytes());
    let hash = hasher.finalize();
    let manifest_hash = hex::encode(hash);

    // Pretty-printed manifest JSON for the fixture file
    let manifest_json = serde_json::to_string_pretty(&manifest_groups)?;

    // ── WRITE FIXTURES ──────────────────────────────────────────────

    std::fs::create_dir_all(&output_dir)?;
    std::fs::write(format!("{}/jwt.txt", output_dir), &jwt)?;
    std::fs::write(format!("{}/pubkey.txt", output_dir), &pubkey_hex)?;
    std::fs::write(format!("{}/manifest.json", output_dir), &manifest_json)?;
    std::fs::write(format!("{}/manifest-hash.txt", output_dir), &manifest_hash)?;

    // ── STDOUT FOR TEST SCRIPT ──────────────────────────────────────

    println!("JWT={}", jwt);
    println!("PUBKEY={}", pubkey_hex);
    println!("ISSUER={}", address);
    println!("MANIFEST_HASH={}", manifest_hash);

    eprintln!("  Wrote: {}/jwt.txt", output_dir);
    eprintln!("  Wrote: {}/pubkey.txt", output_dir);
    eprintln!("  Wrote: {}/manifest.json", output_dir);
    eprintln!("  Wrote: {}/manifest-hash.txt", output_dir);
    eprintln!("  Canonical JSON: {}", canonical_json);

    Ok(())
}
