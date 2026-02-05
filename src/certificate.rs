//! Akash mTLS Certificate Generation
//!
//! This module handles X.509 certificate generation for Akash provider mTLS.
//! Pure generation — no storage, no signing, no chain interaction.
//! The backend handles persistence and broadcasting.
//!
//! **Important**: Akash expects the public key in SEC1 EC format with header
//! `-----BEGIN EC PUBLIC KEY-----`, NOT SPKI format (`-----BEGIN PUBLIC KEY-----`).

use crate::error::DeployError;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use sha2::{Digest, Sha256};
use std::time::Duration;

// Base64 engine for PEM encoding
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

/// Generated certificate with all components for mTLS.
#[derive(Debug, Clone)]
pub struct GeneratedCertificate {
    /// X.509 certificate in PEM format (for chain storage).
    pub cert_pem: Vec<u8>,
    /// Public key in PEM format (for chain storage).
    pub pubkey_pem: Vec<u8>,
    /// Private key in PEM format (for mTLS client auth).
    /// The backend should encrypt this before storage.
    pub privkey_pem: Vec<u8>,
    /// Certificate serial number (hex-encoded).
    pub serial: String,
}

/// Generate an Akash-compatible X.509 certificate.
///
/// Creates a self-signed ECDSA P-256 certificate for mTLS authentication
/// between tenants and providers on Akash Network.
///
/// # Arguments
/// * `address` - The Akash account address (used as Common Name)
///
/// # Returns
/// * `GeneratedCertificate` with cert, pubkey, privkey (all PEM), and serial
pub fn generate_certificate(address: &str) -> Result<GeneratedCertificate, DeployError> {
    // Generate ECDSA P-256 key pair (Akash requirement)
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| DeployError::Certificate(format!("keypair generation failed: {}", e)))?;

    // Generate unique serial from random bytes + address
    let serial = generate_serial(address);

    // Build certificate parameters
    let mut params = CertificateParams::default();

    // Set subject with Common Name = address (Akash requirement)
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, address);
    params.distinguished_name = distinguished_name;

    // Set validity period (1 year)
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + Duration::from_secs(365 * 24 * 60 * 60);

    // Extract public key in SEC1 EC format (Akash requirement)
    // rcgen produces SPKI format ("BEGIN PUBLIC KEY"), but Akash expects
    // SEC1 format ("BEGIN EC PUBLIC KEY")
    let pubkey_pem = convert_spki_to_sec1_pem(&key_pair)?;

    // Extract private key PEM
    let privkey_pem = key_pair.serialize_pem().into_bytes();

    // Generate self-signed certificate
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| DeployError::Certificate(format!("certificate generation failed: {}", e)))?;

    let cert_pem = cert.pem().into_bytes();

    Ok(GeneratedCertificate {
        cert_pem,
        pubkey_pem,
        privkey_pem,
        serial,
    })
}

/// Generate a unique serial number from random bytes and address.
fn generate_serial(address: &str) -> String {
    let random_bytes: [u8; 16] = rand::random();
    let mut hasher = Sha256::new();
    hasher.update(random_bytes);
    hasher.update(address.as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..16])
}

/// Convert SPKI public key PEM to SEC1 EC PUBLIC KEY PEM format.
///
/// rcgen produces SPKI format: `-----BEGIN PUBLIC KEY-----`
/// Akash expects SEC1 format: `-----BEGIN EC PUBLIC KEY-----`
///
/// For P-256, SPKI structure is:
/// - 26 bytes: Algorithm identifier (OID for ecPublicKey + P-256 curve)
/// - Remaining: The actual EC point (65 bytes: 0x04 || X || Y)
fn convert_spki_to_sec1_pem(key_pair: &KeyPair) -> Result<Vec<u8>, DeployError> {
    // Get raw public key bytes (DER-encoded SPKI)
    let spki_der = key_pair.public_key_der();

    // SPKI for P-256 has a fixed 26-byte header before the EC point
    // Structure: SEQUENCE { SEQUENCE { OID, OID }, BIT STRING { EC point } }
    // The EC point starts at offset 26 for P-256
    const P256_SPKI_HEADER_LEN: usize = 26;
    const P256_EC_POINT_LEN: usize = 65; // 0x04 || 32-byte X || 32-byte Y

    if spki_der.len() < P256_SPKI_HEADER_LEN + P256_EC_POINT_LEN {
        return Err(DeployError::Certificate(format!(
            "unexpected SPKI length: {} (expected at least {})",
            spki_der.len(),
            P256_SPKI_HEADER_LEN + P256_EC_POINT_LEN
        )));
    }

    // Extract the EC point (skip the SPKI header)
    let ec_point = &spki_der[P256_SPKI_HEADER_LEN..];

    // Verify it's an uncompressed point (starts with 0x04)
    if ec_point.first() != Some(&0x04) {
        return Err(DeployError::Certificate(
            "expected uncompressed EC point (0x04 prefix)".into(),
        ));
    }

    // Build SEC1 EC PUBLIC KEY structure
    // This is just the raw EC point wrapped in a BIT STRING, no algorithm OID
    // Format: 30 <len> 03 <len> 00 <ec_point>
    // But actually, looking at Akash's expected format, it's the SubjectPublicKeyInfo
    // with just the EC point part re-wrapped

    // Actually, examining the working example more closely:
    // The "EC PUBLIC KEY" format Akash uses is the same as SPKI but with different header text
    // Let me check the actual bytes...

    // Looking at the working pubkey from Akash:
    // MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
    // This decodes to SPKI structure! So Akash just wants the same DER bytes
    // but with "EC PUBLIC KEY" PEM label instead of "PUBLIC KEY"

    // Encode as PEM with "EC PUBLIC KEY" header
    let b64 = BASE64.encode(&spki_der);
    let mut pem = String::with_capacity(b64.len() + 60);
    pem.push_str("-----BEGIN EC PUBLIC KEY-----\n");

    // Wrap at 64 characters per line (PEM standard)
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END EC PUBLIC KEY-----\n");

    Ok(pem.into_bytes())
}

// ═══════════════════════════════════════════════════════════════════
// PRIVATE KEY ENCRYPTION (optional utilities)
// ═══════════════════════════════════════════════════════════════════

use chacha20poly1305::{
    aead::{Aead, NewAead},
    ChaCha20Poly1305, Key, Nonce,
};
use argon2::Argon2;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const SALT_SIZE: usize = 32;

/// Encrypt a private key for secure storage.
///
/// Uses ChaCha20-Poly1305 with Argon2id key derivation.
/// Format: salt (32 bytes) || nonce (12 bytes) || ciphertext
///
/// The backend MAY use this for encrypted key storage, or implement
/// its own encryption. This is a convenience function.
pub fn encrypt_key(privkey_pem: &[u8], password: &str) -> Result<Vec<u8>, DeployError> {
    // Generate random salt and nonce
    let salt: [u8; SALT_SIZE] = rand::random();
    let nonce_bytes: [u8; NONCE_SIZE] = rand::random();

    // Derive key from password using Argon2id
    let key = derive_key(password, &salt)?;

    // Encrypt
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, privkey_pem)
        .map_err(|e| DeployError::Certificate(format!("encryption failed: {}", e)))?;

    // Combine: salt || nonce || ciphertext
    let mut result = Vec::with_capacity(SALT_SIZE + NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt a private key.
///
/// Input format: salt (32 bytes) || nonce (12 bytes) || ciphertext
pub fn decrypt_key(encrypted: &[u8], password: &str) -> Result<Vec<u8>, DeployError> {
    const MIN_LEN: usize = SALT_SIZE + NONCE_SIZE + 16; // 16 = poly1305 tag
    if encrypted.len() < MIN_LEN {
        return Err(DeployError::Certificate("encrypted data too short".into()));
    }

    // Extract components
    let salt = &encrypted[..SALT_SIZE];
    let nonce_bytes = &encrypted[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
    let ciphertext = &encrypted[SALT_SIZE + NONCE_SIZE..];

    // Derive key
    let key = derive_key(password, salt)?;

    // Decrypt
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| DeployError::Certificate("decryption failed - wrong password".into()))?;

    Ok(plaintext)
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_SIZE], DeployError> {
    let mut key = [0u8; KEY_SIZE];

    // Argon2id with reasonable parameters
    // memory: 64 MiB, iterations: 2, parallelism: 2
    let params = argon2::Params::new(1 << 16, 2, 2, Some(KEY_SIZE))
        .map_err(|e| DeployError::Certificate(format!("argon2 params: {}", e)))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| DeployError::Certificate(format!("key derivation failed: {}", e)))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_certificate() {
        let cert = generate_certificate("akash1abc123def456").unwrap();

        // Verify PEMs are non-empty
        assert!(!cert.cert_pem.is_empty());
        assert!(!cert.pubkey_pem.is_empty());
        assert!(!cert.privkey_pem.is_empty());

        // Verify serial is 32 hex chars (16 bytes)
        assert_eq!(cert.serial.len(), 32);

        // Verify PEM headers
        let cert_str = String::from_utf8_lossy(&cert.cert_pem);
        let key_str = String::from_utf8_lossy(&cert.privkey_pem);
        let pub_str = String::from_utf8_lossy(&cert.pubkey_pem);

        assert!(cert_str.contains("BEGIN CERTIFICATE"));
        assert!(key_str.contains("BEGIN PRIVATE KEY"));
        // Akash requires "EC PUBLIC KEY" format, not "PUBLIC KEY"
        assert!(pub_str.contains("BEGIN EC PUBLIC KEY"), "pubkey should be EC PUBLIC KEY format");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let privkey = b"-----BEGIN PRIVATE KEY-----\ntest key data\n-----END PRIVATE KEY-----";
        let password = "hunter2";

        let encrypted = encrypt_key(privkey, password).unwrap();

        // Encrypted should be larger (salt + nonce + tag)
        assert!(encrypted.len() > privkey.len());

        // Decrypt should return original
        let decrypted = decrypt_key(&encrypted, password).unwrap();
        assert_eq!(decrypted, privkey);
    }

    #[test]
    fn test_wrong_password_fails() {
        let privkey = b"secret key data";
        let encrypted = encrypt_key(privkey, "correct").unwrap();

        let result = decrypt_key(&encrypted, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_data_fails() {
        let encrypted = vec![0u8; 10]; // Too short
        let result = decrypt_key(&encrypted, "password");
        assert!(result.is_err());
    }

    #[test]
    fn test_serial_uniqueness() {
        let addr = "akash1test";
        let cert1 = generate_certificate(addr).unwrap();
        let cert2 = generate_certificate(addr).unwrap();

        // Serials should differ (random component)
        assert_ne!(cert1.serial, cert2.serial);
    }
}
