//! JWT authentication for Akash providers.
//!
//! Akash providers authenticate clients via self-attested JWTs:
//!
//! 1. Client creates JWT with claims (issuer = wallet address, timestamps)
//! 2. Client signs JWT with their secp256k1 private key (ES256K algorithm)
//! 3. Client sends JWT in `Authorization: Bearer` header
//! 4. Provider validates by fetching issuer's public key from on-chain state
//!
//! There is NO challenge-response or registration - each request is self-attested.
//!
//! # Usage
//!
//! ```ignore
//! use akash_deploy::jwt::{JwtBuilder, JwtClaims};
//!
//! // Build JWT claims
//! let claims = JwtClaims::new("akash1...")
//!     .with_access("full");
//!
//! // Build and sign
//! let jwt = JwtBuilder::new()
//!     .build_and_sign(&claims, |message| {
//!         // Your ES256K signing implementation
//!         keypair.sign_jwt_es256k(message)
//!     })?;
//! ```

use crate::error::DeployError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// JWT Claims
// ============================================================================

/// JWT claims for Akash provider authentication.
///
/// These claims are self-attested by the client. The provider validates
/// by fetching the issuer's public key from on-chain account state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Issuer - the account address (e.g., "akash1...")
    pub iss: String,
    /// Issued at - Unix timestamp
    pub iat: i64,
    /// Expiration - Unix timestamp
    pub exp: i64,
    /// Not before - Unix timestamp
    pub nbf: i64,
    /// JWT ID - unique identifier to prevent replay attacks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Version identifier
    pub version: String,
    /// Lease access permissions
    pub leases: JwtLeases,
}

/// Lease access permissions for JWT claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtLeases {
    /// Access type: "full", "scoped", or "granular"
    pub access: String,
}

impl JwtClaims {
    /// Create new JWT claims for an address.
    ///
    /// Default validity: 15 minutes (900 seconds)
    /// Default access: "full"
    pub fn new(address: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs() as i64;

        Self {
            iss: address.to_string(),
            iat: now,
            exp: now + 900, // 15 minutes
            nbf: now,
            jti: None,
            version: "v1".to_string(),
            leases: JwtLeases {
                access: "full".to_string(),
            },
        }
    }

    /// Set JWT ID for replay protection.
    pub fn with_jti(mut self, jti: &str) -> Self {
        self.jti = Some(jti.to_string());
        self
    }

    /// Set access type ("full", "scoped", or "granular").
    pub fn with_access(mut self, access: &str) -> Self {
        self.leases.access = access.to_string();
        self
    }

    /// Set custom expiration (seconds from now).
    pub fn with_expiry_secs(mut self, secs: i64) -> Self {
        self.exp = self.iat + secs;
        self
    }

    /// Validate claims before signing.
    ///
    /// Checks:
    /// - Issuer format (akash1 + 38 chars = 44 total)
    /// - Time relationships (nbf <= iat <= exp)
    /// - Token not expired or not-yet-valid
    /// - Version is "v1"
    /// - Access type is valid
    pub fn validate(&self) -> Result<(), DeployError> {
        // Validate issuer format
        if !self.iss.starts_with("akash1") || self.iss.len() != 44 {
            return Err(DeployError::Jwt(format!(
                "invalid issuer format: must be akash1 + 38 chars (got: {})",
                self.iss
            )));
        }

        // Validate time relationships
        if self.nbf > self.iat {
            return Err(DeployError::Jwt(format!(
                "nbf ({}) > iat ({})",
                self.nbf, self.iat
            )));
        }
        if self.iat > self.exp {
            return Err(DeployError::Jwt(format!(
                "iat ({}) > exp ({})",
                self.iat, self.exp
            )));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| DeployError::Jwt(format!("system time error: {}", e)))?
            .as_secs() as i64;

        if self.exp < now {
            return Err(DeployError::Jwt(format!(
                "token expired: exp {} < now {}",
                self.exp, now
            )));
        }
        if self.nbf > now {
            return Err(DeployError::Jwt(format!(
                "token not yet valid: nbf {} > now {}",
                self.nbf, now
            )));
        }

        // Validate version
        if self.version != "v1" {
            return Err(DeployError::Jwt(format!(
                "invalid version: expected v1, got {}",
                self.version
            )));
        }

        // Validate access type
        if !["full", "scoped", "granular"].contains(&self.leases.access.as_str()) {
            return Err(DeployError::Jwt(format!(
                "invalid access type: {}. Must be full, scoped, or granular",
                self.leases.access
            )));
        }

        Ok(())
    }
}

// ============================================================================
// JWT Header
// ============================================================================

/// JWT header for ES256K signing.
#[derive(Debug, Clone, Serialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

impl Default for JwtHeader {
    fn default() -> Self {
        Self {
            alg: "ES256K".to_string(),
            typ: "JWT".to_string(),
        }
    }
}

// ============================================================================
// JWT Builder
// ============================================================================

/// Builder for Akash provider JWTs.
///
/// Handles the JWT structure and encoding. You provide the signing function.
#[derive(Debug, Default)]
pub struct JwtBuilder {
    _private: (), // Prevent external construction without Default
}

impl JwtBuilder {
    /// Create a new JWT builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build and sign a JWT.
    ///
    /// The `sign_fn` receives the signing input (header.claims in base64) and
    /// must return the ES256K signature (64 bytes: r || s in compact form).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let jwt = JwtBuilder::new().build_and_sign(&claims, |msg| {
    ///     keypair.sign_jwt_es256k(msg)
    /// })?;
    /// ```
    pub fn build_and_sign<F, E>(
        &self,
        claims: &JwtClaims,
        sign_fn: F,
    ) -> Result<String, DeployError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, E>,
        E: std::fmt::Display,
    {
        // Validate claims first
        claims.validate()?;

        let header = JwtHeader::default();

        // Encode header and claims
        let header_json = serde_json::to_string(&header)
            .map_err(|e| DeployError::Jwt(format!("header serialize: {}", e)))?;
        let claims_json = serde_json::to_string(claims)
            .map_err(|e| DeployError::Jwt(format!("claims serialize: {}", e)))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());

        let signing_input = format!("{}.{}", header_b64, claims_b64);

        // Sign with provided function (ES256K: secp256k1 + SHA-256)
        let signature = sign_fn(signing_input.as_bytes())
            .map_err(|e| DeployError::Jwt(format!("signing failed: {}", e)))?;

        // Validate signature length (ES256K = 64 bytes: r || s)
        if signature.len() != 64 {
            return Err(DeployError::Jwt(format!(
                "invalid signature length: expected 64 bytes, got {}",
                signature.len()
            )));
        }

        let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{}.{}", signing_input, signature_b64))
    }

    /// Build signing input without signing (for external signers).
    ///
    /// Returns the base64-encoded "header.claims" that needs to be signed.
    pub fn build_signing_input(&self, claims: &JwtClaims) -> Result<String, DeployError> {
        claims.validate()?;

        let header = JwtHeader::default();

        let header_json = serde_json::to_string(&header)
            .map_err(|e| DeployError::Jwt(format!("header serialize: {}", e)))?;
        let claims_json = serde_json::to_string(claims)
            .map_err(|e| DeployError::Jwt(format!("claims serialize: {}", e)))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());

        Ok(format!("{}.{}", header_b64, claims_b64))
    }

    /// Complete JWT from signing input and signature.
    pub fn complete_jwt(&self, signing_input: &str, signature: &[u8]) -> Result<String, DeployError> {
        if signature.len() != 64 {
            return Err(DeployError::Jwt(format!(
                "invalid signature length: expected 64 bytes, got {}",
                signature.len()
            )));
        }

        let signature_b64 = URL_SAFE_NO_PAD.encode(signature);
        Ok(format!("{}.{}", signing_input, signature_b64))
    }
}

// ============================================================================
// Cached JWT Token
// ============================================================================

/// JWT token with expiry tracking for caching.
#[derive(Debug, Clone)]
pub struct CachedJwt {
    /// The JWT string
    pub token: String,
    /// When this token expires (local time)
    pub expires_at: Instant,
}

impl CachedJwt {
    /// Create a new cached JWT.
    ///
    /// `valid_for` is how long the token should be considered valid.
    /// Recommend using less than the actual expiry (e.g., 14 min for 15 min token).
    pub fn new(token: String, valid_for: Duration) -> Self {
        Self {
            token,
            expires_at: Instant::now() + valid_for,
        }
    }

    /// Check if token is expired (with 60s safety buffer).
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .checked_duration_since(Instant::now())
            .map(|remaining| remaining < Duration::from_secs(60))
            .unwrap_or(true)
    }

    /// Get the token if not expired, None otherwise.
    pub fn get_if_valid(&self) -> Option<&str> {
        if self.is_expired() {
            None
        } else {
            Some(&self.token)
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_claims_new() {
        let claims = JwtClaims::new("akash1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5nue2z");

        assert!(claims.iss.starts_with("akash1"));
        assert_eq!(claims.iss.len(), 44);
        assert_eq!(claims.version, "v1");
        assert_eq!(claims.leases.access, "full");
        assert!(claims.exp > claims.iat);
        assert_eq!(claims.nbf, claims.iat);
    }

    #[test]
    fn test_jwt_claims_validation_invalid_issuer() {
        let claims = JwtClaims::new("cosmos1invalid");
        let result = claims.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid issuer"));
    }

    #[test]
    fn test_jwt_claims_validation_invalid_access() {
        let mut claims = JwtClaims::new("akash1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5nue2z");
        claims.leases.access = "invalid".to_string();
        let result = claims.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid access"));
    }

    #[test]
    fn test_jwt_builder_signing_input() {
        let claims = JwtClaims::new("akash1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5nue2z");
        let builder = JwtBuilder::new();

        let input = builder.build_signing_input(&claims).unwrap();

        // Should be header.claims in base64
        let parts: Vec<&str> = input.split('.').collect();
        assert_eq!(parts.len(), 2);

        // Decode header
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES256K");
        assert_eq!(header["typ"], "JWT");
    }

    #[test]
    fn test_jwt_builder_complete_jwt() {
        let builder = JwtBuilder::new();
        let signing_input = "header.claims";
        let signature = vec![0u8; 64]; // Dummy signature

        let jwt = builder.complete_jwt(signing_input, &signature).unwrap();

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "header");
        assert_eq!(parts[1], "claims");
    }

    #[test]
    fn test_jwt_builder_invalid_signature_length() {
        let builder = JwtBuilder::new();
        let signing_input = "header.claims";
        let bad_signature = vec![0u8; 32]; // Wrong length

        let result = builder.complete_jwt(signing_input, &bad_signature);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid signature length"));
    }

    #[test]
    fn test_cached_jwt_expiry() {
        // Token that expires in 120 seconds (valid since >60s remaining)
        let token = CachedJwt::new("test".to_string(), Duration::from_secs(120));
        assert!(!token.is_expired());
        assert!(token.get_if_valid().is_some());

        // Token that expires in 30 seconds (expired since <60s remaining)
        let almost_expired = CachedJwt::new("test".to_string(), Duration::from_secs(30));
        assert!(almost_expired.is_expired());
        assert!(almost_expired.get_if_valid().is_none());

        // Token already expired
        let expired = CachedJwt::new("test".to_string(), Duration::from_secs(0));
        assert!(expired.is_expired());
        assert!(expired.get_if_valid().is_none());
    }

    #[test]
    fn test_jwt_builder_build_and_sign() {
        let claims = JwtClaims::new("akash1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5nue2z");
        let builder = JwtBuilder::new();

        // Mock signer that returns 64 zero bytes
        let jwt = builder.build_and_sign(&claims, |_msg| -> Result<Vec<u8>, &str> {
            Ok(vec![0u8; 64])
        }).unwrap();

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
    }
}
