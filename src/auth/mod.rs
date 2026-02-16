pub mod certificate;
pub mod jwt;

/// Provider authentication mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// JWT Bearer token authentication (default).
    /// Generates a self-attested JWT signed with the wallet's secp256k1 key.
    Jwt,
    /// mTLS certificate-based authentication (legacy).
    /// Requires an on-chain certificate.
    Mtls,
}

impl Default for AuthMode {
    fn default() -> Self {
        Self::Jwt
    }
}
