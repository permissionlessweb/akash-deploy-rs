//! Generic storage trait for deployment session persistence.
//!
//! This module defines the `SessionStorage` trait which provides a generic
//! interface for persisting deployment state. Users can implement this trait
//! to use custom storage backends (databases, cloud storage, etc.).
//!
//! A default file-based implementation is provided via the `file-storage` feature.

use crate::error::DeployError;
use crate::state::DeploymentState;
use crate::types::{CertificateInfo, ProviderInfo};
use async_trait::async_trait;

/// Generic trait for persisting deployment sessions and related data.
///
/// This trait defines the interface for storing and retrieving deployment state,
/// certificates, and provider information. Implementations can use any storage
/// backend (memory, file system, database, cloud storage, etc.).
///
/// # Example
///
/// ```ignore
/// use akash_deploy_rs::store::SessionStorage;
///
/// struct MyCustomStorage {
///     // Your storage implementation
/// }
///
/// #[async_trait]
/// impl SessionStorage for MyCustomStorage {
///     async fn save_session(&mut self, session: &DeploymentState) -> Result<(), DeployError> {
///         // Save to your storage backend
///         Ok(())
///     }
///     // ... implement other methods
/// }
/// ```
#[async_trait]
pub trait SessionStorage: Send + Sync {
    // ═══════════════════════════════════════════════════════════════
    // SESSION MANAGEMENT
    // ═══════════════════════════════════════════════════════════════

    /// Save a deployment session to storage.
    async fn save_session(&mut self, session: &DeploymentState) -> Result<(), DeployError>;

    /// Load a deployment session from storage.
    ///
    /// Returns `Ok(None)` if the session doesn't exist.
    async fn load_session(&self, session_id: &str) -> Result<Option<DeploymentState>, DeployError>;

    /// List all stored session IDs.
    async fn list_sessions(&self) -> Result<Vec<String>, DeployError>;

    /// Delete a deployment session from storage.
    ///
    /// Returns `Ok(())` even if the session doesn't exist (idempotent).
    async fn delete_session(&mut self, session_id: &str) -> Result<(), DeployError>;

    // ═══════════════════════════════════════════════════════════════
    // CERTIFICATE STORAGE
    // ═══════════════════════════════════════════════════════════════

    /// Save a certificate's private key (encrypted or plaintext).
    async fn save_cert_key(&mut self, owner: &str, key_pem: &[u8]) -> Result<(), DeployError>;

    /// Load a certificate's private key.
    ///
    /// Returns `Ok(None)` if no key is stored for this owner.
    async fn load_cert_key(&self, owner: &str) -> Result<Option<Vec<u8>>, DeployError>;

    /// Delete a certificate's private key.
    async fn delete_cert_key(&mut self, owner: &str) -> Result<(), DeployError>;

    // ═══════════════════════════════════════════════════════════════
    // PROVIDER CACHING (OPTIONAL)
    // ═══════════════════════════════════════════════════════════════

    /// Cache provider information to reduce chain queries.
    async fn cache_provider(&mut self, info: &ProviderInfo) -> Result<(), DeployError>;

    /// Load cached provider information.
    ///
    /// Returns `Ok(None)` if not cached or if cache is stale.
    async fn load_cached_provider(
        &self,
        provider: &str,
    ) -> Result<Option<ProviderInfo>, DeployError>;

    // ═══════════════════════════════════════════════════════════════
    // CERTIFICATE INFO CACHING (OPTIONAL)
    // ═══════════════════════════════════════════════════════════════

    /// Cache certificate information from the chain.
    async fn cache_certificate(&mut self, info: &CertificateInfo) -> Result<(), DeployError>;

    /// Load cached certificate information.
    ///
    /// Returns `Ok(None)` if not cached.
    async fn load_cached_certificate(
        &self,
        owner: &str,
    ) -> Result<Option<CertificateInfo>, DeployError>;
}
