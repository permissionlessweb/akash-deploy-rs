//! The One Trait: AkashBackend
//!
//! This is the single abstraction point for all external dependencies.
//! The workflow engine is pure logic — it doesn't know about gRPC,
//! REST, storage engines, or key management. That's YOUR problem
//! when you implement this trait.

use crate::error::DeployError;
use crate::state::DeploymentState;
use crate::types::*;
use std::future::Future;

/// The single trait consumers implement to use the deployment workflow.
///
/// Abstracts:
/// - Chain queries (balance, certs, bids, leases)
/// - Transaction signing and broadcast
/// - Provider communication (manifest, status)
/// - Workflow state persistence
/// - Certificate key storage
pub trait AkashBackend: Send + Sync {
    /// Signing context — key name, HD path, whatever you need.
    /// The workflow doesn't care what this is.
    type Signer: Send + Sync;

    // ═══════════════════════════════════════════════════════════════
    // CHAIN QUERIES (read-only)
    // ═══════════════════════════════════════════════════════════════

    /// Query account balance.
    fn query_balance(
        &self,
        address: &str,
        denom: &str,
    ) -> impl Future<Output = Result<u128, DeployError>> + Send;

    /// Query certificate for address. Returns None if no cert exists.
    fn query_certificate(
        &self,
        address: &str,
    ) -> impl Future<Output = Result<Option<CertificateInfo>, DeployError>> + Send;

    /// Query provider info. Returns None if provider not registered.
    fn query_provider_info(
        &self,
        provider: &str,
    ) -> impl Future<Output = Result<Option<ProviderInfo>, DeployError>> + Send;

    /// Query bids for a deployment.
    fn query_bids(
        &self,
        owner: &str,
        dseq: u64,
    ) -> impl Future<Output = Result<Vec<Bid>, DeployError>> + Send;

    /// Query lease info.
    fn query_lease(
        &self,
        owner: &str,
        dseq: u64,
        gseq: u32,
        oseq: u32,
        provider: &str,
    ) -> impl Future<Output = Result<LeaseInfo, DeployError>> + Send;

    /// Query escrow account.
    fn query_escrow(
        &self,
        owner: &str,
        dseq: u64,
    ) -> impl Future<Output = Result<EscrowInfo, DeployError>> + Send;

    // ═══════════════════════════════════════════════════════════════
    // TRANSACTIONS (need signing)
    // ═══════════════════════════════════════════════════════════════

    /// Create and broadcast a certificate.
    fn broadcast_create_certificate(
        &self,
        signer: &Self::Signer,
        owner: &str,
        cert_pem: &[u8],
        pubkey_pem: &[u8],
    ) -> impl Future<Output = Result<TxResult, DeployError>> + Send;

    /// Create and broadcast a deployment. Returns (tx_result, dseq).
    fn broadcast_create_deployment(
        &self,
        signer: &Self::Signer,
        owner: &str,
        sdl_content: &str,
        deposit_uakt: u64,
    ) -> impl Future<Output = Result<(TxResult, u64), DeployError>> + Send;

    /// Create a lease from a bid.
    fn broadcast_create_lease(
        &self,
        signer: &Self::Signer,
        bid: &BidId,
    ) -> impl Future<Output = Result<TxResult, DeployError>> + Send;

    /// Deposit more funds into escrow.
    fn broadcast_deposit(
        &self,
        signer: &Self::Signer,
        owner: &str,
        dseq: u64,
        amount_uakt: u64,
    ) -> impl Future<Output = Result<TxResult, DeployError>> + Send;

    /// Close a deployment.
    fn broadcast_close_deployment(
        &self,
        signer: &Self::Signer,
        owner: &str,
        dseq: u64,
    ) -> impl Future<Output = Result<TxResult, DeployError>> + Send;

    // ═══════════════════════════════════════════════════════════════
    // PROVIDER COMMUNICATION (mTLS)
    // ═══════════════════════════════════════════════════════════════

    /// Send manifest to provider.
    fn send_manifest(
        &self,
        provider_uri: &str,
        lease: &LeaseId,
        manifest: &[u8],
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> impl Future<Output = Result<(), DeployError>> + Send;

    /// Query provider for lease status.
    fn query_provider_status(
        &self,
        provider_uri: &str,
        lease: &LeaseId,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> impl Future<Output = Result<ProviderLeaseStatus, DeployError>> + Send;

    // ═══════════════════════════════════════════════════════════════
    // STATE PERSISTENCE
    // ═══════════════════════════════════════════════════════════════

    /// Load workflow state by session ID.
    fn load_state(
        &self,
        session_id: &str,
    ) -> impl Future<Output = Result<Option<DeploymentState>, DeployError>> + Send;

    /// Save workflow state.
    fn save_state(
        &self,
        session_id: &str,
        state: &DeploymentState,
    ) -> impl Future<Output = Result<(), DeployError>> + Send;

    // ═══════════════════════════════════════════════════════════════
    // CERTIFICATE KEY STORAGE (for mTLS persistence)
    // ═══════════════════════════════════════════════════════════════

    /// Load certificate private key for address.
    /// The key may be encrypted — that's the backend's business.
    fn load_cert_key(
        &self,
        owner: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, DeployError>> + Send;

    /// Store certificate private key for address.
    fn save_cert_key(
        &self,
        owner: &str,
        key: &[u8],
    ) -> impl Future<Output = Result<(), DeployError>> + Send;

    /// Delete certificate key (on revocation).
    fn delete_cert_key(
        &self,
        owner: &str,
    ) -> impl Future<Output = Result<(), DeployError>> + Send;

    // ═══════════════════════════════════════════════════════════════
    // PROVIDER INFO CACHE (optional optimization)
    // ═══════════════════════════════════════════════════════════════

    /// Load cached provider info.
    fn load_cached_provider(
        &self,
        provider: &str,
    ) -> impl Future<Output = Result<Option<ProviderInfo>, DeployError>> + Send;

    /// Cache provider info.
    fn cache_provider(
        &self,
        info: &ProviderInfo,
    ) -> impl Future<Output = Result<(), DeployError>> + Send;
}
