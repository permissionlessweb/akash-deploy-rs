//! Minimal domain types for Akash deployment workflow.
//!
//! These are the types the workflow engine needs. Nothing more.
//! If you're adding types here, ask yourself if the workflow
//! actually needs them or if you're just being clever.

use serde::{Deserialize, Serialize};

/// A bid from a provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bid {
    pub provider: String,
    pub price_uakt: u64,
    pub resources: Resources,
}

/// Bid identifier — everything needed to create a lease from a bid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BidId {
    pub owner: String,
    pub dseq: u64,
    pub gseq: u32,
    pub oseq: u32,
    pub provider: String,
}

impl BidId {
    pub fn from_bid(owner: &str, dseq: u64, gseq: u32, oseq: u32, bid: &Bid) -> Self {
        Self {
            owner: owner.to_string(),
            dseq,
            gseq,
            oseq,
            provider: bid.provider.clone(),
        }
    }
}

/// Lease identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseId {
    pub owner: String,
    pub dseq: u64,
    pub gseq: u32,
    pub oseq: u32,
    pub provider: String,
}

impl From<BidId> for LeaseId {
    fn from(bid: BidId) -> Self {
        Self {
            owner: bid.owner,
            dseq: bid.dseq,
            gseq: bid.gseq,
            oseq: bid.oseq,
            provider: bid.provider,
        }
    }
}

/// Lease state on chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseState {
    Active,
    InsufficientFunds,
    Closed,
}

/// Lease info from chain query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseInfo {
    pub state: LeaseState,
    pub price_uakt: u64,
}

/// Certificate info from chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub cert_pem: Vec<u8>,
    pub serial: String,
}

/// Provider info for display and caching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub address: String,
    pub host_uri: String,
    pub email: String,
    pub website: String,
    pub attributes: Vec<(String, String)>,
    pub cached_at: u64,
}

/// Escrow account info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowInfo {
    pub balance_uakt: u64,
    pub deposited_uakt: u64,
}

/// Transaction result from broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxResult {
    pub hash: String,
    pub code: u32,
    pub raw_log: String,
    pub height: u64,
}

impl TxResult {
    pub fn is_success(&self) -> bool {
        self.code == 0
    }
}

/// Service endpoint from provider status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub service: String,
    pub uri: String,
    pub port: u16,
}

/// Provider's status for a lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderLeaseStatus {
    pub ready: bool,
    pub endpoints: Vec<ServiceEndpoint>,
}

/// Resource allocation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Resources {
    pub cpu_millicores: u32,
    pub memory_bytes: u64,
    pub storage_bytes: u64,
    pub gpu_count: u32,
}
