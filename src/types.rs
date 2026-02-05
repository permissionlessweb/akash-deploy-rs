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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bid_id_from_bid() {
        let bid = Bid {
            provider: "akash1provider".to_string(),
            price_uakt: 1000,
            resources: Resources::default(),
        };

        let bid_id = BidId::from_bid("akash1owner", 123, 1, 1, &bid);
        assert_eq!(bid_id.owner, "akash1owner");
        assert_eq!(bid_id.dseq, 123);
        assert_eq!(bid_id.gseq, 1);
        assert_eq!(bid_id.oseq, 1);
        assert_eq!(bid_id.provider, "akash1provider");
    }

    #[test]
    fn test_lease_id_from_bid_id() {
        let bid_id = BidId {
            owner: "akash1owner".to_string(),
            dseq: 456,
            gseq: 2,
            oseq: 3,
            provider: "akash1provider".to_string(),
        };

        let lease_id: LeaseId = bid_id.into();
        assert_eq!(lease_id.owner, "akash1owner");
        assert_eq!(lease_id.dseq, 456);
        assert_eq!(lease_id.gseq, 2);
        assert_eq!(lease_id.oseq, 3);
        assert_eq!(lease_id.provider, "akash1provider");
    }

    #[test]
    fn test_tx_result_is_success() {
        let success_tx = TxResult {
            hash: "ABC123".to_string(),
            code: 0,
            raw_log: "success".to_string(),
            height: 1000,
        };
        assert!(success_tx.is_success());

        let failed_tx = TxResult {
            hash: "DEF456".to_string(),
            code: 5,
            raw_log: "insufficient funds".to_string(),
            height: 1001,
        };
        assert!(!failed_tx.is_success());
    }

    #[test]
    fn test_serialization_golden() {
        let bid = Bid {
            provider: "akash1test".to_string(),
            price_uakt: 5000,
            resources: Resources {
                cpu_millicores: 1000,
                memory_bytes: 1073741824, // 1 GiB
                storage_bytes: 10737418240, // 10 GiB
                gpu_count: 1,
            },
        };

        let json = serde_json::to_string(&bid).unwrap();

        // Golden test: verify exact JSON structure
        let expected = r#"{"provider":"akash1test","price_uakt":5000,"resources":{"cpu_millicores":1000,"memory_bytes":1073741824,"storage_bytes":10737418240,"gpu_count":1}}"#;
        assert_eq!(json, expected, "JSON structure changed - wire format compatibility broken");

        // Verify roundtrip
        let deserialized: Bid = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.provider, bid.provider);
        assert_eq!(deserialized.price_uakt, bid.price_uakt);
    }

    #[test]
    fn test_boundary_conditions() {
        // Test with extreme values
        let bid = Bid {
            provider: "akash1provider".to_string(),
            price_uakt: u64::MAX,
            resources: Resources {
                cpu_millicores: u32::MAX,
                memory_bytes: u64::MAX,
                storage_bytes: u64::MAX,
                gpu_count: u32::MAX,
            },
        };

        let json = serde_json::to_string(&bid).unwrap();
        let deserialized: Bid = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.price_uakt, u64::MAX);
        assert_eq!(deserialized.resources.cpu_millicores, u32::MAX);

        // Test with zeros
        let min_resources = Resources {
            cpu_millicores: 0,
            memory_bytes: 0,
            storage_bytes: 0,
            gpu_count: 0,
        };
        let json = serde_json::to_string(&min_resources).unwrap();
        let deserialized: Resources = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.cpu_millicores, 0);
    }
}
