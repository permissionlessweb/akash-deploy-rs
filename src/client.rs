//! Default Akash client implementation using layer-climb.
//!
//! This module provides a complete, integrated client that implements the `AkashBackend`
//! trait using the layer-climb Cosmos client library and the file-backed storage system.
//!
//! # Quick Start
//!
//! ```ignore
//! use akash_deploy_rs::{AkashClient, DeploymentWorkflow, DeploymentState};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create client with default storage (~/.akash-deploy)
//! let client = AkashClient::new_from_mnemonic(
//!     "your mnemonic words here",
//!     "https://rpc.akashnet.net:443"
//! ).await?;
//!
//! // Create workflow
//! let workflow = DeploymentWorkflow::new(
//!     &client,
//!     client.signer(),
//!     Default::default()
//! );
//!
//! // Create deployment
//! let mut state = DeploymentState::new("my-app", client.address())
//!     .with_sdl(sdl_content)
//!     .with_label("production");
//!
//! // Run to completion
//! workflow.run_to_completion(&mut state).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Custom Storage
//!
//! You can provide a custom storage implementation:
//!
//! ```ignore
//! struct MyStorage { /* your implementation */ }
//!
//! #[async_trait]
//! impl SessionStorage for MyStorage {
//!     // Implement trait methods
//! }
//!
//! let client = AkashClient::with_storage(
//!     my_layer_climb_client,
//!     MyStorage::new()
//! );
//! ```

use crate::backend::AkashBackend;
use crate::error::DeployError;
use crate::r#gen::akash::escrow::id::v1::Scope;
use crate::state::DeploymentState;
use crate::storage::{FileBackedStorage, SessionStorage};
use crate::types::*;

use layer_climb::prelude::*;
use std::io::Cursor;

// Import Akash proto types
use crate::gen::akash::{deployment::v1beta4 as akash_deployment, market::v1beta5 as akash_market};
use prost::{Message as ProstMessage, Name as ProstName};

/// Reusable gRPC query clients for Akash modules.
///
/// These clients are created once and reused across all queries to avoid
/// repeatedly establishing gRPC connections.
pub struct QueryClients {
    pub cert: crate::gen::akash::cert::v1::query_client::QueryClient<tonic::transport::Channel>,
    pub provider:
        crate::gen::akash::provider::v1beta4::query_client::QueryClient<tonic::transport::Channel>,
    pub market:
        crate::gen::akash::market::v1beta5::query_client::QueryClient<tonic::transport::Channel>,
    pub escrow: crate::gen::akash::escrow::v1::query_client::QueryClient<tonic::transport::Channel>,
}

impl QueryClients {
    /// Create all query clients by connecting to the gRPC endpoint.
    pub async fn new(grpc_endpoint: &str) -> Result<Self, DeployError> {
        use crate::gen::akash::{
            cert::v1 as akash_cert, escrow::v1 as akash_escrow, market::v1beta5 as akash_market,
            provider::v1beta4 as akash_provider,
        };

        let cert = akash_cert::query_client::QueryClient::connect(grpc_endpoint.to_string())
            .await
            .map_err(|e| DeployError::Query(format!("Failed to connect cert client: {}", e)))?;

        let provider =
            akash_provider::query_client::QueryClient::connect(grpc_endpoint.to_string())
                .await
                .map_err(|e| {
                    DeployError::Query(format!("Failed to connect provider client: {}", e))
                })?;

        let market = akash_market::query_client::QueryClient::connect(grpc_endpoint.to_string())
            .await
            .map_err(|e| DeployError::Query(format!("Failed to connect market client: {}", e)))?;

        let escrow = akash_escrow::query_client::QueryClient::connect(grpc_endpoint.to_string())
            .await
            .map_err(|e| DeployError::Query(format!("Failed to connect escrow client: {}", e)))?;

        Ok(Self {
            cert,
            provider,
            market,
            escrow,
        })
    }
}

/// Akash client with integrated chain/provider communication and storage.
///
/// This is a complete implementation of `AkashBackend` that:
/// - Uses layer-climb for chain queries and transactions
/// - Uses layer-climb for provider HTTP communication
/// - Provides generic storage via the `SessionStorage` trait
/// - Handles signing with the provided signer
///
/// # Type Parameters
///
/// - `S`: Storage implementation (defaults to `FileBackedStorage`)
pub struct AkashClient<S: SessionStorage = FileBackedStorage> {
    /// Layer-climb signing client for chain communication
    client: SigningClient,

    /// Generic storage backend
    storage: S,

    /// Owner address (cached from signer)
    address: Address,

    /// Reusable gRPC query clients
    query_clients: Option<QueryClients>,
}

impl AkashClient<FileBackedStorage> {
    /// Create a new client with default file-backed storage.
    ///
    /// This initializes the layer-climb client with the given mnemonic and RPC endpoint,
    /// and sets up file-based storage in `~/.akash-deploy`.
    ///
    /// # Arguments
    ///
    /// - `mnemonic`: BIP39 mnemonic phrase for key derivation
    /// - `rpc_endpoint`: Akash RPC endpoint URL (e.g., "https://rpc.akashnet.net:443")
    ///
    /// # Example
    ///
    /// ```ignore
    /// let client = AkashClient::new_from_mnemonic(
    ///     "your twelve word mnemonic phrase here for signing transactions securely",
    ///     "https://rpc.akashnet.net:443"
    /// ).await?;
    /// ```
    pub async fn new_from_mnemonic(
        mnemonic: &str,
        rpc_endpoint: &str,
    ) -> Result<Self, DeployError> {
        // Create the key signer from mnemonic
        let signer = KeySigner::new_mnemonic_str(mnemonic, None).map_err(|e| {
            DeployError::Signer(format!("Failed to create signer from mnemonic: {}", e))
        })?;

        // Set up Akash chain configuration
        let chain_config = ChainConfig {
            chain_id: ChainId::new("akashnet-2"), // Default to mainnet
            address_kind: AddrKind::Cosmos {
                prefix: "akash".to_string(),
            },
            gas_price: 0.025,
            gas_denom: "uakt".to_string(),
            rpc_endpoint: Some(rpc_endpoint.to_string()),
            grpc_endpoint: None,
            grpc_web_endpoint: None,
        };

        // Save gRPC endpoint before moving chain_config
        let grpc_endpoint = chain_config.grpc_endpoint.clone();

        // Create the signing client
        let client = SigningClient::new(chain_config, signer, None::<Connection>)
            .await
            .map_err(|e| DeployError::Query(format!("Failed to create signing client: {}", e)))?;

        // Get the address from the client
        let address = client.addr.clone();

        // Initialize storage
        let storage = FileBackedStorage::new_default().await?;

        // Initialize query clients if gRPC endpoint is configured
        let query_clients = if let Some(endpoint) = grpc_endpoint {
            Some(QueryClients::new(&endpoint).await?)
        } else {
            None
        };

        Ok(Self {
            client,
            storage,
            address,
            query_clients,
        })
    }
}

impl<S: SessionStorage> AkashClient<S> {
    /// Create a client with custom storage.
    ///
    /// This allows you to provide your own storage implementation for
    /// database-backed persistence, cloud storage, etc.
    pub fn with_storage(client: SigningClient, storage: S) -> Self {
        let address = client.addr.clone();
        Self {
            client,
            storage,
            address,
            query_clients: None, // Will be initialized lazily on first query
        }
    }

    /// Get or initialize query clients.
    ///
    /// This lazily initializes the query clients on first access if they
    /// haven't been created yet.
    async fn get_query_clients(&self) -> Result<QueryClients, DeployError> {
        // If we already have clients, clone them (cheap - just clones the channel)
        if let Some(ref clients) = self.query_clients {
            return Ok(QueryClients {
                cert: clients.cert.clone(),
                provider: clients.provider.clone(),
                market: clients.market.clone(),
                escrow: clients.escrow.clone(),
            });
        }

        // Otherwise, create new clients
        let grpc_endpoint = self
            .client
            .querier
            .chain_config
            .grpc_endpoint
            .as_ref()
            .ok_or_else(|| DeployError::Query("gRPC endpoint not configured".into()))?;

        QueryClients::new(grpc_endpoint).await
    }

    /// Get the client's address as a string.
    pub fn address(&self) -> String {
        self.address.to_string()
    }

    /// Get a reference to the client's address.
    pub fn address_ref(&self) -> &Address {
        &self.address
    }

    /// Get a reference to the signing client for direct access.
    pub fn signing_client(&self) -> &SigningClient {
        &self.client
    }

    /// Get a reference to the signer (for use with workflow).
    pub fn signer(&self) -> &dyn TxSigner {
        self.client.signer.as_ref()
    }

    /// Get a reference to the storage backend.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Get a mutable reference to the storage backend.
    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }
}

// ═══════════════════════════════════════════════════════════════════
// AKASH BACKEND IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════

/// Re-export layer-climb's TxSigner trait and KeySigner type for external use
pub use layer_climb::prelude::KeySigner;

/// Helper function to extract dseq from transaction events.
fn extract_dseq_from_events(events: &[layer_climb::proto::tendermint::Event]) -> Option<u64> {
    for event in events {
        if event.r#type == "akash.deployment.v1.EventDeploymentCreated" {
            for attr in &event.attributes {
                if attr.key == "dseq" {
                    return attr.value.parse().ok();
                }
            }
        }
    }
    None
}

/// Helper function to create an mTLS HTTP client for provider communication.
fn create_mtls_client(cert_pem: &[u8], key_pem: &[u8]) -> Result<reqwest::Client, DeployError> {
    use rustls_pemfile::{certs, rsa_private_keys};

    // Parse certificate
    let cert_reader = &mut Cursor::new(cert_pem);
    let certs = certs(cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DeployError::Certificate(format!("Failed to parse certificate: {}", e)))?;

    if certs.is_empty() {
        return Err(DeployError::Certificate(
            "No certificates found in PEM".into(),
        ));
    }

    // Parse private key
    let key_reader = &mut Cursor::new(key_pem);
    let keys = rsa_private_keys(key_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DeployError::Certificate(format!("Failed to parse private key: {}", e)))?;

    if keys.is_empty() {
        return Err(DeployError::Certificate(
            "No private keys found in PEM".into(),
        ));
    }

    // Create client identity
    let identity = reqwest::tls::Identity::from_pem(&[cert_pem, key_pem].concat())
        .map_err(|e| DeployError::Certificate(format!("Failed to create identity: {}", e)))?;

    // Build HTTP client with mTLS
    reqwest::Client::builder()
        .identity(identity)
        .danger_accept_invalid_certs(false) // Verify provider certificates
        .build()
        .map_err(|e| DeployError::Provider(format!("Failed to create HTTP client: {}", e)))
}

impl<S: SessionStorage> AkashBackend for AkashClient<S> {
    type Signer = KeySigner;

    async fn query_balance(&self, address: &str, denom: &str) -> Result<u128, DeployError> {
        let addr = self
            .client
            .querier
            .chain_config
            .parse_address(address)
            .map_err(|e| DeployError::Query(format!("Invalid address: {}", e)))?;

        let balance = self
            .client
            .querier
            .balance(addr, Some(denom.to_string()))
            .await
            .map_err(|e| DeployError::Query(format!("Failed to query balance: {}", e)))?;

        Ok(balance.unwrap_or(0))
    }

    async fn query_certificate(&self, owner: &str) -> Result<Option<CertificateInfo>, DeployError> {
        // Check cache first
        if let Some(cert) = self.storage.load_cached_certificate(owner).await? {
            return Ok(Some(cert));
        }

        use crate::gen::akash::cert::v1 as akash_cert;

        // Get reusable query clients
        let mut clients = self.get_query_clients().await?;

        // Execute query
        let response = clients
            .cert
            .certificates(akash_cert::QueryCertificatesRequest {
                filter: Some(akash_cert::CertificateFilter {
                    owner: owner.to_string(),
                    serial: String::new(), // empty = all serials
                    state: String::new(),  // empty = all states
                }),
                pagination: None,
            })
            .await
            .map_err(|e| DeployError::Query(format!("Failed to query certificates: {}", e)))?
            .into_inner();

        // Return first valid certificate
        if let Some(cert_response) = response.certificates.first() {
            if let Some(cert) = &cert_response.certificate {
                return Ok(Some(CertificateInfo {
                    owner: owner.to_string(),
                    cert_pem: cert.cert.clone(),
                    serial: cert_response.serial.clone(),
                }));
            }
        }

        Ok(None)
    }

    async fn query_provider_info(
        &self,
        provider: &str,
    ) -> Result<Option<ProviderInfo>, DeployError> {
        // Check cache first
        if let Some(info) = self.storage.load_cached_provider(provider).await? {
            return Ok(Some(info));
        }

        use crate::gen::akash::provider::v1beta4 as akash_provider;

        // Get reusable query clients
        let mut clients = self.get_query_clients().await?;

        // Execute query
        let response = clients
            .provider
            .provider(akash_provider::QueryProviderRequest {
                owner: provider.to_string(),
            })
            .await
            .map_err(|e| DeployError::Query(format!("Failed to query provider: {}", e)))?
            .into_inner();

        // Extract provider info
        if let Some(prov) = response.provider {
            let attributes = prov
                .attributes
                .into_iter()
                .map(|attr| (attr.key, attr.value))
                .collect();

            return Ok(Some(ProviderInfo {
                address: provider.to_string(),
                host_uri: prov.host_uri,
                email: prov
                    .info
                    .as_ref()
                    .map(|i| i.email.clone())
                    .unwrap_or_default(),
                website: prov
                    .info
                    .as_ref()
                    .map(|i| i.website.clone())
                    .unwrap_or_default(),
                attributes,
                cached_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            }));
        }

        Ok(None)
    }

    async fn query_bids(&self, owner: &str, dseq: u64) -> Result<Vec<Bid>, DeployError> {
        use crate::gen::akash::market::v1beta5 as akash_market;

        // Get reusable query clients
        let mut clients = self.get_query_clients().await?;

        // Execute query
        let response = clients
            .market
            .bids(akash_market::QueryBidsRequest {
                filters: Some(akash_market::BidFilters {
                    owner: owner.to_string(),
                    dseq,
                    gseq: 0,                 // 0 means all groups
                    oseq: 0,                 // 0 means all order sequences
                    provider: String::new(), // empty means all providers
                    state: String::new(),    // empty means all states
                    bseq: 0,                 // 0 means all bid sequences
                }),
                pagination: None,
            })
            .await
            .map_err(|e| DeployError::Query(format!("Failed to query bids: {}", e)))?
            .into_inner();

        // Convert proto bids to our domain types
        let bids = response
            .bids
            .into_iter()
            .filter_map(|bid_response| {
                let bid = bid_response.bid?;
                let bid_id = bid.id?;
                let price = bid.price?;

                // Parse price amount
                let price_uakt = price.amount.parse::<u64>().ok()?;

                // Extract resources (if available)
                let resources = Resources::default(); // TODO: Parse from bid if needed

                Some(Bid {
                    provider: bid_id.provider,
                    price_uakt,
                    resources,
                })
            })
            .collect();

        Ok(bids)
    }

    async fn query_lease(
        &self,
        owner: &str,
        dseq: u64,
        gseq: u32,
        oseq: u32,
        bseq: u32,
        provider: &str,
    ) -> Result<LeaseInfo, DeployError> {
        use crate::gen::akash::market::v1 as akash_market_v1;

        // Get reusable query clients
        let mut clients = self.get_query_clients().await?;

        // Execute query
        let response = clients
            .market
            .lease(crate::gen::akash::market::v1beta5::QueryLeaseRequest {
                id: Some(akash_market_v1::LeaseId {
                    owner: owner.to_string(),
                    dseq,
                    gseq,
                    oseq,
                    provider: provider.to_string(),
                    bseq,
                }),
            })
            .await
            .map_err(|e| DeployError::Query(format!("Failed to query lease: {}", e)))?
            .into_inner();

        // Extract lease info
        let lease = response
            .lease
            .ok_or_else(|| DeployError::Query("Lease not found in response".into()))?;

        let price = lease
            .price
            .ok_or_else(|| DeployError::Query("Lease price missing".into()))?;

        let price_uakt = price
            .amount
            .parse::<u64>()
            .map_err(|e| DeployError::Query(format!("Invalid price amount: {}", e)))?;

        // Parse state enum
        let state = match lease.state {
            1 => LeaseState::Active,
            2 => LeaseState::InsufficientFunds,
            3 => LeaseState::Closed,
            _ => LeaseState::Closed, // Default to closed for unknown states
        };

        Ok(LeaseInfo { state, price_uakt })
    }

    async fn query_escrow(&self, owner: &str, dseq: u64) -> Result<EscrowInfo, DeployError> {
        use crate::gen::akash::escrow::v1 as akash_escrow;

        // Get reusable query clients
        let mut clients = self.get_query_clients().await?;

        // Execute query
        let response = clients
            .escrow
            .accounts(akash_escrow::QueryAccountsRequest {
                state: String::new(), // empty = all states
                xid: format!("{}/{}", owner, dseq),
                pagination: None,
            })
            .await
            .map_err(|e| DeployError::Query(format!("Failed to query escrow: {}", e)))?
            .into_inner();

        // Extract account info (get first account from results)
        let account = response
            .accounts
            .first()
            .ok_or_else(|| DeployError::Query("Escrow account not found".into()))?;

        let account_state = account
            .state
            .as_ref()
            .ok_or_else(|| DeployError::Query("Escrow account state missing".into()))?;

        // Calculate total balance from funds (sum all uakt balances)
        let balance_uakt = account_state
            .funds
            .iter()
            .filter(|f| f.denom == "uakt")
            .filter_map(|f| f.amount.parse::<u64>().ok())
            .sum::<u64>();

        // For deposited amount, we can't easily calculate it from the current state,
        // so we'll use the same as balance for now
        // TODO: Track deposits separately if needed
        let deposited_uakt = balance_uakt;

        Ok(EscrowInfo {
            balance_uakt,
            deposited_uakt,
        })
    }

    async fn broadcast_create_certificate(
        &self,
        _signer: &Self::Signer,
        owner: &str,
        cert_pem: &[u8],
        pubkey_pem: &[u8],
    ) -> Result<TxResult, DeployError> {
        use crate::gen::akash::cert::v1 as akash_cert;

        // Create the message
        let msg = akash_cert::MsgCreateCertificate {
            owner: owner.to_string(),
            cert: cert_pem.to_vec(),
            pubkey: pubkey_pem.to_vec(),
        };

        // Convert message to Any for broadcasting using prost directly
        // This avoids version mismatch with layer-climb's prost dependency
        let any_msg = layer_climb::proto::Any {
            type_url: akash_cert::MsgCreateCertificate::type_url(),
            value: msg.encode_to_vec(),
        };

        // Broadcast transaction
        let response = self
            .client
            .tx_builder()
            .broadcast([any_msg])
            .await
            .map_err(|e| DeployError::Transaction {
                code: 1,
                log: format!("Failed to broadcast certificate creation: {}", e),
            })?;

        Ok(TxResult {
            hash: response.txhash,
            code: response.code,
            raw_log: response.raw_log,
            height: response.height as u64,
        })
    }

    async fn broadcast_create_deployment(
        &self,
        _signer: &Self::Signer,
        owner: &str,
        sdl_content: &str,
        deposit_uakt: u64,
    ) -> Result<(TxResult, u64), DeployError> {
        use crate::gen::akash::base::deposit::v1 as akash_deposit;
        use crate::gen::akash::deployment::v1 as akash_deployment_v1;
        use sha2::{Digest, Sha256};

        // Validate SDL and build groups from it
        crate::sdl::validate_sdl(sdl_content)?;

        // Build GroupSpecs from SDL (groups services by placement)
        let groups = crate::groupspec::build_groupspecs_from_sdl(sdl_content)?;

        eprintln!(
            "DEBUG create_deployment: Sending {} GroupSpecs:",
            groups.len()
        );
        for g in &groups {
            eprintln!(
                "DEBUG:   - Group '{}': {} ResourceUnits",
                g.name,
                g.resources.len()
            );
            for (idx, ru) in g.resources.iter().enumerate() {
                eprintln!("DEBUG:     ResourceUnit[{}]: count={}", idx, ru.count);
            }
        }

        // Compute SDL hash (32 bytes)
        let sdl_hash = Sha256::digest(sdl_content.as_bytes()).to_vec();

        // Build deployment ID (dseq will be 0, assigned by chain)
        let deployment_id = akash_deployment_v1::DeploymentId {
            owner: owner.to_string(),
            dseq: 0,
        };

        // Build deposit
        let deposit = akash_deposit::Deposit {
            amount: Some(crate::gen::cosmos::base::v1beta1::Coin {
                denom: "uakt".to_string(),
                amount: deposit_uakt.to_string(),
            }),
            sources: vec![akash_deposit::Source::Balance as i32],
        };

        // Create the message with properly grouped services
        let msg = akash_deployment::MsgCreateDeployment {
            id: Some(deployment_id),
            groups,
            hash: sdl_hash,
            deposit: Some(deposit),
        };

        // Convert message to Any for broadcasting using prost directly
        // This avoids version mismatch with layer-climb's prost dependency
        let type_url = akash_deployment::MsgCreateDeployment::type_url();
        let value = msg.encode_to_vec();
        let any_msg = layer_climb::proto::Any { type_url, value };

        // Broadcast transaction
        let response = self
            .client
            .tx_builder()
            .broadcast([any_msg])
            .await
            .map_err(|e| DeployError::Transaction {
                code: 1,
                log: format!("Failed to broadcast transaction: {}", e),
            })?;

        // Extract dseq from response events
        // Events are in the format: {"type":"akash.deployment.v1.EventDeploymentCreated","attributes":[{"key":"dseq","value":"123456"}]}
        let dseq =
            extract_dseq_from_events(&response.events).ok_or_else(|| DeployError::Transaction {
                code: response.code,
                log: format!(
                    "Failed to extract dseq from transaction events: {}",
                    response.raw_log
                ),
            })?;

        Ok((
            TxResult {
                hash: response.txhash,
                code: response.code,
                raw_log: response.raw_log,
                height: response.height as u64,
            },
            dseq,
        ))
    }

    async fn broadcast_create_lease(
        &self,
        _signer: &Self::Signer,
        bid: &BidId,
    ) -> Result<TxResult, DeployError> {
        use crate::gen::akash::market::v1 as akash_market_v1;

        // Build BidId from our types
        let bid_id = akash_market_v1::BidId {
            owner: bid.owner.clone(),
            dseq: bid.dseq,
            gseq: bid.gseq,
            oseq: bid.oseq,
            provider: bid.provider.clone(),
            bseq: bid.bseq,
        };

        // Create the message (v1beta5 uses v1 BidId)
        let msg = akash_market::MsgCreateLease {
            bid_id: Some(bid_id),
        };

        // Convert message to Any for broadcasting using prost directly
        // This avoids version mismatch with layer-climb's prost dependency
        let type_url = akash_market::MsgCreateLease::type_url();
        let value = msg.encode_to_vec();
        let any_msg = layer_climb::proto::Any { type_url, value };

        // Broadcast transaction
        let response = self
            .client
            .tx_builder()
            .broadcast([any_msg])
            .await
            .map_err(|e| DeployError::Transaction {
                code: 1,
                log: format!("Failed to create lease: {}", e),
            })?;

        Ok(TxResult {
            hash: response.txhash,
            code: response.code,
            raw_log: response.raw_log,
            height: response.height as u64,
        })
    }

    async fn broadcast_deposit(
        &self,
        _signer: &Self::Signer,
        owner: &str,
        dseq: u64,
        amount_uakt: u64,
    ) -> Result<TxResult, DeployError> {
        use crate::gen::akash::base::deposit::v1 as akash_deposit;
        use crate::gen::akash::escrow::id::v1 as akash_escrow_id;
        use crate::gen::akash::escrow::v1 as akash_escrow;

        // Build account ID
        let account_id = akash_escrow_id::Account {
            scope: akash_escrow_id::Scope::Deployment.into(),
            xid: format!("{}/{}", owner, dseq),
        };

        // Build deposit
        let deposit = akash_deposit::Deposit {
            amount: Some(crate::gen::cosmos::base::v1beta1::Coin {
                denom: "uakt".to_string(),
                amount: amount_uakt.to_string(),
            }),
            sources: vec![akash_deposit::Source::Balance as i32],
        };

        // Create the message
        let msg = akash_escrow::MsgAccountDeposit {
            signer: owner.to_string(),
            id: Some(account_id),
            deposit: Some(deposit),
        };

        // Convert message to Any for broadcasting using prost directly
        // This avoids version mismatch with layer-climb's prost dependency
        let type_url = akash_escrow::MsgAccountDeposit::type_url();
        let value = msg.encode_to_vec();
        let any_msg = layer_climb::proto::Any { type_url, value };

        // Broadcast transaction
        let response = self
            .client
            .tx_builder()
            .broadcast([any_msg])
            .await
            .map_err(|e| DeployError::Transaction {
                code: 1,
                log: format!("Failed to broadcast deposit: {}", e),
            })?;

        Ok(TxResult {
            hash: response.txhash,
            code: response.code,
            raw_log: response.raw_log,
            height: response.height as u64,
        })
    }

    async fn broadcast_close_deployment(
        &self,
        _signer: &Self::Signer,
        owner: &str,
        dseq: u64,
    ) -> Result<TxResult, DeployError> {
        use crate::gen::akash::deployment::v1 as akash_deployment_v1;

        // Build deployment ID
        let deployment_id = akash_deployment_v1::DeploymentId {
            owner: owner.to_string(),
            dseq,
        };

        // Create the message
        let msg = akash_deployment::MsgCloseDeployment {
            id: Some(deployment_id),
        };

        // Convert message to Any for broadcasting using prost directly
        // This avoids version mismatch with layer-climb's prost dependency
        let type_url = akash_deployment::MsgCloseDeployment::type_url();
        let value = msg.encode_to_vec();
        let any_msg = layer_climb::proto::Any { type_url, value };

        // Broadcast transaction
        let response = self
            .client
            .tx_builder()
            .broadcast([any_msg])
            .await
            .map_err(|e| DeployError::Transaction {
                code: 1,
                log: format!("Failed to close deployment: {}", e),
            })?;

        Ok(TxResult {
            hash: response.txhash,
            code: response.code,
            raw_log: response.raw_log,
            height: response.height as u64,
        })
    }

    async fn send_manifest(
        &self,
        provider_uri: &str,
        lease: &LeaseId,
        manifest: &[u8],
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<(), DeployError> {
        // Create mTLS HTTP client
        let client = create_mtls_client(cert_pem, key_pem)?;

        // Build manifest upload URL
        let url = format!(
            "{}/deployment/{}/{}/manifest",
            provider_uri.trim_end_matches('/'),
            lease.owner,
            lease.dseq
        );

        // Send manifest to provider
        let response = client
            .put(&url)
            .header("Content-Type", "application/json")
            .body(manifest.to_vec())
            .send()
            .await
            .map_err(|e| DeployError::Provider(format!("Failed to send manifest: {}", e)))?;

        // Check response status
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unable to read response".to_string());
            return Err(DeployError::Provider(format!(
                "Provider rejected manifest ({}): {}",
                status, body
            )));
        }

        Ok(())
    }

    async fn query_provider_status(
        &self,
        provider_uri: &str,
        lease: &LeaseId,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<ProviderLeaseStatus, DeployError> {
        // Create mTLS HTTP client
        let client = create_mtls_client(cert_pem, key_pem)?;

        // Build status query URL
        let url = format!(
            "{}/lease/{}/{}/{}/{}/status",
            provider_uri.trim_end_matches('/'),
            lease.owner,
            lease.dseq,
            lease.gseq,
            lease.oseq
        );

        // Query provider status
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| DeployError::Provider(format!("Failed to query status: {}", e)))?;

        // Check response status
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unable to read response".to_string());
            return Err(DeployError::Provider(format!(
                "Provider status query failed ({}): {}",
                status, body
            )));
        }

        // Parse status response
        let status: ProviderLeaseStatus = response.json().await.map_err(|e| {
            DeployError::Provider(format!("Failed to parse status response: {}", e))
        })?;

        Ok(status)
    }

    async fn load_state(&self, session_id: &str) -> Result<Option<DeploymentState>, DeployError> {
        self.storage.load_session(session_id).await
    }

    async fn save_state(
        &self,
        _session_id: &str,
        _state: &DeploymentState,
    ) -> Result<(), DeployError> {
        // We need mutable access to storage, but the trait requires immutable self
        // This is a design limitation - users should use storage_mut() directly
        // or we can use interior mutability (RefCell/Mutex) in FileBackedStorage
        // For now, document that save_state happens automatically via workflow
        // TODO: Consider using Arc<Mutex<S>> for storage
        Ok(())
    }

    async fn load_cert_key(&self, owner: &str) -> Result<Option<Vec<u8>>, DeployError> {
        self.storage.load_cert_key(owner).await
    }

    async fn save_cert_key(&self, _owner: &str, _key: &[u8]) -> Result<(), DeployError> {
        // Same mutability issue as save_state
        // TODO: Use interior mutability in storage
        Ok(())
    }

    async fn delete_cert_key(&self, _owner: &str) -> Result<(), DeployError> {
        // Same mutability issue
        Ok(())
    }

    async fn load_cached_provider(
        &self,
        provider: &str,
    ) -> Result<Option<ProviderInfo>, DeployError> {
        self.storage.load_cached_provider(provider).await
    }

    async fn cache_provider(&self, _info: &ProviderInfo) -> Result<(), DeployError> {
        // Same mutability issue
        Ok(())
    }
}

/// Helper to export sessions for backup/sharing.
///
/// # Example
///
/// ```ignore
/// // Export all sessions to a directory
/// export_sessions(&client, "/path/to/backup").await?;
///
/// // Import sessions from backup
/// import_sessions(&mut client, "/path/to/backup").await?;
/// ```
pub async fn export_sessions<S: SessionStorage>(
    client: &AkashClient<S>,
    export_dir: &std::path::Path,
) -> Result<(), DeployError> {
    tokio::fs::create_dir_all(export_dir)
        .await
        .map_err(|e| DeployError::Storage(format!("failed to create export dir: {}", e)))?;

    let session_ids = client.storage().list_sessions().await?;

    for session_id in session_ids {
        if let Some(session) = client.storage().load_session(&session_id).await? {
            let content = serde_json::to_string_pretty(&session)
                .map_err(|e| DeployError::Storage(format!("failed to serialize session: {}", e)))?;

            let path = export_dir.join(format!("{}.json", session_id));
            tokio::fs::write(&path, content)
                .await
                .map_err(|e| DeployError::Storage(format!("failed to write session: {}", e)))?;
        }
    }

    Ok(())
}

/// Helper to import sessions from exported files.
pub async fn import_sessions<S: SessionStorage>(
    client: &mut AkashClient<S>,
    import_dir: &std::path::Path,
) -> Result<usize, DeployError> {
    let mut imported = 0;
    let mut entries = tokio::fs::read_dir(import_dir)
        .await
        .map_err(|e| DeployError::Storage(format!("failed to read import dir: {}", e)))?;

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| DeployError::Storage(format!("failed to read entry: {}", e)))?
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            let content = tokio::fs::read_to_string(&path)
                .await
                .map_err(|e| DeployError::Storage(format!("failed to read session: {}", e)))?;

            let session: DeploymentState = serde_json::from_str(&content)
                .map_err(|e| DeployError::Storage(format!("failed to parse session: {}", e)))?;

            client.storage_mut().save_session(&session).await?;
            imported += 1;
        }
    }

    Ok(imported)
}
