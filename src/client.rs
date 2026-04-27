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

use crate::auth::jwt::{JwtBuilder, JwtClaims};
use crate::error::DeployError;
use crate::state::DeploymentState;
#[cfg(feature = "file-storage")]
use crate::store::FileBackedStorage;
use crate::store::SessionStorage;
use crate::traits::AkashBackend;
use crate::types::*;

use bip32::{DerivationPath, XPrv};
use coins_bip39::{English, Mnemonic};
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use layer_climb::prelude::*;
use layer_climb::transaction::{SequenceStrategy, SequenceStrategyKind};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use tokio::sync::RwLock;

// Import Akash proto types
use crate::gen::akash::{deployment::v1beta4 as akash_deployment, market::v1beta5 as akash_market};
use prost::{Message as ProstMessage, Name as ProstName};

/// Convert a prost message into a `layer_climb::proto::Any` for broadcasting.
///
/// This avoids version mismatch with layer-climb's prost dependency by using
/// prost's `encode_to_vec` and `type_url` directly.
fn to_any<M: ProstMessage + ProstName>(msg: &M) -> layer_climb::proto::Any {
    layer_climb::proto::Any {
        type_url: M::type_url(),
        value: msg.encode_to_vec(),
    }
}

/// Build a `MsgMintACT` as an `Any`-encoded proto message.
///
/// Does NOT broadcast — returns the message for inclusion in a multi-msg
/// batch (e.g. prepended before `MsgCreateDeployment` to ensure ACT funds).
pub fn build_mint_act_msg(owner: &str, amount_uakt: u64) -> layer_climb::proto::Any {
    use crate::gen::akash::bme::v1 as akash_bme;

    let msg = akash_bme::MsgMintAct {
        owner: owner.to_string(),
        to: owner.to_string(),
        coins_to_burn: Some(crate::gen::cosmos::base::v1beta1::Coin {
            denom: "uakt".to_string(),
            amount: amount_uakt.to_string(),
        }),
    };

    tracing::info!(
        owner,
        amount_uakt,
        "build_mint_act_msg: built (not broadcast)"
    );

    to_any(&msg)
}

/// Build a `MsgCreateLease` as an `Any`-encoded proto message.
///
/// Does NOT broadcast — returns the message for inclusion in a multi-msg
/// batch (e.g. batching lease acceptances for multiple deployments in a
/// single signed transaction via `broadcast_multi_signer`).
pub fn build_create_lease_msg(bid: &BidId) -> layer_climb::proto::Any {
    use crate::gen::akash::market::v1 as akash_market_v1;

    let bid_id = akash_market_v1::BidId {
        owner: bid.owner.clone(),
        dseq: bid.dseq,
        gseq: bid.gseq,
        oseq: bid.oseq,
        provider: bid.provider.clone(),
        bseq: bid.bseq,
    };

    let msg = akash_market::MsgCreateLease {
        bid_id: Some(bid_id),
    };

    tracing::info!(
        owner = %bid.owner, dseq = bid.dseq, provider = %bid.provider,
        "build_create_lease_msg: built (not broadcast)"
    );

    to_any(&msg)
}

/// Build a `MsgCloseDeployment` as an `Any`-encoded proto message.
///
/// Does NOT broadcast — returns the message for inclusion in a multi-msg
/// batch (e.g. batching close operations for multiple deployments in a
/// single signed transaction via `broadcast_multi_signer`).
pub fn build_close_deployment_msg(owner: &str, dseq: u64) -> layer_climb::proto::Any {
    use crate::gen::akash::deployment::v1 as akash_deployment_v1;

    let msg = akash_deployment::MsgCloseDeployment {
        id: Some(akash_deployment_v1::DeploymentId {
            owner: owner.to_string(),
            dseq,
        }),
    };

    to_any(&msg)
}

/// Build a `MsgSend` as an `Any`-encoded proto message.
///
/// Does NOT broadcast — returns the message for inclusion in a multi-msg batch.
pub fn build_bank_send_msg(
    from: &str,
    to: &str,
    amount: u64,
    denom: &str,
) -> layer_climb::proto::Any {
    // MsgSend defined inline to avoid pulling cosmos bank proto as a top-level dep.
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct MsgSend {
        #[prost(string, tag = "1")]
        from_address: String,
        #[prost(string, tag = "2")]
        to_address: String,
        #[prost(message, repeated, tag = "3")]
        amount: Vec<crate::gen::cosmos::base::v1beta1::Coin>,
    }
    impl ::prost::Name for MsgSend {
        const NAME: &'static str = "MsgSend";
        const PACKAGE: &'static str = "cosmos.bank.v1beta1";
        fn full_name() -> String {
            "cosmos.bank.v1beta1.MsgSend".into()
        }
        fn type_url() -> String {
            "/cosmos.bank.v1beta1.MsgSend".into()
        }
    }

    to_any(&MsgSend {
        from_address: from.to_string(),
        to_address: to.to_string(),
        amount: vec![crate::gen::cosmos::base::v1beta1::Coin {
            denom: denom.to_string(),
            amount: amount.to_string(),
        }],
    })
}

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
    pub bme: crate::gen::akash::bme::v1::query_client::QueryClient<tonic::transport::Channel>,
}

impl QueryClients {
    /// Create all query clients by connecting to the gRPC endpoint.
    pub async fn new(grpc_endpoint: &str) -> Result<Self, DeployError> {
        tracing::info!(endpoint = %grpc_endpoint, "connecting gRPC query clients");
        use crate::gen::akash::{
            bme::v1 as akash_bme, cert::v1 as akash_cert, escrow::v1 as akash_escrow,
            market::v1beta5 as akash_market, provider::v1beta4 as akash_provider,
        };

        tracing::debug!("  connecting cert query client...");
        let cert = akash_cert::query_client::QueryClient::connect(grpc_endpoint.to_string())
            .await
            .map_err(|e| {
                tracing::error!(%e, "failed to connect cert query client");
                DeployError::Query(format!("Failed to connect cert client: {}", e))
            })?;
        tracing::debug!("  cert query client connected");

        tracing::debug!("  connecting provider query client...");
        let provider =
            akash_provider::query_client::QueryClient::connect(grpc_endpoint.to_string())
                .await
                .map_err(|e| {
                    tracing::error!(%e, "failed to connect provider query client");
                    DeployError::Query(format!("Failed to connect provider client: {}", e))
                })?;
        tracing::debug!("  provider query client connected");

        tracing::debug!("  connecting market query client...");
        let market = akash_market::query_client::QueryClient::connect(grpc_endpoint.to_string())
            .await
            .map_err(|e| {
                tracing::error!(%e, "failed to connect market query client");
                DeployError::Query(format!("Failed to connect market client: {}", e))
            })?;
        tracing::debug!("  market query client connected");

        tracing::debug!("  connecting escrow query client...");
        let escrow = akash_escrow::query_client::QueryClient::connect(grpc_endpoint.to_string())
            .await
            .map_err(|e| {
                tracing::error!(%e, "failed to connect escrow query client");
                DeployError::Query(format!("Failed to connect escrow client: {}", e))
            })?;
        tracing::debug!("  escrow query client connected");

        tracing::debug!("  connecting bme query client...");
        let bme = akash_bme::query_client::QueryClient::connect(grpc_endpoint.to_string())
            .await
            .map_err(|e| {
                tracing::error!(%e, "failed to connect bme query client");
                DeployError::Query(format!("Failed to connect bme client: {}", e))
            })?;
        tracing::debug!("  bme query client connected");

        tracing::info!("all gRPC query clients connected successfully");

        Ok(Self {
            cert,
            provider,
            market,
            escrow,
            bme,
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
/// - `S`: Storage implementation.
///   - With `file-storage` feature: defaults to `FileBackedStorage` (disk persistence)
///   - Without `file-storage`: defaults to `StdoutStorage` (JSON to stdout, no persistence)
///   - Use `AkashClient::with_storage()` for custom backends (DB, WASM, etc.)
#[cfg(feature = "file-storage")]
pub struct AkashClient<S: SessionStorage = FileBackedStorage> {
    /// Layer-climb signing client for chain communication
    client: SigningClient,

    /// Generic storage backend (behind RwLock for interior mutability).
    /// The `AkashBackend` trait requires `&self` but `SessionStorage` write
    /// methods need `&mut self` — the lock bridges this gap.
    storage: RwLock<S>,

    /// Owner address (cached from signer)
    address: Address,

    /// Reusable gRPC query clients
    query_clients: Option<QueryClients>,

    /// secp256k1 signing key for JWT generation (ES256K)
    jwt_signing_key: Option<SigningKey>,

    /// Cosmos REST (gRPC-Gateway) base URL. When set, Akash chain queries
    /// (bids, leases, certs, etc.) use REST instead of gRPC.
    rest_endpoint: Option<String>,

    /// AuthZ granter address. When set, all broadcast messages are wrapped
    /// in `MsgExec` and `Fee.granter` is set for fee delegation.
    authz_granter: Option<String>,
}

/// See [`AkashClient`] — this variant defaults to `StdoutStorage` when
/// the `file-storage` feature is not enabled.
#[cfg(not(feature = "file-storage"))]
pub struct AkashClient<S: SessionStorage = StdoutStorage> {
    /// Layer-climb signing client for chain communication
    client: SigningClient,

    /// Generic storage backend (behind RwLock for interior mutability).
    /// The `AkashBackend` trait requires `&self` but `SessionStorage` write
    /// methods need `&mut self` — the lock bridges this gap.
    storage: RwLock<S>,

    /// Owner address (cached from signer)
    address: Address,

    /// Reusable gRPC query clients
    query_clients: Option<QueryClients>,

    /// secp256k1 signing key for JWT generation (ES256K)
    jwt_signing_key: Option<SigningKey>,

    /// Cosmos REST (gRPC-Gateway) base URL. When set, Akash chain queries
    /// (bids, leases, certs, etc.) use REST instead of gRPC.
    rest_endpoint: Option<String>,

    /// AuthZ granter address. When set, all broadcast messages are wrapped
    /// in `MsgExec` and `Fee.granter` is set for fee delegation.
    authz_granter: Option<String>,
}

/// Intermediate result from the common client init steps (signer, chain config, RPC, gRPC).
struct ClientInit {
    client: SigningClient,
    address: Address,
    query_clients: Option<QueryClients>,
    jwt_signing_key: SigningKey,
}

/// Query the chain_id from a Tendermint RPC `/status` endpoint.
///
/// Falls back to `"akashnet-2"` if the query fails (e.g. node not up yet in tests).
async fn query_chain_id_from_rpc(rpc_endpoint: &str) -> String {
    let url = format!("{}/status", rpc_endpoint.trim_end_matches('/'));
    match reqwest::get(&url).await {
        Ok(resp) => {
            match resp.json::<serde_json::Value>().await {
                Ok(v) => {
                    // Tendermint wraps result: {"result": {"node_info": {"network": "..."}}}
                    if let Some(chain_id) = v
                        .pointer("/result/node_info/network")
                        .and_then(|v| v.as_str())
                    {
                        tracing::info!(chain_id, "auto-detected chain_id from RPC /status");
                        return chain_id.to_string();
                    }
                    tracing::warn!(
                        "chain_id not found in /status response; defaulting to akashnet-2"
                    );
                }
                Err(e) => {
                    tracing::warn!(%e, "failed to parse /status JSON; defaulting to akashnet-2")
                }
            }
        }
        Err(e) => tracing::warn!(%e, "failed to GET /status; defaulting to akashnet-2"),
    }
    "akashnet-2".to_string()
}

/// Common initialization: mnemonic → signer → chain config → signing client → gRPC clients.
/// Storage creation is left to the caller so it can differ by feature flag.
async fn init_client_core(
    mnemonic: &str,
    rpc_endpoint: &str,
    grpc_endpoint: &str,
) -> Result<ClientInit, DeployError> {
    init_client_core_at_index(mnemonic, rpc_endpoint, grpc_endpoint, None).await
}

/// Like `init_client_core` but derives the signer and JWT key at a specific
/// BIP44 HD index (`m/44'/118'/0'/0/{index}`).  When `hd_index` is `None`,
/// behaviour is identical to the original `init_client_core`.
async fn init_client_core_at_index(
    mnemonic: &str,
    rpc_endpoint: &str,
    grpc_endpoint: &str,
    hd_index: Option<u32>,
) -> Result<ClientInit, DeployError> {
    tracing::info!("starting client initialization");

    // Step 1: Create the key signer from mnemonic (optionally at child index)
    tracing::info!("step 1/5: creating key signer from mnemonic");
    let derivation_path = hd_index
        .map(|i| {
            format!("m/44'/118'/0'/0/{}", i)
                .parse::<DerivationPath>()
                .map_err(|e| DeployError::Signer(format!("Invalid HD path: {}", e)))
        })
        .transpose()?;
    let signer = KeySigner::new_mnemonic_str(mnemonic, derivation_path.as_ref()).map_err(|e| {
        tracing::error!(?e, "failed to create signer from mnemonic");
        DeployError::Signer(format!("Failed to create signer from mnemonic: {}", e))
    })?;
    tracing::info!("step 1/5: key signer created successfully");

    // Step 2: Derive secp256k1 signing key for JWT (ES256K) from the same mnemonic
    tracing::info!("step 2/5: deriving JWT signing key (ES256K)");
    let jwt_signing_key = derive_jwt_signing_key_at_index(mnemonic, hd_index)?;
    tracing::info!("step 2/5: JWT signing key derived successfully");

    // Step 3: Set up Akash chain configuration
    // NOTE: We intentionally omit gRPC from the SigningClient config so that
    // layer-climb uses RPC for all tx operations (simulate, broadcast, poll).
    // gRPC is only used for our custom Akash query clients (bids, leases, etc.).
    tracing::info!(
        rpc = %rpc_endpoint,
        grpc = %grpc_endpoint,
        "step 3/5: building chain config"
    );
    let grpc_ep = if grpc_endpoint.is_empty() {
        None
    } else {
        // Ensure the endpoint has a scheme — tonic requires a valid URI.
        let ep = grpc_endpoint.to_string();
        let ep = if !ep.starts_with("http://") && !ep.starts_with("https://") {
            format!("https://{}", ep)
        } else {
            ep
        };
        Some(ep)
    };

    let chain_id = query_chain_id_from_rpc(rpc_endpoint).await;
    let chain_config = ChainConfig {
        chain_id: ChainId::new(&chain_id),
        address_kind: AddrKind::Cosmos {
            prefix: "akash".to_string(),
        },
        gas_price: 0.025,
        gas_denom: "uakt".to_string(),
        rpc_endpoint: Some(rpc_endpoint.to_string()),
        grpc_endpoint: None, // Use RPC for all tx operations
        grpc_web_endpoint: None,
    };
    tracing::info!(
        chain_id,
        rpc = %rpc_endpoint,
        "step 3/5: chain config built"
    );

    // Step 4: Create the signing client (connects to RPC)
    tracing::info!("step 4/5: creating signing client (connecting to RPC endpoint)...");
    let mut client = SigningClient::new(chain_config, signer, None::<Connection>)
        .await
        .map_err(|e| {
            tracing::error!(%e, "step 4/5 FAILED: signing client creation error");
            DeployError::Query(format!("Failed to create signing client: {:#}", e))
        })?;
    tracing::info!(address = %client.addr, "step 4/5: signing client created successfully");

    // Use Query: always queries sequence fresh from chain (safe for retries and error paths).
    client.sequence_strategy = SequenceStrategy::new(SequenceStrategyKind::Query);

    let address = client.addr.clone();

    // Step 5: Initialize query clients if gRPC endpoint is configured.
    // Failure is non-fatal: log a warning and continue without gRPC.
    // Queries will use the REST endpoint if configured, or attempt lazy gRPC init later.
    let query_clients = if let Some(ref endpoint) = grpc_ep {
        tracing::info!(endpoint = %endpoint, "step 5/5: connecting gRPC query clients");
        match QueryClients::new(endpoint).await {
            Ok(clients) => {
                tracing::info!("step 5/5: gRPC query clients connected");
                Some(clients)
            }
            Err(e) => {
                tracing::warn!(
                    endpoint = %endpoint,
                    error = %e,
                    "step 5/5: gRPC unavailable — queries will use REST or lazy-init"
                );
                None
            }
        }
    } else {
        tracing::info!("step 5/5: skipped (no gRPC endpoint configured)");
        None
    };

    Ok(ClientInit {
        client,
        address,
        query_clients,
        jwt_signing_key,
    })
}

/// With `file-storage`: `new_from_mnemonic` persists to `~/.akash-deploy`.
#[cfg(feature = "file-storage")]
impl AkashClient<FileBackedStorage> {
    /// Create a new client with file-backed storage (`~/.akash-deploy`).
    ///
    /// Requires the `file-storage` feature.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let client = AkashClient::new_from_mnemonic(
    ///     "your twelve word mnemonic phrase here",
    ///     "https://rpc.akashnet.net:443",
    ///     "https://grpc.akashnet.net:443",
    /// ).await?;
    /// ```
    pub async fn new_from_mnemonic(
        mnemonic: &str,
        rpc_endpoint: &str,
        grpc_endpoint: &str,
    ) -> Result<Self, DeployError> {
        let init = init_client_core(mnemonic, rpc_endpoint, grpc_endpoint).await?;

        tracing::info!("initializing file-backed storage (~/.akash-deploy)");
        let storage = FileBackedStorage::new_default().await?;
        tracing::info!("file-backed storage initialized");

        tracing::info!(address = %init.address, "client initialization complete (file-storage)");

        Ok(Self {
            client: init.client,
            storage: RwLock::new(storage),
            address: init.address,
            query_clients: init.query_clients,
            jwt_signing_key: Some(init.jwt_signing_key),
            rest_endpoint: None,
            authz_granter: None,
        })
    }

    /// Create a new client at a specific BIP44 HD child index.
    ///
    /// Derives the signer and JWT key at `m/44'/118'/0'/0/{hd_index}` instead
    /// of the default index 0.  Used by parallel deployment to give each phase
    /// its own signing account.
    pub async fn new_from_mnemonic_at_index(
        mnemonic: &str,
        hd_index: u32,
        rpc_endpoint: &str,
        grpc_endpoint: &str,
    ) -> Result<Self, DeployError> {
        let init = init_client_core_at_index(mnemonic, rpc_endpoint, grpc_endpoint, Some(hd_index))
            .await?;

        let storage = FileBackedStorage::new_default().await?;

        tracing::info!(
            address = %init.address,
            hd_index,
            "client initialization complete (file-storage, child account)"
        );

        Ok(Self {
            client: init.client,
            storage: RwLock::new(storage),
            address: init.address,
            query_clients: init.query_clients,
            jwt_signing_key: Some(init.jwt_signing_key),
            rest_endpoint: None,
            authz_granter: None,
        })
    }
}

/// Without `file-storage`: `new_from_mnemonic` uses stdout (JSON output, no persistence).
#[cfg(not(feature = "file-storage"))]
impl AkashClient<StdoutStorage> {
    /// Create a new client with stdout storage (JSON to stdout, no persistence).
    ///
    /// State is printed as JSON to stdout for interoperability with external tools.
    /// For disk persistence, enable the `file-storage` feature.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let client = AkashClient::new_from_mnemonic(
    ///     "your twelve word mnemonic phrase here",
    ///     "https://rpc.akashnet.net:443",
    ///     "https://grpc.akashnet.net:443",
    /// ).await?;
    /// ```
    pub async fn new_from_mnemonic(
        mnemonic: &str,
        rpc_endpoint: &str,
        grpc_endpoint: &str,
    ) -> Result<Self, DeployError> {
        let init = init_client_core(mnemonic, rpc_endpoint, grpc_endpoint).await?;

        tracing::info!("using stdout storage (no file-storage feature)");

        tracing::info!(address = %init.address, "client initialization complete (stdout-storage)");

        Ok(Self {
            client: init.client,
            storage: RwLock::new(StdoutStorage::new()),
            address: init.address,
            query_clients: init.query_clients,
            jwt_signing_key: Some(init.jwt_signing_key),
            rest_endpoint: None,
            authz_granter: None,
        })
    }

    /// Create a new client at a specific BIP44 HD child index (stdout storage).
    pub async fn new_from_mnemonic_at_index(
        mnemonic: &str,
        hd_index: u32,
        rpc_endpoint: &str,
        grpc_endpoint: &str,
    ) -> Result<Self, DeployError> {
        let init = init_client_core_at_index(mnemonic, rpc_endpoint, grpc_endpoint, Some(hd_index))
            .await?;

        tracing::info!(
            address = %init.address,
            hd_index,
            "client initialization complete (stdout-storage, child account)"
        );

        Ok(Self {
            client: init.client,
            storage: RwLock::new(StdoutStorage::new()),
            address: init.address,
            query_clients: init.query_clients,
            jwt_signing_key: Some(init.jwt_signing_key),
            rest_endpoint: None,
            authz_granter: None,
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
            storage: RwLock::new(storage),
            address,
            query_clients: None, // Will be initialized lazily on first query
            jwt_signing_key: None,
            rest_endpoint: None,
            authz_granter: None,
        }
    }

    /// Set the gRPC endpoint, forcing lazy re-init of query clients.
    pub fn with_grpc(mut self, endpoint: impl Into<String>) -> Self {
        self.client.querier.chain_config.grpc_endpoint = Some(endpoint.into());
        self.query_clients = None; // force lazy re-init
        self
    }

    /// Set the RPC endpoint.
    pub fn with_rpc(mut self, endpoint: impl Into<String>) -> Self {
        self.client.querier.chain_config.rpc_endpoint = Some(endpoint.into());
        self
    }

    /// Set the REST (gRPC-Gateway) endpoint for Akash chain queries.
    ///
    /// When set, all Akash query methods (bids, leases, certs, providers,
    /// escrow, balance) use the Cosmos REST API instead of gRPC, avoiding
    /// 503 errors from unreliable gRPC endpoints.
    ///
    /// Endpoint format: `https://api.akashnet.net:443`
    pub fn with_rest(mut self, endpoint: impl Into<String>) -> Self {
        self.rest_endpoint = Some(endpoint.into());
        self
    }

    /// Enable AuthZ delegation mode.
    ///
    /// When set, broadcast methods wrap all messages in `MsgExec` and set
    /// `Fee.granter` so the granter pays gas via FeeGrant.
    pub fn with_authz_granter(mut self, granter: impl Into<String>) -> Self {
        self.authz_granter = Some(granter.into());
        self
    }

    /// Prepare a message for broadcast, applying AuthZ wrapping if configured.
    ///
    /// Returns the (possibly wrapped) message and configures the tx_builder
    /// with `fee_granter` when in authz mode.
    fn authz_prepare_msg(
        &self,
        msg: layer_climb::proto::Any,
        tx_builder: &mut layer_climb::prelude::TxBuilder<'_>,
    ) -> layer_climb::proto::Any {
        if let Some(ref granter) = self.authz_granter {
            tx_builder.set_fee_granter(granter);
            crate::authz::wrap_in_msg_exec(&self.address.to_string(), &[msg])
        } else {
            msg
        }
    }

    /// Get or initialize query clients.
    ///
    /// This lazily initializes the query clients on first access if they
    /// haven't been created yet.
    async fn get_query_clients(&self) -> Result<QueryClients, DeployError> {
        // If we already have clients, clone them (cheap - just clones the channel)
        if let Some(ref clients) = self.query_clients {
            tracing::debug!("reusing cached gRPC query clients");
            return Ok(QueryClients {
                cert: clients.cert.clone(),
                provider: clients.provider.clone(),
                market: clients.market.clone(),
                escrow: clients.escrow.clone(),
                bme: clients.bme.clone(),
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

    /// Get the storage lock for direct access.
    ///
    /// Use `.read().await` for read-only access or `.write().await` for mutations.
    pub fn storage(&self) -> &RwLock<S> {
        &self.storage
    }

    /// Send coins from this account to another address (cosmos.bank MsgSend).
    ///
    /// Common use: faucet funding, pre-test account seeding.
    pub async fn bank_send(
        &self,
        to: &str,
        amount: u128,
        denom: &str,
    ) -> Result<TxResult, DeployError> {
        // MsgSend defined inline — avoids pulling in a separate cosmos-sdk proto crate.
        #[derive(Clone, PartialEq, ::prost::Message)]
        struct MsgSend {
            #[prost(string, tag = "1")]
            from_address: String,
            #[prost(string, tag = "2")]
            to_address: String,
            #[prost(message, repeated, tag = "3")]
            amount: Vec<crate::gen::cosmos::base::v1beta1::Coin>,
        }
        impl ::prost::Name for MsgSend {
            const NAME: &'static str = "MsgSend";
            const PACKAGE: &'static str = "cosmos.bank.v1beta1";
            fn full_name() -> String {
                "cosmos.bank.v1beta1.MsgSend".into()
            }
            fn type_url() -> String {
                "/cosmos.bank.v1beta1.MsgSend".into()
            }
        }
        self.broadcast_any_msg(MsgSend {
            from_address: self.address().to_string(),
            to_address: to.to_string(),
            amount: vec![crate::gen::cosmos::base::v1beta1::Coin {
                denom: denom.to_string(),
                amount: amount.to_string(),
            }],
        })
        .await
    }

    /// Send coins to multiple recipients in a single transaction.
    ///
    /// Builds N `MsgSend` messages (same `from_address`, different `to_address`)
    /// and broadcasts them in one tx — single sequence number, one gas estimation,
    /// one confirmation.  Saves ~(N-1) × block_time compared to sequential sends.
    pub async fn bank_send_batch(
        &self,
        recipients: &[(&str, u128, &str)], // (to_addr, amount, denom)
    ) -> Result<TxResult, DeployError> {
        #[derive(Clone, PartialEq, ::prost::Message)]
        struct MsgSend {
            #[prost(string, tag = "1")]
            from_address: String,
            #[prost(string, tag = "2")]
            to_address: String,
            #[prost(message, repeated, tag = "3")]
            amount: Vec<crate::gen::cosmos::base::v1beta1::Coin>,
        }
        impl ::prost::Name for MsgSend {
            const NAME: &'static str = "MsgSend";
            const PACKAGE: &'static str = "cosmos.bank.v1beta1";
            fn full_name() -> String {
                "cosmos.bank.v1beta1.MsgSend".into()
            }
            fn type_url() -> String {
                "/cosmos.bank.v1beta1.MsgSend".into()
            }
        }

        if recipients.is_empty() {
            return Err(DeployError::InvalidState(
                "bank_send_batch: empty recipients list".into(),
            ));
        }

        let from = self.address().to_string();
        let msgs: Vec<layer_climb::proto::Any> = recipients
            .iter()
            .map(|(to, amount, denom)| {
                to_any(&MsgSend {
                    from_address: from.clone(),
                    to_address: to.to_string(),
                    amount: vec![crate::gen::cosmos::base::v1beta1::Coin {
                        denom: denom.to_string(),
                        amount: amount.to_string(),
                    }],
                })
            })
            .collect();

        tracing::info!(
            "bank_send_batch: {} MsgSend msgs in 1 tx from {}",
            msgs.len(),
            from
        );

        // Log account state for diagnostics.
        match self.client.querier.base_account(&self.address).await {
            Ok(acct) => tracing::info!(
                account_number = acct.account_number,
                sequence = acct.sequence,
                "tx: on-chain account state"
            ),
            Err(e) => tracing::warn!(%e, "tx: failed to query base_account"),
        }

        let mut tx = self.client.tx_builder();
        tx.set_gas_simulate_multiplier(1.5);
        tx.set_broadcast_poll_timeout_duration(std::time::Duration::from_secs(60));
        let response = tx
            .broadcast(msgs)
            .await
            .map_err(|e| DeployError::Transaction {
                code: 1,
                log: format!("{:#}", e),
            })?;
        Ok(TxResult {
            hash: response.txhash,
            code: response.code,
            raw_log: response.raw_log,
            height: response.height as u64,
        })
    }

    /// Build a `MsgCreateDeployment` as an `Any`-encoded proto message.
    ///
    /// Does NOT broadcast — returns the message for inclusion in a multi-signer
    /// batch. The caller provides `dseq` so all deployments in a batch can use
    /// the same block height.
    pub fn build_create_deployment_msg(
        &self,
        owner: &str,
        sdl_content: &str,
        deposit_amount: u64,
        deposit_denom: &str,
        dseq: u64,
    ) -> Result<layer_climb::proto::Any, DeployError> {
        use crate::gen::akash::base::deposit::v1 as akash_deposit;
        use crate::gen::akash::deployment::v1 as akash_deployment_v1;
        use sha2::{Digest, Sha256};

        crate::sdl::sdl::validate_sdl(sdl_content)?;
        let groups = crate::sdl::groupspec::build_groupspecs_from_sdl(sdl_content)?;

        let deployment_id = akash_deployment_v1::DeploymentId {
            owner: owner.to_string(),
            dseq,
        };

        let manifest_builder = crate::manifest::manifest::ManifestBuilder::new(owner, dseq);
        let manifest_groups = manifest_builder
            .build_from_sdl(sdl_content)
            .map_err(|e| DeployError::Sdl(format!("Manifest build failed: {}", e)))?;
        let manifest_json = crate::manifest::canonical::to_canonical_json(&manifest_groups)
            .map_err(|e| DeployError::Sdl(format!("Canonical manifest JSON failed: {}", e)))?;

        let sdl_hash = Sha256::digest(manifest_json.as_bytes()).to_vec();

        let deposit = akash_deposit::Deposit {
            amount: Some(crate::gen::cosmos::base::v1beta1::Coin {
                denom: deposit_denom.to_string(),
                amount: deposit_amount.to_string(),
            }),
            sources: vec![akash_deposit::Source::Balance as i32],
        };

        let msg = akash_deployment::MsgCreateDeployment {
            id: Some(deployment_id),
            groups,
            hash: sdl_hash,
            deposit: Some(deposit),
        };

        tracing::info!(
            owner, dseq, deposit_amount, deposit_denom,
            groups = msg.groups.len(),
            hash = %hex::encode(&msg.hash),
            "build_create_deployment_msg: built (not broadcast)"
        );

        Ok(to_any(&msg))
    }

    /// Broadcast any Cosmos/Akash message. Returns a TxResult on success.
    ///
    /// Encodes the message as a `google.protobuf.Any` and broadcasts it via
    /// the signing client. Useful for one-off message types (provider
    /// registration, bids, etc.) without needing a full workflow.
    pub async fn broadcast_any_msg<M: ProstMessage + ProstName>(
        &self,
        msg: M,
    ) -> Result<TxResult, DeployError> {
        let any = to_any(&msg);

        // Log account state so we can diagnose sequence/account_number issues.
        match self.client.querier.base_account(&self.address).await {
            Ok(acct) => tracing::info!(
                account_number = acct.account_number,
                sequence = acct.sequence,
                "tx: on-chain account state"
            ),
            Err(e) => {
                tracing::warn!(%e, "tx: failed to query base_account (account may not exist on-chain yet)")
            }
        }
        let mut tx = self.client.tx_builder();
        tx.set_gas_simulate_multiplier(1.5);
        tx.set_broadcast_poll_timeout_duration(std::time::Duration::from_secs(60));
        let broadcast_msg = self.authz_prepare_msg(any, &mut tx);
        let response =
            tx.broadcast([broadcast_msg])
                .await
                .map_err(|e| DeployError::Transaction {
                    code: 1,
                    log: format!("{:#}", e),
                })?;
        Ok(TxResult {
            hash: response.txhash,
            code: response.code,
            raw_log: response.raw_log,
            height: response.height as u64,
        })
    }

    /// Query bids via gRPC first, falling back to REST if configured.
    ///
    /// gRPC is preferred because it filters by dseq server-side and supports
    /// state filtering.  REST is used as a fallback when gRPC is unavailable.
    async fn query_bids_impl(&self, owner: &str, dseq: u64) -> Result<Vec<Bid>, DeployError> {
        tracing::debug!(owner, dseq, "query_bids: querying bids");

        // Try gRPC first.
        match self.query_bids_grpc(owner, dseq).await {
            Ok(bids) => return Ok(bids),
            Err(e) => {
                if let Some(ref api) = self.rest_endpoint {
                    tracing::warn!(error = %e, "query_bids: gRPC failed, falling back to REST");
                    return crate::rest::query_bids(api, owner, dseq).await;
                }
                return Err(e);
            }
        }
    }

    async fn query_bids_grpc(&self, owner: &str, dseq: u64) -> Result<Vec<Bid>, DeployError> {
        use crate::gen::akash::market::v1beta5 as akash_market;

        let mut clients = self.get_query_clients().await?;

        let response = clients
            .market
            .bids(akash_market::QueryBidsRequest {
                filters: Some(akash_market::BidFilters {
                    owner: owner.to_string(),
                    dseq,
                    gseq: 0,
                    oseq: 0,
                    provider: String::new(),
                    state: "open".to_string(),
                    bseq: 0,
                }),
                pagination: None,
            })
            .await
            .map_err(|e| DeployError::Query(format!("Failed to query bids: {}", e)))?
            .into_inner();

        tracing::debug!(
            raw_count = response.bids.len(),
            "query_bids: raw gRPC response"
        );

        let bids = response
            .bids
            .into_iter()
            .filter_map(|bid_response| {
                let bid = bid_response.bid?;
                let bid_id = bid.id?;
                let price = bid.price?;

                tracing::debug!(
                    provider = %bid_id.provider,
                    denom = %price.denom,
                    amount = %price.amount,
                    state = bid.state,
                    "query_bids: bid"
                );

                let raw_amount = price
                    .amount
                    .split('.')
                    .next()
                    .unwrap_or("0")
                    .parse::<u128>()
                    .ok()?;
                const DEC_PRECISION: u128 = 1_000_000_000_000_000_000;
                let price_amount = (raw_amount / DEC_PRECISION) as u64;

                Some(Bid {
                    provider: bid_id.provider,
                    price: price_amount,
                    price_denom: price.denom.clone(),
                    resources: Resources::default(),
                })
            })
            .collect::<Vec<_>>();

        tracing::debug!(parsed_count = bids.len(), "query_bids: done");
        Ok(bids)
    }
}

// ═══════════════════════════════════════════════════════════════════
// JWT KEY DERIVATION
// ═══════════════════════════════════════════════════════════════════

/// Derive secp256k1 signing key from mnemonic for JWT ES256K signing.
///
/// Uses the Cosmos HD path: m/44'/118'/0'/0/0
fn derive_jwt_signing_key(mnemonic: &str) -> Result<SigningKey, DeployError> {
    derive_jwt_signing_key_at_index(mnemonic, None)
}

/// Like `derive_jwt_signing_key` but derives at `m/44'/118'/0'/0/{index}` when
/// `hd_index` is `Some`.  Falls back to index 0 when `None`.
fn derive_jwt_signing_key_at_index(
    mnemonic: &str,
    hd_index: Option<u32>,
) -> Result<SigningKey, DeployError> {
    let path_str = match hd_index {
        Some(i) => format!("m/44'/118'/0'/0/{}", i),
        None => "m/44'/118'/0'/0/0".to_string(),
    };

    let parsed: Mnemonic<English> = mnemonic
        .parse()
        .map_err(|e| DeployError::Jwt(format!("invalid mnemonic: {:?}", e)))?;

    let seed_bytes = parsed
        .to_seed(None)
        .map_err(|e| DeployError::Jwt(format!("failed to derive seed: {:?}", e)))?;

    let child_key = XPrv::derive_from_path(
        seed_bytes,
        &path_str
            .parse()
            .map_err(|e| DeployError::Jwt(format!("invalid HD path: {}", e)))?,
    )
    .map_err(|e| DeployError::Jwt(format!("HD key derivation failed: {}", e)))?;

    SigningKey::from_bytes(child_key.private_key().to_bytes().as_slice().into())
        .map_err(|e| DeployError::Jwt(format!("invalid signing key: {}", e)))
}

/// Sign a JWT signing input with ES256K (SHA-256 + secp256k1).
///
/// Returns 64-byte compact signature (r || s).
fn sign_jwt_es256k(key: &SigningKey, message: &[u8]) -> Result<Vec<u8>, DeployError> {
    let msg_hash = Sha256::digest(message);
    let signature: Signature = key
        .sign_prehash(&msg_hash)
        .map_err(|e| DeployError::Jwt(format!("ES256K signing failed: {}", e)))?;
    Ok(signature.to_bytes().to_vec())
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

fn parse_provider_lease_status(body: &str) -> Result<ProviderLeaseStatus, DeployError> {
    let json: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| DeployError::Provider(format!("Invalid JSON in status response: {}", e)))?;

    tracing::debug!(
        "parse_provider_lease_status: raw response body length={}",
        body.len()
    );
    tracing::trace!("parse_provider_lease_status: {}", body);

    let mut endpoints = Vec::new();
    let mut ready = false;

    if let Some(services) = json.get("services").and_then(|s| s.as_object()) {
        for (name, service) in services {
            let available = service
                .get("available")
                .and_then(|a| a.as_u64())
                .unwrap_or(0);

            if available > 0 {
                ready = true;
            }

            if let Some(uris) = service.get("uris").and_then(|u| u.as_array()) {
                for uri_val in uris {
                    if let Some(uri) = uri_val.as_str() {
                        let full_uri = if uri.starts_with("http://") || uri.starts_with("https://")
                        {
                            uri.to_string()
                        } else {
                            format!("https://{}", uri)
                        };

                        let port = if full_uri.starts_with("https://") {
                            443u16
                        } else {
                            80u16
                        };

                        endpoints.push(ServiceEndpoint {
                            service: name.clone(),
                            uri: full_uri,
                            port,
                            internal_port: 0, // HTTP-ingress: no SDL-port mapping
                        });
                    }
                }
            }
        }
    }

    // Also parse forwarded_ports (raw TCP ports). These are NOT mutually
    // exclusive with services — a deployment can have both HTTP-routed
    // endpoints and TCP-forwarded ports.
    //
    // Akash provider JSON fields:
    //   "port"         → provider-assigned NodePort (what clients connect to)
    //   "externalPort" → SDL-specified internal port (e.g. 26656 or 26657)
    //
    // Each service can have multiple forwarded ports — iterate the entire array.
    if let Some(ports) = json.get("forwarded_ports").and_then(|p| p.as_object()) {
        for (service_name, port_info) in ports {
            let items: Vec<&serde_json::Value> = if let Some(arr) = port_info.as_array() {
                arr.iter().collect()
            } else {
                vec![port_info]
            };

            for item in items {
                if let Some(port_obj) = item.as_object() {
                    if let Some(host) = port_obj.get("host").and_then(|h| h.as_str()) {
                        // Akash provider JSON field semantics (confirmed by observed behavior):
                        //   "externalPort" = provider-assigned NodePort clients connect to (e.g. 32202)
                        //   "port"         = SDL-specified internal container port (e.g. 26656 / 26657)
                        let node_port = port_obj
                            .get("externalPort")
                            .and_then(|p| p.as_u64())
                            .unwrap_or(0);

                        if node_port == 0 {
                            continue;
                        }

                        // internal_port identifies the protocol: 26657 = RPC, 26656 = P2P.
                        let internal_port = port_obj
                            .get("port")
                            .and_then(|p| p.as_u64())
                            .unwrap_or(node_port)
                            as u16;

                        let uri = format!("http://{}:{}", host, node_port);

                        ready = true;
                        endpoints.push(ServiceEndpoint {
                            service: service_name.clone(),
                            uri,
                            port: node_port as u16,
                            internal_port,
                        });
                    }
                }
            }
        }
    }

    for ep in &endpoints {
        tracing::debug!(
            service = %ep.service,
            uri = %ep.uri,
            port = ep.port,
            internal_port = ep.internal_port,
            "parse_provider_lease_status: endpoint"
        );
    }
    tracing::debug!(
        ready,
        endpoint_count = endpoints.len(),
        "parse_provider_lease_status: done"
    );

    Ok(ProviderLeaseStatus { ready, endpoints })
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
        if let Some(cert) = self
            .storage
            .read()
            .await
            .load_cached_certificate(owner)
            .await?
        {
            return Ok(Some(cert));
        }

        // REST fallback
        if let Some(ref api) = self.rest_endpoint {
            return crate::rest::query_certificate(api, owner).await;
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
        if let Some(info) = self
            .storage
            .read()
            .await
            .load_cached_provider(provider)
            .await?
        {
            return Ok(Some(info));
        }

        // REST fallback
        if let Some(ref api) = self.rest_endpoint {
            return crate::rest::query_provider_info(api, provider).await;
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
        self.query_bids_impl(owner, dseq).await
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
        // REST fallback
        if let Some(ref api) = self.rest_endpoint {
            return crate::rest::query_lease(api, owner, dseq, gseq, oseq, bseq, provider).await;
        }

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

        let price_amount = price
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

        Ok(LeaseInfo {
            state,
            price: price_amount,
            price_denom: price.denom.clone(),
        })
    }

    async fn query_escrow(&self, owner: &str, dseq: u64) -> Result<EscrowInfo, DeployError> {
        // REST fallback
        if let Some(ref api) = self.rest_endpoint {
            return crate::rest::query_escrow(api, owner, dseq).await;
        }

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
        let balance_amount = account_state
            .funds
            .iter()
            .filter(|f| f.denom == "uakt")
            .filter_map(|f| f.amount.parse::<u64>().ok())
            .sum::<u64>();

        // For deposited amount, we can't easily calculate it from the current state,
        // so we'll use the same as balance for now
        // TODO: Track deposits separately if needed
        let deposited_amount = balance_amount;

        Ok(EscrowInfo {
            balance: balance_amount,
            balance_denom: "uakt".to_string(),
            deposited: deposited_amount,
            deposited_denom: "uakt".to_string(),
        })
    }

    async fn query_bme_status(&self) -> Result<BmeStatus, DeployError> {
        // REST fallback
        if let Some(ref api) = self.rest_endpoint {
            return crate::rest::query_bme_status(api).await;
        }

        use crate::gen::akash::bme::v1 as akash_bme;

        let mut clients = self.get_query_clients().await?;
        let response = clients
            .bme
            .status(akash_bme::QueryStatusRequest {})
            .await
            .map_err(|e| DeployError::Query(format!("Failed to query BME status: {}", e)))?
            .into_inner();

        let status_str = akash_bme::MintStatus::try_from(response.status)
            .map(|s| s.as_str_name().to_string())
            .unwrap_or_else(|_| format!("unknown({})", response.status));

        Ok(BmeStatus {
            mints_allowed: response.mints_allowed,
            status: status_str,
            collateral_ratio: response.collateral_ratio,
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

        let mut tx_builder = self.client.tx_builder();
        let cert_msg = to_any(&akash_cert::MsgCreateCertificate {
            owner: owner.to_string(),
            cert: cert_pem.to_vec(),
            pubkey: pubkey_pem.to_vec(),
        });
        let broadcast_msg = self.authz_prepare_msg(cert_msg, &mut tx_builder);
        let response =
            tx_builder
                .broadcast([broadcast_msg])
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
        deposit_amount: u64,
        deposit_denom: &str,
    ) -> Result<(TxResult, u64), DeployError> {
        use crate::gen::akash::base::deposit::v1 as akash_deposit;
        use crate::gen::akash::deployment::v1 as akash_deployment_v1;
        use sha2::{Digest, Sha256};

        // Validate SDL and build groups from it
        crate::sdl::sdl::validate_sdl(sdl_content)?;
        // Build GroupSpecs from SDL (groups services by placement)
        let groups = crate::sdl::groupspec::build_groupspecs_from_sdl(sdl_content)?;

        // Get current block height to use as dseq (standard Akash practice)
        let dseq: u64 = self.client.querier.block_height().await.map_err(|e| {
            DeployError::Query(format!("Failed to get block height for dseq: {}", e))
        })?;

        tracing::info!(dseq, owner, "using block height as deployment sequence");

        let deployment_id = akash_deployment_v1::DeploymentId {
            owner: owner.to_string(),
            dseq,
        };

        // Build manifest and hash its canonical JSON (must match what provider computes)
        let manifest_builder = crate::manifest::manifest::ManifestBuilder::new(owner, dseq);
        let manifest_groups = manifest_builder
            .build_from_sdl(sdl_content)
            .map_err(|e| DeployError::Sdl(format!("Manifest build failed: {}", e)))?;
        let manifest_json = crate::manifest::canonical::to_canonical_json(&manifest_groups)
            .map_err(|e| DeployError::Sdl(format!("Canonical manifest JSON failed: {}", e)))?;

        let sdl_hash = Sha256::digest(manifest_json.as_bytes()).to_vec();

        let deposit = akash_deposit::Deposit {
            amount: Some(crate::gen::cosmos::base::v1beta1::Coin {
                denom: deposit_denom.to_string(),
                amount: deposit_amount.to_string(),
            }),
            // Use Balance only — Grant requires an authz grant which
            // doesn't exist for fresh deployer accounts and may cause
            // the chain to silently reject the deposit.
            sources: vec![akash_deposit::Source::Balance as i32],
        };

        // Build the full message
        let msg = akash_deployment::MsgCreateDeployment {
            id: Some(deployment_id),
            groups,
            hash: sdl_hash,
            deposit: Some(deposit),
        };

        tracing::info!(
            owner,
            dseq,
            deposit_amount,
            deposit_denom,
            groups = msg.groups.len(),
            hash = %hex::encode(&msg.hash),
            "MsgCreateDeployment: broadcasting"
        );

        // Configure tx builder:
        // - 1.4x gas simulation multiplier for overhead
        // - Increase poll timeout to give nodes time to include the tx
        let mut tx_builder = self.client.tx_builder();
        tx_builder.set_gas_simulate_multiplier(1.4);
        tx_builder.set_broadcast_poll_timeout_duration(std::time::Duration::from_secs(60));

        let broadcast_msg = self.authz_prepare_msg(to_any(&msg), &mut tx_builder);
        let broadcast_result = tx_builder.broadcast([broadcast_msg]).await;

        match broadcast_result {
            Ok(response) => {
                // Normal success path
                let event_dseq = extract_dseq_from_events(&response.events);
                tracing::info!(
                    block_height_dseq = dseq,
                    event_dseq = ?event_dseq,
                    tx_hash = %response.txhash,
                    tx_code = response.code,
                    "deployment tx response"
                );
                tracing::debug!(
                    block_height_dseq = dseq,
                    event_dseq = ?event_dseq,
                    num_events = response.events.len(),
                    "create_deployment: tx events"
                );
                for (ei, event) in response.events.iter().enumerate() {
                    tracing::trace!(
                        event_index = ei,
                        event_type = %event.r#type,
                        "create_deployment: event"
                    );
                    for attr in &event.attributes {
                        tracing::trace!(key = %attr.key, value = %attr.value, "  attr");
                    }
                }

                let final_dseq = event_dseq.unwrap_or(dseq);
                tracing::info!(
                    final_dseq,
                    tx_hash = %response.txhash,
                    tx_code = response.code,
                    "create_deployment: complete"
                );

                Ok((
                    TxResult {
                        hash: response.txhash,
                        code: response.code,
                        raw_log: response.raw_log,
                        height: response.height as u64,
                    },
                    final_dseq,
                ))
            }
            Err(e) => {
                let err_str = e.to_string();

                // Handle "Missing response message" — a known gRPC issue where
                // the tx succeeds on-chain but the response is lost/truncated.
                // We recover by waiting and verifying the deployment exists.
                if err_str.contains("Missing response message") {
                    tracing::warn!(
                        dseq,
                        "gRPC returned 'Missing response message' — tx likely succeeded on-chain, verifying..."
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
                    match self.query_bids(owner, dseq).await {
                        Ok(bids) => {
                            tracing::info!(
                                dseq,
                                bid_count = bids.len(),
                                "Verified: deployment exists on-chain"
                            );
                            Ok((
                                TxResult {
                                    hash: String::new(),
                                    code: 0,
                                    raw_log: "gRPC response missing; verified on-chain".to_string(),
                                    height: 0,
                                },
                                dseq,
                            ))
                        }
                        Err(verify_err) => {
                            tracing::error!(error = %verify_err, "Deployment verification failed");
                            // Could not verify — report the original error
                            Err(DeployError::Transaction {
                                code: 1,
                                log: format!("Failed to broadcast transaction: {}", err_str),
                            })
                        }
                    }
                } else {
                    Err(DeployError::Transaction {
                        code: 1,
                        log: format!("Failed to broadcast transaction: {}", e),
                    })
                }
            }
        }
    }

    async fn broadcast_create_lease(
        &self,
        _signer: &Self::Signer,
        bid: &BidId,
    ) -> Result<TxResult, DeployError> {
        use crate::gen::akash::market::v1 as akash_market_v1;

        let bid_id = akash_market_v1::BidId {
            owner: bid.owner.clone(),
            dseq: bid.dseq,
            gseq: bid.gseq,
            oseq: bid.oseq,
            provider: bid.provider.clone(),
            bseq: bid.bseq,
        };

        let msg = akash_market::MsgCreateLease {
            bid_id: Some(bid_id),
        };

        eprintln!("═══ MsgCreateLease ═══");
        eprintln!("  owner: {}", bid.owner);
        eprintln!("  dseq: {}", bid.dseq);
        eprintln!(
            "  gseq: {}, oseq: {}, bseq: {}",
            bid.gseq, bid.oseq, bid.bseq
        );
        eprintln!("  provider: {}", bid.provider);
        eprintln!(
            "  type_url: {}",
            <akash_market::MsgCreateLease as ProstName>::type_url()
        );
        eprintln!("═══ Broadcasting... ═══");

        let mut tx_builder = self.client.tx_builder();
        tx_builder.set_gas_simulate_multiplier(1.4);
        tx_builder.set_broadcast_poll_timeout_duration(std::time::Duration::from_secs(60));

        let broadcast_msg = self.authz_prepare_msg(to_any(&msg), &mut tx_builder);
        let broadcast_result = tx_builder.broadcast([broadcast_msg]).await;

        match broadcast_result {
            Ok(response) => {
                eprintln!("  tx_hash: {}", response.txhash);
                eprintln!("  tx_code: {}", response.code);
                Ok(TxResult {
                    hash: response.txhash,
                    code: response.code,
                    raw_log: response.raw_log,
                    height: response.height as u64,
                })
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("Missing response message") {
                    eprintln!("WARNING: gRPC returned 'Missing response message' for CreateLease");
                    eprintln!("  Tx likely succeeded — returning synthetic success");
                    Ok(TxResult {
                        hash: String::new(),
                        code: 0,
                        raw_log: "gRPC response missing; tx likely succeeded".to_string(),
                        height: 0,
                    })
                } else {
                    Err(DeployError::Transaction {
                        code: 1,
                        log: format!("Failed to create lease: {}", e),
                    })
                }
            }
        }
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

        let deposit = akash_deposit::Deposit {
            amount: Some(crate::gen::cosmos::base::v1beta1::Coin {
                denom: "uakt".to_string(),
                amount: amount_uakt.to_string(),
            }),
            sources: vec![akash_deposit::Source::Balance as i32],
        };

        let response = self
            .client
            .tx_builder()
            .broadcast([to_any(&akash_escrow::MsgAccountDeposit {
                signer: owner.to_string(),
                id: Some(account_id),
                deposit: Some(deposit),
            })])
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

        let mut tx_builder = self.client.tx_builder();
        tx_builder.set_gas_simulate_multiplier(1.4);
        tx_builder.set_broadcast_poll_timeout_duration(std::time::Duration::from_secs(60));

        let close_msg = to_any(&akash_deployment::MsgCloseDeployment {
            id: Some(deployment_id),
        });
        let broadcast_msg = self.authz_prepare_msg(close_msg, &mut tx_builder);
        let broadcast_result = tx_builder.broadcast([broadcast_msg]).await;

        match broadcast_result {
            Ok(response) => Ok(TxResult {
                hash: response.txhash,
                code: response.code,
                raw_log: response.raw_log,
                height: response.height as u64,
            }),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("Missing response message") {
                    Ok(TxResult {
                        hash: String::new(),
                        code: 0,
                        raw_log: "gRPC response missing; tx likely succeeded".to_string(),
                        height: 0,
                    })
                } else {
                    Err(DeployError::Transaction {
                        code: 1,
                        log: format!("Failed to close deployment: {}", e),
                    })
                }
            }
        }
    }

    async fn broadcast_mint_act(
        &self,
        _signer: &Self::Signer,
        owner: &str,
        amount_uakt: u64,
    ) -> Result<TxResult, DeployError> {
        use crate::gen::akash::bme::v1 as akash_bme;

        let msg = akash_bme::MsgMintAct {
            owner: owner.to_string(),
            to: owner.to_string(),
            coins_to_burn: Some(crate::gen::cosmos::base::v1beta1::Coin {
                denom: "uakt".to_string(),
                amount: amount_uakt.to_string(),
            }),
        };

        tracing::info!(
            owner,
            amount_uakt,
            type_url = %<akash_bme::MsgMintAct as prost::Name>::type_url(),
            "broadcasting MsgMintACT"
        );

        self.broadcast_any_msg(msg).await
    }

    async fn generate_jwt(&self, owner: &str) -> Result<String, DeployError> {
        let signing_key = self
            .jwt_signing_key
            .as_ref()
            .ok_or_else(|| DeployError::Jwt("JWT signing key not configured".into()))?;

        let claims = JwtClaims::new(owner);
        let key = signing_key.clone();

        JwtBuilder::new().build_and_sign(&claims, |message| sign_jwt_es256k(&key, message))
    }

    async fn send_manifest(
        &self,
        provider_uri: &str,
        lease: &LeaseId,
        manifest: &[u8],
        auth: &ProviderAuth,
    ) -> Result<(), DeployError> {
        // URL format matches reference: /deployment/{dseq}/manifest
        // Owner is identified via JWT token, not in the URL path.
        let url = format!(
            "{}/deployment/{}/manifest",
            provider_uri.trim_end_matches('/'),
            lease.dseq
        );

        eprintln!("  manifest url: {}", url);

        // Build HTTP client once and reuse across retries (matches reference pattern)
        let http = match auth {
            ProviderAuth::Jwt { .. } => reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|e| {
                    DeployError::Provider(format!("Failed to create HTTP client: {}", e))
                })?,
            ProviderAuth::Mtls { cert_pem, key_pem } => create_mtls_client(cert_pem, key_pem)?,
        };

        // Retry with backoff — provider may not be ready immediately after lease creation
        let max_attempts: u64 = 4;
        let mut last_err = String::new();

        for attempt in 1..=max_attempts {
            if attempt > 1 {
                let delay = std::time::Duration::from_secs(5 * attempt);
                eprintln!(
                    "  manifest send attempt {}/{} (retrying in {}s)",
                    attempt,
                    max_attempts,
                    delay.as_secs()
                );
                tokio::time::sleep(delay).await;
            }

            let mut req = http
                .put(&url)
                .header("Content-Type", "application/json")
                .body(manifest.to_vec());

            if let ProviderAuth::Jwt { token } = auth {
                req = req.header("Authorization", format!("Bearer {}", token));
            }

            let send_result = req.send().await;

            match send_result {
                Ok(response) => {
                    if response.status().is_success() {
                        eprintln!("  manifest sent successfully");
                        return Ok(());
                    }
                    let status = response.status();
                    let body = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "unable to read response".to_string());
                    last_err = format!("Provider rejected manifest ({}): {}", status, body);
                    eprintln!("  manifest rejected: {}", last_err);
                    // Don't retry on 4xx (client error) — only on 5xx / connection errors
                    if status.is_client_error() {
                        return Err(DeployError::Provider(last_err));
                    }
                }
                Err(e) => {
                    // Use {:#} to get the full error chain (TLS details, connection info)
                    last_err = format!("{:#}", e);
                    eprintln!("  manifest send error (attempt {}): {}", attempt, last_err);
                }
            }
        }

        Err(DeployError::Provider(format!(
            "Failed to send manifest after {} attempts: {}",
            max_attempts, last_err
        )))
    }

    async fn query_provider_status(
        &self,
        provider_uri: &str,
        lease: &LeaseId,
        auth: &ProviderAuth,
    ) -> Result<ProviderLeaseStatus, DeployError> {
        // URL format matches reference: /lease/{dseq}/{gseq}/{oseq}/status
        // Owner is identified via JWT token, not in the URL path.
        let url = format!(
            "{}/lease/{}/{}/{}/status",
            provider_uri.trim_end_matches('/'),
            lease.dseq,
            lease.gseq,
            lease.oseq
        );

        // Build HTTP client once and reuse across retries
        let http = match auth {
            ProviderAuth::Jwt { .. } => reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|e| {
                    DeployError::Provider(format!("Failed to create HTTP client: {}", e))
                })?,
            ProviderAuth::Mtls { cert_pem, key_pem } => create_mtls_client(cert_pem, key_pem)?,
        };

        // Retry with backoff — provider may be slow to respond
        let max_attempts: u64 = 3;
        let mut last_err = String::new();

        for attempt in 1..=max_attempts {
            if attempt > 1 {
                let delay = std::time::Duration::from_secs(5 * attempt);
                eprintln!(
                    "  status query attempt {}/{} (retrying in {}s)",
                    attempt,
                    max_attempts,
                    delay.as_secs()
                );
                tokio::time::sleep(delay).await;
            }

            let mut req = http.get(&url);
            if let ProviderAuth::Jwt { token } = auth {
                req = req.header("Authorization", format!("Bearer {}", token));
            }

            match req.send().await {
                Ok(response) => {
                    if !response.status().is_success() {
                        let status = response.status();
                        let body = response
                            .text()
                            .await
                            .unwrap_or_else(|_| "unable to read response".to_string());
                        last_err = format!("Provider status query failed ({}): {}", status, body);
                        if status.is_client_error() {
                            return Err(DeployError::Provider(last_err));
                        }
                        continue;
                    }

                    let body = response.text().await.map_err(|e| {
                        DeployError::Provider(format!("Failed to read status response: {}", e))
                    })?;

                    eprintln!(
                        "  provider status response: {}",
                        &body[..body.len().min(500)]
                    );

                    let status = parse_provider_lease_status(&body)?;
                    return Ok(status);
                }
                Err(e) => {
                    last_err = format!("{:#}", e);
                    eprintln!("  status query error (attempt {}): {}", attempt, last_err);
                }
            }
        }

        Err(DeployError::Provider(format!(
            "Failed to query provider status after {} attempts: {}",
            max_attempts, last_err
        )))
    }

    async fn load_state(&self, session_id: &str) -> Result<Option<DeploymentState>, DeployError> {
        self.storage.read().await.load_session(session_id).await
    }

    async fn save_state(
        &self,
        session_id: &str,
        state: &DeploymentState,
    ) -> Result<(), DeployError> {
        tracing::debug!(session_id, "persisting workflow state");
        self.storage.write().await.save_session(state).await
    }

    async fn load_cert_key(&self, owner: &str) -> Result<Option<Vec<u8>>, DeployError> {
        self.storage.read().await.load_cert_key(owner).await
    }

    async fn save_cert_key(&self, owner: &str, key: &[u8]) -> Result<(), DeployError> {
        tracing::debug!(owner, "persisting certificate key");
        self.storage.write().await.save_cert_key(owner, key).await
    }

    async fn delete_cert_key(&self, owner: &str) -> Result<(), DeployError> {
        tracing::debug!(owner, "deleting certificate key");
        self.storage.write().await.delete_cert_key(owner).await
    }

    async fn load_cached_provider(
        &self,
        provider: &str,
    ) -> Result<Option<ProviderInfo>, DeployError> {
        self.storage
            .read()
            .await
            .load_cached_provider(provider)
            .await
    }

    async fn cache_provider(&self, info: &ProviderInfo) -> Result<(), DeployError> {
        tracing::debug!(provider = %info.address, "caching provider info");
        self.storage.write().await.cache_provider(info).await
    }
}

/// Helper to export sessions for backup/sharing.
///
/// Requires the `file-storage` feature for filesystem access.
///
/// # Example
///
/// ```ignore
/// // Export all sessions to a directory
/// export_sessions(&client, "/path/to/backup").await?;
///
/// // Import sessions from backup
/// import_sessions(&client, "/path/to/backup").await?;
/// ```
#[cfg(feature = "file-storage")]
pub async fn export_sessions<S: SessionStorage>(
    client: &AkashClient<S>,
    export_dir: &std::path::Path,
) -> Result<(), DeployError> {
    tokio::fs::create_dir_all(export_dir)
        .await
        .map_err(|e| DeployError::Storage(format!("failed to create export dir: {}", e)))?;

    let storage = client.storage().read().await;
    let session_ids = storage.list_sessions().await?;

    for session_id in session_ids {
        if let Some(session) = storage.load_session(&session_id).await? {
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
///
/// Requires the `file-storage` feature for filesystem access.
#[cfg(feature = "file-storage")]
pub async fn import_sessions<S: SessionStorage>(
    client: &AkashClient<S>,
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

            client
                .storage()
                .write()
                .await
                .save_session(&session)
                .await?;
            imported += 1;
        }
    }

    Ok(imported)
}

// ── Multi-signer transaction support ─────────────────────────────────────────

/// One signer's contribution to a multi-signer transaction.
pub struct SignerEntry<'a> {
    /// Signer that will produce the signature for this entry.
    pub signer: &'a dyn layer_climb::prelude::TxSigner,
    /// On-chain account number (from `base_account`).
    pub account_number: u64,
    /// On-chain sequence number (from `base_account`).
    pub sequence: u64,
    /// Messages this signer authorises.
    pub messages: Vec<layer_climb::proto::Any>,
}

/// Result of a confirmed multi-signer transaction.
pub struct MultiSignerTxResult {
    pub hash: String,
    pub code: u32,
    pub raw_log: String,
    pub height: u64,
}

/// Broadcast a transaction signed by multiple independent signers.
///
/// Each entry in `signer_entries` provides a signer, its on-chain account info,
/// and the messages it authorises.  Messages appear in `TxBody` in signer order.
/// The first signer is the fee payer.
///
/// Uses `SIGN_MODE_DIRECT`: each signer signs a `SignDoc` with their own
/// `account_number` but shared `body_bytes` and `auth_info_bytes`.
pub async fn broadcast_multi_signer(
    querier: &layer_climb::prelude::QueryClient,
    chain_id: &str,
    signer_entries: Vec<SignerEntry<'_>>,
    gas_multiplier: f32,
    poll_timeout: std::time::Duration,
) -> Result<MultiSignerTxResult, DeployError> {
    use layer_climb::prelude::proto_into_bytes;

    if signer_entries.is_empty() {
        return Err(DeployError::InvalidState(
            "broadcast_multi_signer: no signer entries".into(),
        ));
    }

    // ── 1. Build TxBody ──────────────────────────────────────────────────
    let all_messages: Vec<layer_climb::proto::Any> = signer_entries
        .iter()
        .flat_map(|e| e.messages.clone())
        .collect();

    let block_height = querier
        .block_height()
        .await
        .map_err(|e| DeployError::Query(format!("block_height for timeout: {}", e)))?;

    let body = layer_climb::proto::tx::TxBody {
        messages: all_messages,
        memo: String::new(),
        timeout_height: block_height + 10,
        extension_options: Vec::new(),
        non_critical_extension_options: Vec::new(),
        unordered: false,
        timeout_timestamp: None,
    };
    let body_bytes = proto_into_bytes(&body).map_err(|e| DeployError::Transaction {
        code: 0,
        log: format!("encode TxBody: {}", e),
    })?;

    // Diagnostic: log signer state and message types before simulation
    for (i, entry) in signer_entries.iter().enumerate() {
        let type_urls: Vec<&str> = entry.messages.iter().map(|m| m.type_url.as_str()).collect();
        tracing::info!(
            signer = i,
            account_number = entry.account_number,
            sequence = entry.sequence,
            chain_id,
            msgs = ?type_urls,
            "broadcast_multi_signer: signer entry"
        );
    }

    // ── 2. Build SignerInfos (Unspecified mode for simulation) ────────────
    let mut sim_signer_infos = Vec::with_capacity(signer_entries.len());
    for entry in &signer_entries {
        let si = entry
            .signer
            .signer_info(
                entry.sequence,
                layer_climb::proto::tx::SignMode::Unspecified,
            )
            .await
            .map_err(|e| DeployError::Transaction {
                code: 0,
                log: format!("signer_info (sim): {}", e),
            })?;
        sim_signer_infos.push(si);
    }

    // Simulation fee: 0 gas, correct denom
    let sim_fee = layer_climb::proto::tx::Fee {
        amount: vec![layer_climb::prelude::new_coin(
            0,
            &querier.chain_config.gas_denom,
        )],
        gas_limit: 0,
        payer: String::new(),
        granter: String::new(),
    };

    #[allow(deprecated)]
    let sim_auth_info = layer_climb::proto::tx::AuthInfo {
        signer_infos: sim_signer_infos,
        fee: Some(sim_fee),
        tip: None,
    };
    let sim_auth_bytes =
        proto_into_bytes(&sim_auth_info).map_err(|e| DeployError::Transaction {
            code: 0,
            log: format!("encode sim AuthInfo: {}", e),
        })?;

    // Build unsigned TxRaw for simulation
    let sim_tx_raw = layer_climb::proto::tx::TxRaw {
        body_bytes: body_bytes.clone(),
        auth_info_bytes: sim_auth_bytes,
        signatures: signer_entries.iter().map(|_| Vec::new()).collect(),
    };
    let sim_tx_bytes = proto_into_bytes(&sim_tx_raw).map_err(|e| DeployError::Transaction {
        code: 0,
        log: format!("encode sim TxRaw: {}", e),
    })?;

    // ── 3. Simulate gas ──────────────────────────────────────────────────
    let sim_response = querier.simulate_tx(sim_tx_bytes).await.map_err(|e| {
        tracing::error!(error = ?e, "broadcast_multi_signer: simulate_tx failed");
        DeployError::Transaction {
            code: 0,
            log: format!("simulate_tx: {:#}", e),
        }
    })?;
    let gas_used = sim_response
        .gas_info
        .as_ref()
        .map(|g| g.gas_used)
        .unwrap_or(200_000);
    let gas_units = (gas_used as f32 * gas_multiplier).ceil() as u64;

    tracing::info!(
        gas_used,
        gas_units,
        signers = signer_entries.len(),
        "multi_signer: gas simulated"
    );

    // ── 4. Rebuild AuthInfo with real fee ────────────────────────────────
    let fee_amount = (querier.chain_config.gas_price * gas_units as f32).ceil() as u128;
    let real_fee = layer_climb::proto::tx::Fee {
        amount: vec![layer_climb::prelude::new_coin(
            fee_amount,
            &querier.chain_config.gas_denom,
        )],
        gas_limit: gas_units,
        payer: String::new(),
        granter: String::new(),
    };

    let mut real_signer_infos = Vec::with_capacity(signer_entries.len());
    for entry in &signer_entries {
        let si = entry
            .signer
            .signer_info(entry.sequence, layer_climb::proto::tx::SignMode::Direct)
            .await
            .map_err(|e| DeployError::Transaction {
                code: 0,
                log: format!("signer_info: {}", e),
            })?;
        real_signer_infos.push(si);
    }

    #[allow(deprecated)]
    let real_auth_info = layer_climb::proto::tx::AuthInfo {
        signer_infos: real_signer_infos,
        fee: Some(real_fee),
        tip: None,
    };
    let auth_info_bytes =
        proto_into_bytes(&real_auth_info).map_err(|e| DeployError::Transaction {
            code: 0,
            log: format!("encode AuthInfo: {}", e),
        })?;

    // ── 5. Each signer signs its own SignDoc ─────────────────────────────
    let mut signatures = Vec::with_capacity(signer_entries.len());
    for entry in &signer_entries {
        let sign_doc = layer_climb::proto::tx::SignDoc {
            body_bytes: body_bytes.clone(),
            auth_info_bytes: auth_info_bytes.clone(),
            chain_id: chain_id.to_string(),
            account_number: entry.account_number,
        };
        let sig = entry
            .signer
            .sign(&sign_doc)
            .await
            .map_err(|e| DeployError::Transaction {
                code: 0,
                log: format!("sign: {}", e),
            })?;
        signatures.push(sig);
    }

    // ── 6. Assemble and broadcast ────────────────────────────────────────
    let tx_raw = layer_climb::proto::tx::TxRaw {
        body_bytes,
        auth_info_bytes,
        signatures,
    };
    let tx_bytes = proto_into_bytes(&tx_raw).map_err(|e| DeployError::Transaction {
        code: 0,
        log: format!("encode TxRaw: {}", e),
    })?;

    tracing::info!(
        msgs = signer_entries
            .iter()
            .map(|e| e.messages.len())
            .sum::<usize>(),
        signers = signer_entries.len(),
        gas_units,
        "multi_signer: broadcasting"
    );

    let response = querier
        .broadcast_tx_bytes(tx_bytes, layer_climb::proto::tx::BroadcastMode::Sync)
        .await
        .map_err(|e| DeployError::Transaction {
            code: 1,
            log: format!("broadcast: {}", e),
        })?;

    if response.code() != 0 {
        return Err(DeployError::Transaction {
            code: response.code(),
            log: format!(
                "multi_signer tx failed: code={}, log={}",
                response.code(),
                response.raw_log()
            ),
        });
    }

    // Poll until confirmed on-chain
    let confirmed = querier
        .poll_until_tx_ready(
            response.tx_hash(),
            std::time::Duration::from_secs(1),
            poll_timeout,
        )
        .await
        .map_err(|e| DeployError::Transaction {
            code: 0,
            log: format!("poll_until_tx_ready: {}", e),
        })?;

    let height = confirmed.tx_response.height as u64;
    let hash = confirmed.tx_response.txhash.clone();
    let code = confirmed.tx_response.code;

    if code != 0 {
        return Err(DeployError::Transaction {
            code,
            log: format!(
                "multi_signer tx confirmed but failed: code={}, log={}",
                code, confirmed.tx_response.raw_log
            ),
        });
    }

    tracing::info!(
        tx_hash = %hash, height, code,
        "multi_signer: confirmed"
    );

    Ok(MultiSignerTxResult {
        hash,
        code,
        raw_log: confirmed.tx_response.raw_log,
        height,
    })
}

/// Broadcast messages with a fee granter (for AuthZ fee delegation).
///
/// Similar to `broadcast_multi_signer` but for a single signer with
/// `Fee.granter` set so the granter's account pays gas via FeeGrant.
/// The signer is the grantee; the granter pays fees.
pub async fn broadcast_with_fee_granter(
    querier: &layer_climb::prelude::QueryClient,
    chain_id: &str,
    signer: &dyn layer_climb::prelude::TxSigner,
    account_number: u64,
    sequence: u64,
    messages: Vec<layer_climb::proto::Any>,
    fee_granter: &str,
    gas_multiplier: f32,
    poll_timeout: std::time::Duration,
) -> Result<MultiSignerTxResult, DeployError> {
    use layer_climb::prelude::proto_into_bytes;

    if messages.is_empty() {
        return Err(DeployError::InvalidState(
            "broadcast_with_fee_granter: no messages".into(),
        ));
    }

    let msg_count = messages.len();

    // ── 1. Build TxBody ──────────────────────────────────────────────────
    let block_height = querier
        .block_height()
        .await
        .map_err(|e| DeployError::Query(format!("block_height for timeout: {}", e)))?;

    let body = layer_climb::proto::tx::TxBody {
        messages,
        memo: String::new(),
        timeout_height: block_height + 10,
        extension_options: Vec::new(),
        non_critical_extension_options: Vec::new(),
        unordered: false,
        timeout_timestamp: None,
    };
    let body_bytes = proto_into_bytes(&body).map_err(|e| DeployError::Transaction {
        code: 0,
        log: format!("encode TxBody: {}", e),
    })?;

    // ── 2. Build SignerInfo for simulation ────────────────────────────────
    let sim_si = signer
        .signer_info(sequence, layer_climb::proto::tx::SignMode::Unspecified)
        .await
        .map_err(|e| DeployError::Transaction {
            code: 0,
            log: format!("signer_info (sim): {}", e),
        })?;

    let sim_fee = layer_climb::proto::tx::Fee {
        amount: vec![layer_climb::prelude::new_coin(
            0,
            &querier.chain_config.gas_denom,
        )],
        gas_limit: 0,
        payer: String::new(),
        granter: fee_granter.to_string(),
    };

    #[allow(deprecated)]
    let sim_auth_info = layer_climb::proto::tx::AuthInfo {
        signer_infos: vec![sim_si],
        fee: Some(sim_fee),
        tip: None,
    };
    let sim_auth_bytes =
        proto_into_bytes(&sim_auth_info).map_err(|e| DeployError::Transaction {
            code: 0,
            log: format!("encode sim AuthInfo: {}", e),
        })?;

    let sim_tx_raw = layer_climb::proto::tx::TxRaw {
        body_bytes: body_bytes.clone(),
        auth_info_bytes: sim_auth_bytes,
        signatures: vec![Vec::new()],
    };
    let sim_tx_bytes = proto_into_bytes(&sim_tx_raw).map_err(|e| DeployError::Transaction {
        code: 0,
        log: format!("encode sim TxRaw: {}", e),
    })?;

    // ── 3. Simulate gas ──────────────────────────────────────────────────
    let sim_response = querier.simulate_tx(sim_tx_bytes).await.map_err(|e| {
        tracing::error!(error = ?e, "broadcast_with_fee_granter: simulate_tx failed");
        DeployError::Transaction {
            code: 0,
            log: format!("simulate_tx: {:#}", e),
        }
    })?;
    let gas_used = sim_response
        .gas_info
        .as_ref()
        .map(|g| g.gas_used)
        .unwrap_or(200_000);
    let gas_units = (gas_used as f32 * gas_multiplier).ceil() as u64;

    tracing::info!(
        gas_used,
        gas_units,
        fee_granter,
        "fee_granter: gas simulated"
    );

    // ── 4. Rebuild AuthInfo with real fee ────────────────────────────────
    let fee_amount = (querier.chain_config.gas_price * gas_units as f32).ceil() as u128;
    let real_fee = layer_climb::proto::tx::Fee {
        amount: vec![layer_climb::prelude::new_coin(
            fee_amount,
            &querier.chain_config.gas_denom,
        )],
        gas_limit: gas_units,
        payer: String::new(),
        granter: fee_granter.to_string(),
    };

    let real_si = signer
        .signer_info(sequence, layer_climb::proto::tx::SignMode::Direct)
        .await
        .map_err(|e| DeployError::Transaction {
            code: 0,
            log: format!("signer_info: {}", e),
        })?;

    #[allow(deprecated)]
    let real_auth_info = layer_climb::proto::tx::AuthInfo {
        signer_infos: vec![real_si],
        fee: Some(real_fee),
        tip: None,
    };
    let auth_info_bytes =
        proto_into_bytes(&real_auth_info).map_err(|e| DeployError::Transaction {
            code: 0,
            log: format!("encode AuthInfo: {}", e),
        })?;

    // ── 5. Sign ──────────────────────────────────────────────────────────
    let sign_doc = layer_climb::proto::tx::SignDoc {
        body_bytes: body_bytes.clone(),
        auth_info_bytes: auth_info_bytes.clone(),
        chain_id: chain_id.to_string(),
        account_number,
    };
    let sig = signer
        .sign(&sign_doc)
        .await
        .map_err(|e| DeployError::Transaction {
            code: 0,
            log: format!("sign: {}", e),
        })?;

    // ── 6. Assemble and broadcast ────────────────────────────────────────
    let tx_raw = layer_climb::proto::tx::TxRaw {
        body_bytes,
        auth_info_bytes,
        signatures: vec![sig],
    };
    let tx_bytes = proto_into_bytes(&tx_raw).map_err(|e| DeployError::Transaction {
        code: 0,
        log: format!("encode TxRaw: {}", e),
    })?;

    tracing::info!(
        msgs = msg_count,
        gas_units,
        fee_granter,
        "fee_granter: broadcasting"
    );

    let response = querier
        .broadcast_tx_bytes(tx_bytes, layer_climb::proto::tx::BroadcastMode::Sync)
        .await
        .map_err(|e| DeployError::Transaction {
            code: 1,
            log: format!("broadcast: {}", e),
        })?;

    if response.code() != 0 {
        return Err(DeployError::Transaction {
            code: response.code(),
            log: format!(
                "fee_granter tx failed: code={}, log={}",
                response.code(),
                response.raw_log()
            ),
        });
    }

    // Poll until confirmed on-chain
    let confirmed = querier
        .poll_until_tx_ready(
            response.tx_hash(),
            std::time::Duration::from_secs(1),
            poll_timeout,
        )
        .await
        .map_err(|e| DeployError::Transaction {
            code: 0,
            log: format!("poll_until_tx_ready: {}", e),
        })?;

    let height = confirmed.tx_response.height as u64;
    let hash = confirmed.tx_response.txhash.clone();
    let code = confirmed.tx_response.code;

    if code != 0 {
        return Err(DeployError::Transaction {
            code,
            log: format!(
                "fee_granter tx confirmed but failed: code={}, log={}",
                code, confirmed.tx_response.raw_log
            ),
        });
    }

    tracing::info!(tx_hash = %hash, height, code, fee_granter, "fee_granter: confirmed");

    Ok(MultiSignerTxResult {
        hash,
        code,
        raw_log: confirmed.tx_response.raw_log,
        height,
    })
}
