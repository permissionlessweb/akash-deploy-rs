//! Deployment Workflow Engine
//!
//! The state machine that drives deployments. It's dumb — it just
//! transitions between steps and calls the backend. No storage,
//! no signing, no transport. Just logic.

use crate::backend::AkashBackend;
use crate::error::DeployError;
use crate::state::{DeploymentState, Step};
use crate::types::{Bid, BidId};

/// Workflow configuration.
#[derive(Debug, Clone)]
pub struct WorkflowConfig {
    /// Minimum balance required to proceed (uakt).
    pub min_balance_uakt: u64,
    /// How long to wait between bid checks (seconds).
    pub bid_wait_seconds: u64,
    /// Max attempts to wait for bids.
    pub max_bid_wait_attempts: u32,
    /// Max attempts to wait for endpoints.
    pub max_endpoint_wait_attempts: u32,
    /// Auto-select cheapest bid without user input.
    pub auto_select_cheapest_bid: bool,
    /// Trusted providers to prefer.
    pub trusted_providers: Vec<String>,
}

impl Default for WorkflowConfig {
    fn default() -> Self {
        Self {
            min_balance_uakt: 5_000_000, // 5 AKT
            bid_wait_seconds: 12,        // ~2 blocks
            max_bid_wait_attempts: 10,
            max_endpoint_wait_attempts: 30,
            auto_select_cheapest_bid: false,
            trusted_providers: Vec::new(),
        }
    }
}

/// Result of advancing one step.
#[derive(Debug)]
pub enum StepResult {
    /// Keep going, call advance() again.
    Continue,
    /// Workflow needs input from caller.
    NeedsInput(InputRequired),
    /// Done successfully.
    Complete,
    /// Failed.
    Failed(String),
}

/// What input the workflow needs.
#[derive(Debug)]
pub enum InputRequired {
    /// User must select a provider from available bids.
    SelectProvider { bids: Vec<Bid> },
    /// SDL content is missing.
    ProvideSdl,
}

/// The deployment workflow engine.
///
/// Parameterized by the backend — you provide the implementation.
pub struct DeploymentWorkflow<'a, B: AkashBackend> {
    backend: &'a B,
    signer: &'a B::Signer,
    config: WorkflowConfig,
}

impl<'a, B: AkashBackend> DeploymentWorkflow<'a, B> {
    /// Create a new workflow engine.
    pub fn new(backend: &'a B, signer: &'a B::Signer, config: WorkflowConfig) -> Self {
        Self {
            backend,
            signer,
            config,
        }
    }

    /// Advance the workflow by one step.
    ///
    /// Each step does ONE thing — query or broadcast — then transitions.
    /// Call this in a loop until you get Complete, Failed, or NeedsInput.
    pub async fn advance(&self, state: &mut DeploymentState) -> Result<StepResult, DeployError> {
        let result = match &state.step {
            Step::Init => self.step_init(state).await,
            Step::CheckBalance => self.step_check_balance(state).await,
            Step::EnsureCertificate => self.step_ensure_certificate(state).await,
            Step::CreateDeployment => self.step_create_deployment(state).await,
            Step::WaitForBids { waited_blocks } => {
                self.step_wait_for_bids(state, *waited_blocks).await
            }
            Step::SelectProvider => self.step_select_provider(state).await,
            Step::CreateLease => self.step_create_lease(state).await,
            Step::SendManifest => self.step_send_manifest(state).await,
            Step::WaitForEndpoints { attempts } => {
                self.step_wait_for_endpoints(state, *attempts).await
            }
            Step::Complete => return Ok(StepResult::Complete),
            Step::Failed { reason, .. } => return Ok(StepResult::Failed(reason.clone())),
        };

        // Always save state after a step (even on error, state might have changed)
        self.backend
            .save_state(&state.session_id, state)
            .await?;

        result
    }

    /// Run until completion or until input is needed.
    pub async fn run_to_completion(
        &self,
        state: &mut DeploymentState,
    ) -> Result<StepResult, DeployError> {
        loop {
            match self.advance(state).await? {
                StepResult::Continue => continue,
                other => return Ok(other),
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // STEP IMPLEMENTATIONS
    // ═══════════════════════════════════════════════════════════════

    async fn step_init(&self, state: &mut DeploymentState) -> Result<StepResult, DeployError> {
        // Check we have SDL
        if state.sdl_content.is_none() {
            return Ok(StepResult::NeedsInput(InputRequired::ProvideSdl));
        }

        state.transition(Step::CheckBalance);
        Ok(StepResult::Continue)
    }

    async fn step_check_balance(
        &self,
        state: &mut DeploymentState,
    ) -> Result<StepResult, DeployError> {
        let balance = self
            .backend
            .query_balance(&state.owner, "uakt")
            .await?;

        if balance < self.config.min_balance_uakt as u128 {
            state.fail(
                format!(
                    "insufficient balance: {} uakt < {} uakt required",
                    balance, self.config.min_balance_uakt
                ),
                false, // not recoverable by retry
            );
            return Ok(StepResult::Failed(format!(
                "insufficient balance: {}",
                balance
            )));
        }

        state.transition(Step::EnsureCertificate);
        Ok(StepResult::Continue)
    }

    async fn step_ensure_certificate(
        &self,
        state: &mut DeploymentState,
    ) -> Result<StepResult, DeployError> {
        // Check if cert exists on chain
        let cert = self.backend.query_certificate(&state.owner).await?;

        if let Some(cert_info) = cert {
            // Cert exists, try to load the key
            let key = self.backend.load_cert_key(&state.owner).await?;
            if let Some(key_pem) = key {
                state.cert_pem = Some(cert_info.cert_pem);
                state.key_pem = Some(key_pem);
                state.transition(Step::CreateDeployment);
                return Ok(StepResult::Continue);
            }
            // Cert exists but we don't have the key — need to recreate
        }

        // Generate new certificate
        let (cert_pem, key_pem, pubkey_pem) = generate_certificate(&state.owner)?;

        // Broadcast cert creation
        let tx = self
            .backend
            .broadcast_create_certificate(self.signer, &state.owner, &cert_pem, &pubkey_pem)
            .await?;

        if !tx.is_success() {
            state.fail(
                format!("certificate tx failed: {}", tx.raw_log),
                true,
            );
            return Ok(StepResult::Failed(tx.raw_log));
        }

        state.record_tx(&tx.hash);

        // Save the key for future mTLS
        self.backend.save_cert_key(&state.owner, &key_pem).await?;

        state.cert_pem = Some(cert_pem);
        state.key_pem = Some(key_pem);
        state.transition(Step::CreateDeployment);
        Ok(StepResult::Continue)
    }

    async fn step_create_deployment(
        &self,
        state: &mut DeploymentState,
    ) -> Result<StepResult, DeployError> {
        let sdl = state.sdl_content.as_ref().ok_or_else(|| {
            DeployError::InvalidState("SDL content missing at CreateDeployment".into())
        })?;

        let (tx, dseq) = self
            .backend
            .broadcast_create_deployment(self.signer, &state.owner, sdl, state.deposit_uakt)
            .await?;

        if !tx.is_success() {
            state.fail(
                format!("create deployment tx failed: {}", tx.raw_log),
                true,
            );
            return Ok(StepResult::Failed(tx.raw_log));
        }

        state.record_tx(&tx.hash);
        state.dseq = Some(dseq);
        state.transition(Step::WaitForBids { waited_blocks: 0 });
        Ok(StepResult::Continue)
    }

    async fn step_wait_for_bids(
        &self,
        state: &mut DeploymentState,
        waited_blocks: u32,
    ) -> Result<StepResult, DeployError> {
        let dseq = state.dseq.ok_or_else(|| {
            DeployError::InvalidState("dseq missing at WaitForBids".into())
        })?;

        // Query bids
        let bids = self.backend.query_bids(&state.owner, dseq).await?;

        if !bids.is_empty() {
            state.bids = bids;
            state.transition(Step::SelectProvider);
            return Ok(StepResult::Continue);
        }

        // No bids yet
        if waited_blocks >= self.config.max_bid_wait_attempts {
            state.fail(
                format!("no bids after {} attempts", self.config.max_bid_wait_attempts),
                true,
            );
            return Ok(StepResult::Failed("no bids received".into()));
        }

        // Wait and try again
        tokio::time::sleep(std::time::Duration::from_secs(self.config.bid_wait_seconds)).await;
        state.transition(Step::WaitForBids {
            waited_blocks: waited_blocks + 1,
        });
        Ok(StepResult::Continue)
    }

    async fn step_select_provider(
        &self,
        state: &mut DeploymentState,
    ) -> Result<StepResult, DeployError> {
        if state.bids.is_empty() {
            state.fail("no bids available", false);
            return Ok(StepResult::Failed("no bids".into()));
        }

        // If provider already selected (user provided it), proceed
        if state.selected_provider.is_some() {
            state.transition(Step::CreateLease);
            return Ok(StepResult::Continue);
        }

        // Auto-select if configured
        if self.config.auto_select_cheapest_bid {
            // Prefer trusted providers, then cheapest
            let selected = self.auto_select_provider(&state.bids);
            state.selected_provider = Some(selected.provider.clone());
            state.transition(Step::CreateLease);
            return Ok(StepResult::Continue);
        }

        // Need user input
        Ok(StepResult::NeedsInput(InputRequired::SelectProvider {
            bids: state.bids.clone(),
        }))
    }

    async fn step_create_lease(
        &self,
        state: &mut DeploymentState,
    ) -> Result<StepResult, DeployError> {
        let dseq = state.dseq.ok_or_else(|| {
            DeployError::InvalidState("dseq missing at CreateLease".into())
        })?;

        let provider = state.selected_provider.as_ref().ok_or_else(|| {
            DeployError::InvalidState("provider not selected".into())
        })?;

        // Find the bid for this provider
        let bid = state
            .bids
            .iter()
            .find(|b| &b.provider == provider)
            .ok_or_else(|| {
                DeployError::InvalidState(format!("no bid from provider {}", provider))
            })?;

        let bid_id = BidId::from_bid(&state.owner, dseq, state.gseq, state.oseq, bid);

        let tx = self.backend.broadcast_create_lease(self.signer, &bid_id).await?;

        if !tx.is_success() {
            state.fail(
                format!("create lease tx failed: {}", tx.raw_log),
                true,
            );
            return Ok(StepResult::Failed(tx.raw_log));
        }

        state.record_tx(&tx.hash);
        state.lease_id = Some(bid_id.into());
        state.transition(Step::SendManifest);
        Ok(StepResult::Continue)
    }

    async fn step_send_manifest(
        &self,
        state: &mut DeploymentState,
    ) -> Result<StepResult, DeployError> {
        let lease = state.lease_id.as_ref().ok_or_else(|| {
            DeployError::InvalidState("lease_id missing at SendManifest".into())
        })?;

        let cert = state.cert_pem.as_ref().ok_or_else(|| {
            DeployError::InvalidState("cert_pem missing at SendManifest".into())
        })?;

        let key = state.key_pem.as_ref().ok_or_else(|| {
            DeployError::InvalidState("key_pem missing at SendManifest".into())
        })?;

        let sdl = state.sdl_content.as_ref().ok_or_else(|| {
            DeployError::InvalidState("sdl_content missing at SendManifest".into())
        })?;

        // Process template if feature enabled and is_template flag set
        #[cfg(feature = "sdl-templates")]
        let processed_sdl = if state.is_template {
            let template = crate::template::SdlTemplate::new(sdl)?;
            let empty_vars = std::collections::HashMap::new();
            let empty_defaults = std::collections::HashMap::new();
            let variables = state.template_variables.as_ref().unwrap_or(&empty_vars);
            let defaults = state.template_defaults.as_ref().unwrap_or(&empty_defaults);
            template.process(variables, defaults)?
        } else {
            sdl.clone()
        };

        #[cfg(not(feature = "sdl-templates"))]
        let processed_sdl = sdl.clone();

        // Get provider URI
        let provider_info = self
            .backend
            .query_provider_info(&lease.provider)
            .await?
            .ok_or_else(|| DeployError::Provider("provider not found".into()))?;

        // Build manifest from SDL using the actual ManifestBuilder
        let manifest = build_manifest(&state.owner, &processed_sdl, lease.dseq)?;

        self.backend
            .send_manifest(&provider_info.host_uri, lease, &manifest, cert, key)
            .await?;

        state.transition(Step::WaitForEndpoints { attempts: 0 });
        Ok(StepResult::Continue)
    }

    async fn step_wait_for_endpoints(
        &self,
        state: &mut DeploymentState,
        attempts: u32,
    ) -> Result<StepResult, DeployError> {
        let lease = state.lease_id.as_ref().ok_or_else(|| {
            DeployError::InvalidState("lease_id missing at WaitForEndpoints".into())
        })?;

        let cert = state.cert_pem.as_ref().ok_or_else(|| {
            DeployError::InvalidState("cert_pem missing at WaitForEndpoints".into())
        })?;

        let key = state.key_pem.as_ref().ok_or_else(|| {
            DeployError::InvalidState("key_pem missing at WaitForEndpoints".into())
        })?;

        let provider_info = self
            .backend
            .query_provider_info(&lease.provider)
            .await?
            .ok_or_else(|| DeployError::Provider("provider not found".into()))?;

        let status = self
            .backend
            .query_provider_status(&provider_info.host_uri, lease, cert, key)
            .await?;

        if status.ready && !status.endpoints.is_empty() {
            state.endpoints = status.endpoints;
            state.transition(Step::Complete);
            return Ok(StepResult::Complete);
        }

        if attempts >= self.config.max_endpoint_wait_attempts {
            state.fail(
                format!("endpoints not ready after {} attempts", attempts),
                true,
            );
            return Ok(StepResult::Failed("endpoints not ready".into()));
        }

        // Wait and try again
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        state.transition(Step::WaitForEndpoints {
            attempts: attempts + 1,
        });
        Ok(StepResult::Continue)
    }

    // ═══════════════════════════════════════════════════════════════
    // HELPERS
    // ═══════════════════════════════════════════════════════════════

    fn auto_select_provider<'b>(&self, bids: &'b [Bid]) -> &'b Bid {
        // First try trusted providers
        for trusted in &self.config.trusted_providers {
            if let Some(bid) = bids.iter().find(|b| &b.provider == trusted) {
                return bid;
            }
        }
        // Otherwise cheapest
        bids.iter()
            .min_by_key(|b| b.price_uakt)
            .expect("bids should not be empty")
    }

    /// Provide user's provider selection.
    pub fn select_provider(state: &mut DeploymentState, provider: &str) -> Result<(), DeployError> {
        if !state.bids.iter().any(|b| b.provider == provider) {
            return Err(DeployError::InvalidState(format!(
                "provider {} not in available bids",
                provider
            )));
        }
        state.selected_provider = Some(provider.to_string());
        Ok(())
    }

    /// Provide SDL content.
    pub fn provide_sdl(state: &mut DeploymentState, sdl: &str) {
        state.sdl_content = Some(sdl.to_string());
    }
}

// ═══════════════════════════════════════════════════════════════════
// CERTIFICATE GENERATION
// ═══════════════════════════════════════════════════════════════════

/// Generate a self-signed certificate for Akash mTLS.
/// Returns (cert_pem, private_key_pem, public_key_pem).
fn generate_certificate(owner: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), DeployError> {
    let cert = crate::certificate::generate_certificate(owner)?;
    Ok((cert.cert_pem, cert.privkey_pem, cert.pubkey_pem))
}

/// Build manifest from SDL.
///
/// Uses `ManifestBuilder` to parse SDL and generate the canonical JSON manifest
/// that providers expect. The manifest hash computed from this JSON must match
/// the on-chain deployment.version hash.
fn build_manifest(owner: &str, sdl: &str, dseq: u64) -> Result<Vec<u8>, DeployError> {
    if sdl.is_empty() {
        return Err(DeployError::Manifest("empty SDL".into()));
    }

    // Use the actual ManifestBuilder to parse SDL
    let builder = crate::manifest::ManifestBuilder::new(owner, dseq);
    let manifest_groups = builder.build_from_sdl(sdl)?;

    // Serialize to canonical JSON (deterministic, matches Go's encoding/json)
    let canonical_json = crate::canonical::to_canonical_json(&manifest_groups)?;

    Ok(canonical_json.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use std::sync::{Arc, Mutex};

    // Common SDL fixtures for testing
    const SIMPLE_SDL: &str = r#"
version: "2.0"
services:
  web:
    image: nginx
    expose:
      - port: 80
        as: 80
        to:
          - global: true
profiles:
  compute:
    web:
      resources:
        cpu:
          units: 1
        memory:
          size: 512Mi
        storage:
          size: 1Gi
  placement:
    dc:
      pricing:
        web:
          denom: uakt
          amount: 1000
deployment:
  web:
    dc:
      profile: web
      count: 1
"#;

    // Mock signer - just a placeholder
    #[derive(Debug, Clone)]
    struct MockSigner;

    // Mock backend with configurable responses
    struct MockBackend {
        balance: Arc<Mutex<u128>>,
        certificate: Arc<Mutex<Option<CertificateInfo>>>,
        cert_key: Arc<Mutex<Option<Vec<u8>>>>,
        bids: Arc<Mutex<Vec<Bid>>>,
        provider_status: Arc<Mutex<Option<ProviderLeaseStatus>>>,
        call_counts: Arc<Mutex<CallCounts>>,
        fail_cert_tx: Arc<Mutex<bool>>,
        fail_deployment_tx: Arc<Mutex<bool>>,
        fail_lease_tx: Arc<Mutex<bool>>,
    }

    #[derive(Debug, Default, Clone)]
    struct CallCounts {
        query_balance: usize,
        query_bids: usize,
        broadcast_create_deployment: usize,
        broadcast_create_lease: usize,
        send_manifest: usize,
        query_provider_status: usize,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                balance: Arc::new(Mutex::new(10_000_000)), // 10 AKT
                certificate: Arc::new(Mutex::new(None)),
                cert_key: Arc::new(Mutex::new(None)),
                bids: Arc::new(Mutex::new(Vec::new())),
                provider_status: Arc::new(Mutex::new(None)),
                call_counts: Arc::new(Mutex::new(CallCounts::default())),
                fail_cert_tx: Arc::new(Mutex::new(false)),
                fail_deployment_tx: Arc::new(Mutex::new(false)),
                fail_lease_tx: Arc::new(Mutex::new(false)),
            }
        }

        fn set_balance(&self, balance: u128) {
            *self.balance.lock().unwrap() = balance;
        }

        fn set_bids(&self, bids: Vec<Bid>) {
            *self.bids.lock().unwrap() = bids;
        }

        fn set_provider_status(&self, status: ProviderLeaseStatus) {
            *self.provider_status.lock().unwrap() = Some(status);
        }

        fn set_certificate(&self, cert: CertificateInfo) {
            *self.certificate.lock().unwrap() = Some(cert);
        }

        fn set_cert_key(&self, key: Vec<u8>) {
            *self.cert_key.lock().unwrap() = Some(key);
        }

        fn set_fail_cert_tx(&self, fail: bool) {
            *self.fail_cert_tx.lock().unwrap() = fail;
        }

        fn set_fail_deployment_tx(&self, fail: bool) {
            *self.fail_deployment_tx.lock().unwrap() = fail;
        }

        fn set_fail_lease_tx(&self, fail: bool) {
            *self.fail_lease_tx.lock().unwrap() = fail;
        }

        fn get_call_counts(&self) -> CallCounts {
            self.call_counts.lock().unwrap().clone()
        }
    }

    impl AkashBackend for MockBackend {
        type Signer = MockSigner;

        async fn query_balance(&self, _address: &str, _denom: &str) -> Result<u128, DeployError> {
            self.call_counts.lock().unwrap().query_balance += 1;
            Ok(*self.balance.lock().unwrap())
        }

        async fn query_certificate(&self, _address: &str) -> Result<Option<CertificateInfo>, DeployError> {
            Ok(self.certificate.lock().unwrap().clone())
        }

        async fn query_provider_info(&self, _provider: &str) -> Result<Option<ProviderInfo>, DeployError> {
            Ok(Some(ProviderInfo {
                address: "akash1provider".to_string(),
                host_uri: "https://provider.akash.net".to_string(),
                email: "test@example.com".to_string(),
                website: "https://example.com".to_string(),
                attributes: vec![],
                cached_at: 0,
            }))
        }

        async fn query_bids(&self, _owner: &str, _dseq: u64) -> Result<Vec<Bid>, DeployError> {
            self.call_counts.lock().unwrap().query_bids += 1;
            Ok(self.bids.lock().unwrap().clone())
        }

        async fn query_lease(&self, _owner: &str, _dseq: u64, _gseq: u32, _oseq: u32, _bseq: u32, _provider: &str) -> Result<LeaseInfo, DeployError> {
            Ok(LeaseInfo {
                state: LeaseState::Active,
                price_uakt: 1000,
            })
        }

        async fn query_escrow(&self, _owner: &str, _dseq: u64) -> Result<EscrowInfo, DeployError> {
            Ok(EscrowInfo {
                balance_uakt: 5_000_000,
                deposited_uakt: 5_000_000,
            })
        }

        async fn broadcast_create_certificate(&self, _signer: &Self::Signer, _owner: &str, _cert_pem: &[u8], _pubkey_pem: &[u8]) -> Result<TxResult, DeployError> {
            if *self.fail_cert_tx.lock().unwrap() {
                Ok(TxResult {
                    hash: "CERT_TX_FAIL".to_string(),
                    code: 5,
                    raw_log: "certificate creation failed".to_string(),
                    height: 1000,
                })
            } else {
                Ok(TxResult {
                    hash: "CERT_TX".to_string(),
                    code: 0,
                    raw_log: "success".to_string(),
                    height: 1000,
                })
            }
        }

        async fn broadcast_create_deployment(&self, _signer: &Self::Signer, _owner: &str, _sdl_content: &str, _deposit_uakt: u64) -> Result<(TxResult, u64), DeployError> {
            self.call_counts.lock().unwrap().broadcast_create_deployment += 1;
            if *self.fail_deployment_tx.lock().unwrap() {
                Ok((
                    TxResult {
                        hash: "DEPLOY_TX_FAIL".to_string(),
                        code: 5,
                        raw_log: "deployment creation failed".to_string(),
                        height: 1001,
                    },
                    123456,
                ))
            } else {
                Ok((
                    TxResult {
                        hash: "DEPLOY_TX".to_string(),
                        code: 0,
                        raw_log: "success".to_string(),
                        height: 1001,
                    },
                    123456,
                ))
            }
        }

        async fn broadcast_create_lease(&self, _signer: &Self::Signer, _bid: &BidId) -> Result<TxResult, DeployError> {
            self.call_counts.lock().unwrap().broadcast_create_lease += 1;
            if *self.fail_lease_tx.lock().unwrap() {
                Ok(TxResult {
                    hash: "LEASE_TX_FAIL".to_string(),
                    code: 5,
                    raw_log: "lease creation failed".to_string(),
                    height: 1002,
                })
            } else {
                Ok(TxResult {
                    hash: "LEASE_TX".to_string(),
                    code: 0,
                    raw_log: "success".to_string(),
                    height: 1002,
                })
            }
        }

        async fn broadcast_deposit(&self, _signer: &Self::Signer, _owner: &str, _dseq: u64, _amount_uakt: u64) -> Result<TxResult, DeployError> {
            Ok(TxResult {
                hash: "DEPOSIT_TX".to_string(),
                code: 0,
                raw_log: "success".to_string(),
                height: 1003,
            })
        }

        async fn broadcast_close_deployment(&self, _signer: &Self::Signer, _owner: &str, _dseq: u64) -> Result<TxResult, DeployError> {
            Ok(TxResult {
                hash: "CLOSE_TX".to_string(),
                code: 0,
                raw_log: "success".to_string(),
                height: 1004,
            })
        }

        async fn send_manifest(&self, _provider_uri: &str, _lease: &LeaseId, _manifest: &[u8], _cert_pem: &[u8], _key_pem: &[u8]) -> Result<(), DeployError> {
            self.call_counts.lock().unwrap().send_manifest += 1;
            Ok(())
        }

        async fn query_provider_status(&self, _provider_uri: &str, _lease: &LeaseId, _cert_pem: &[u8], _key_pem: &[u8]) -> Result<ProviderLeaseStatus, DeployError> {
            self.call_counts.lock().unwrap().query_provider_status += 1;
            self.provider_status.lock().unwrap()
                .clone()
                .ok_or_else(|| DeployError::Provider("no status".into()))
        }

        async fn load_state(&self, _session_id: &str) -> Result<Option<DeploymentState>, DeployError> {
            Ok(None)
        }

        async fn save_state(&self, _session_id: &str, _state: &DeploymentState) -> Result<(), DeployError> {
            Ok(())
        }

        async fn load_cert_key(&self, _owner: &str) -> Result<Option<Vec<u8>>, DeployError> {
            Ok(None)
        }

        async fn save_cert_key(&self, _owner: &str, _key: &[u8]) -> Result<(), DeployError> {
            Ok(())
        }

        async fn delete_cert_key(&self, _owner: &str) -> Result<(), DeployError> {
            Ok(())
        }

        async fn load_cached_provider(&self, _provider: &str) -> Result<Option<ProviderInfo>, DeployError> {
            Ok(None)
        }

        async fn cache_provider(&self, _info: &ProviderInfo) -> Result<(), DeployError> {
            Ok(())
        }
    }

    #[test]
    fn test_default_config() {
        let config = WorkflowConfig::default();
        assert_eq!(config.min_balance_uakt, 5_000_000);
        assert!(!config.auto_select_cheapest_bid);
    }

    #[test]
    fn test_step_result_variants() {
        let _ = StepResult::Continue;
        let _ = StepResult::Complete;
        let _ = StepResult::Failed("oops".into());
        let _ = StepResult::NeedsInput(InputRequired::ProvideSdl);
    }

    #[tokio::test]
    async fn test_workflow_check_balance_sufficient() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::CheckBalance;

        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Continue));
        assert_eq!(backend.get_call_counts().query_balance, 1);
    }

    #[tokio::test]
    async fn test_workflow_check_balance_insufficient() {
        let backend = MockBackend::new();
        backend.set_balance(1_000_000);

        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::CheckBalance;

        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Failed(_)));
    }

    #[tokio::test]
    async fn test_workflow_wait_for_bids() {
        let backend = MockBackend::new();
        backend.set_bids(vec![Bid {
            provider: "akash1provider".to_string(),
            price_uakt: 1000,
            resources: Resources::default(),
        }]);

        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::WaitForBids { waited_blocks: 0 };
        state.dseq = Some(123456);

        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Continue));
        assert_eq!(state.bids.len(), 1);
    }

    #[tokio::test]
    async fn test_workflow_auto_select_cheapest() {
        let backend = MockBackend::new();

        let signer = MockSigner;
        let mut config = WorkflowConfig::default();
        config.auto_select_cheapest_bid = true;
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::SelectProvider;
        state.bids = vec![
            Bid {
                provider: "akash1expensive".to_string(),
                price_uakt: 5000,
                resources: Resources::default(),
            },
            Bid {
                provider: "akash1cheap".to_string(),
                price_uakt: 1000,
                resources: Resources::default(),
            },
        ];

        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Continue));
        assert_eq!(state.selected_provider, Some("akash1cheap".to_string()));
    }

    #[tokio::test]
    async fn test_workflow_endpoints_ready() {
        let backend = MockBackend::new();
        backend.set_provider_status(ProviderLeaseStatus {
            ready: true,
            endpoints: vec![ServiceEndpoint {
                service: "web".to_string(),
                uri: "https://web.example.com".to_string(),
                port: 80,
            }],
        });

        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::WaitForEndpoints { attempts: 0 };
        state.dseq = Some(123456);
        state.selected_provider = Some("akash1provider".to_string());
        state.lease_id = Some(LeaseId {
            owner: "akash1owner".to_string(),
            dseq: 123456,
            gseq: 1,
            oseq: 1,
            provider: "akash1provider".to_string(),
        });
        state.cert_pem = Some(vec![1, 2, 3]); // Mock cert
        state.key_pem = Some(vec![4, 5, 6]); // Mock key

        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Complete));
        assert_eq!(state.endpoints.len(), 1);
    }

    #[tokio::test]
    async fn test_select_provider_invalid() {
        let mut state = DeploymentState::new("test", "akash1owner");
        state.bids = vec![Bid {
            provider: "akash1provider1".to_string(),
            price_uakt: 1000,
            resources: Resources::default(),
        }];

        let result = DeploymentWorkflow::<MockBackend>::select_provider(&mut state, "akash1nonexistent");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_select_provider_valid() {
        let mut state = DeploymentState::new("test", "akash1owner");
        state.bids = vec![Bid {
            provider: "akash1provider1".to_string(),
            price_uakt: 1000,
            resources: Resources::default(),
        }];

        DeploymentWorkflow::<MockBackend>::select_provider(&mut state, "akash1provider1").unwrap();
        assert_eq!(state.selected_provider, Some("akash1provider1".to_string()));
    }

    #[tokio::test]
    async fn test_provide_sdl() {
        let mut state = DeploymentState::new("test", "akash1owner");
        DeploymentWorkflow::<MockBackend>::provide_sdl(&mut state, "version: 2.0");
        assert_eq!(state.sdl_content, Some("version: 2.0".to_string()));
    }

    #[tokio::test]
    async fn test_step_init_missing_sdl() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::Init;

        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::NeedsInput(InputRequired::ProvideSdl)));
    }

    #[tokio::test]
    async fn test_run_to_completion_needs_input() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::Init;

        let result = workflow.run_to_completion(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::NeedsInput(_)));
    }

    #[tokio::test]
    async fn test_step_init_with_sdl() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::Init;
        state.sdl_content = Some("version: 2.0".to_string());

        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Continue));
        assert!(matches!(state.step, Step::CheckBalance));
    }

    #[tokio::test]
    async fn test_step_complete() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::Complete;

        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Complete));
    }

    #[tokio::test]
    async fn test_step_failed() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::Failed {
            reason: "test error".to_string(),
            recoverable: false,
        };

        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Failed(_)));
    }

    #[tokio::test]
    async fn test_step_create_deployment_missing_dseq() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::CreateDeployment;
        state.sdl_content = Some(SIMPLE_SDL.to_string());

        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Continue));
        assert!(matches!(state.step, Step::WaitForBids { .. }));
        assert!(state.dseq.is_some());
    }

    #[tokio::test]
    async fn test_step_create_lease_missing_provider() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::CreateLease;
        state.dseq = Some(123456);
        // No selected_provider

        let result = workflow.advance(&mut state).await;
        assert!(result.is_err() || matches!(result, Ok(StepResult::Failed(_))));
    }

    #[tokio::test]
    async fn test_step_send_manifest_missing_sdl() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::SendManifest;
        state.dseq = Some(123456);
        state.selected_provider = Some("akash1provider".to_string());
        state.cert_pem = Some(vec![1, 2, 3]);
        state.key_pem = Some(vec![4, 5, 6]);
        // No SDL content

        let result = workflow.advance(&mut state).await;
        assert!(result.is_err() || matches!(result, Ok(StepResult::Failed(_))));
    }

    #[tokio::test]
    async fn test_step_wait_for_endpoints_missing_lease_id() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::WaitForEndpoints { attempts: 0 };
        state.dseq = Some(123456);
        state.selected_provider = Some("akash1provider".to_string());
        state.cert_pem = Some(vec![1, 2, 3]);
        state.key_pem = Some(vec![4, 5, 6]);
        // No lease_id

        let result = workflow.advance(&mut state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_step_wait_for_endpoints_missing_cert() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::WaitForEndpoints { attempts: 0 };
        state.dseq = Some(123456);
        state.selected_provider = Some("akash1provider".to_string());
        state.lease_id = Some(LeaseId {
            owner: "akash1owner".to_string(),
            dseq: 123456,
            gseq: 1,
            oseq: 1,
            provider: "akash1provider".to_string(),
        });
        // No cert_pem or key_pem

        let result = workflow.advance(&mut state).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_build_manifest_empty() {
        let result = build_manifest("akash1owner", "", 123);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_build_manifest_valid_sdl() {
        let result = build_manifest("akash1owner", SIMPLE_SDL, 123);
        assert!(result.is_ok());
        let manifest_bytes = result.unwrap();
        assert!(!manifest_bytes.is_empty());
    }

    #[test]
    fn test_generate_cert() {
        let result = generate_certificate("akash1owner");
        assert!(result.is_ok());
        let (cert_pem, key_pem, pubkey_pem) = result.unwrap();
        assert!(!cert_pem.is_empty());
        assert!(!key_pem.is_empty());
        assert!(!pubkey_pem.is_empty());
    }

    #[tokio::test]
    async fn test_step_select_provider_with_trusted() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let mut config = WorkflowConfig::default();
        config.trusted_providers = vec!["akash1trusted".to_string()];
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::SelectProvider;
        state.bids = vec![
            Bid {
                provider: "akash1trusted".to_string(),
                price_uakt: 5000,
                resources: Resources::default(),
            },
            Bid {
                provider: "akash1cheap".to_string(),
                price_uakt: 1000,
                resources: Resources::default(),
            },
        ];

        let result = workflow.advance(&mut state).await.unwrap();
        // Should need input since auto_select is false
        assert!(matches!(result, StepResult::NeedsInput(_)));
    }

    #[tokio::test]
    async fn test_step_create_deployment_with_valid_sdl() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::CreateDeployment;
        state.sdl_content = Some(SIMPLE_SDL.to_string());

        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Continue));
        assert!(state.dseq.is_some());
        assert!(matches!(state.step, Step::WaitForBids { .. }));
    }

    #[tokio::test]
    async fn test_full_workflow_to_bids() {
        let backend = MockBackend::new();
        backend.set_bids(vec![Bid {
            provider: "akash1provider".to_string(),
            price_uakt: 1000,
            resources: Resources::default(),
        }]);

        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.sdl_content = Some(SIMPLE_SDL.to_string());

        // Run through Init -> CheckBalance -> EnsureCertificate -> CreateDeployment -> WaitForBids
        let mut steps = 0;
        loop {
            let result = workflow.advance(&mut state).await.unwrap();
            steps += 1;

            match result {
                StepResult::Continue => {
                    if steps > 10 {
                        panic!("Too many steps");
                    }
                    continue;
                }
                StepResult::NeedsInput(_) => break,
                StepResult::Complete => break,
                StepResult::Failed(reason) => panic!("Failed: {}", reason),
            }
        }

        // Should have bids now and be at SelectProvider step
        assert!(!state.bids.is_empty());
        assert!(matches!(state.step, Step::SelectProvider));
    }

    #[tokio::test]
    async fn test_workflow_wait_for_bids_timeout() {
        let backend = MockBackend::new();
        backend.set_bids(vec![]); // No bids
        let signer = MockSigner;
        let mut config = WorkflowConfig::default();
        config.max_bid_wait_attempts = 2; // Short timeout
        config.bid_wait_seconds = 0; // No actual wait
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.dseq = Some(123456);
        state.step = Step::WaitForBids { waited_blocks: 0 };

        // First attempt - no bids, should retry
        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Continue));
        assert!(matches!(state.step, Step::WaitForBids { waited_blocks: 1 }));

        // Second attempt - still no bids, should retry
        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Continue));
        assert!(matches!(state.step, Step::WaitForBids { waited_blocks: 2 }));

        // Third attempt - max reached, should fail
        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Failed(_)));
    }

    #[tokio::test]
    async fn test_workflow_select_provider_no_bids() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::SelectProvider;
        state.bids = vec![]; // Empty bids

        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Failed(_)));
    }

    #[tokio::test]
    async fn test_workflow_select_provider_already_selected() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::SelectProvider;
        state.bids = vec![Bid {
            provider: "akash1provider".to_string(),
            price_uakt: 1000,
            resources: Resources::default(),
        }];
        state.selected_provider = Some("akash1provider".to_string());

        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Continue));
        assert!(matches!(state.step, Step::CreateLease));
    }

    #[tokio::test]
    async fn test_workflow_select_provider_auto_select() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let mut config = WorkflowConfig::default();
        config.auto_select_cheapest_bid = true;
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::SelectProvider;
        state.bids = vec![
            Bid {
                provider: "akash1expensive".to_string(),
                price_uakt: 5000,
                resources: Resources::default(),
            },
            Bid {
                provider: "akash1cheap".to_string(),
                price_uakt: 1000,
                resources: Resources::default(),
            },
        ];

        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Continue));
        assert_eq!(state.selected_provider, Some("akash1cheap".to_string()));
    }

    #[tokio::test]
    async fn test_workflow_auto_select_trusted_provider() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let mut config = WorkflowConfig::default();
        config.auto_select_cheapest_bid = true;
        config.trusted_providers = vec!["akash1trusted".to_string()];
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::SelectProvider;
        state.bids = vec![
            Bid {
                provider: "akash1trusted".to_string(),
                price_uakt: 5000, // More expensive
                resources: Resources::default(),
            },
            Bid {
                provider: "akash1cheap".to_string(),
                price_uakt: 1000, // Cheaper
                resources: Resources::default(),
            },
        ];

        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Continue));
        // Should select trusted provider even though it's more expensive
        assert_eq!(state.selected_provider, Some("akash1trusted".to_string()));
    }

    #[tokio::test]
    async fn test_workflow_create_lease_missing_dseq() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::CreateLease;
        state.selected_provider = Some("akash1provider".to_string());
        // Missing dseq

        let result = workflow.advance(&mut state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_workflow_create_lease_no_provider_selected() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::CreateLease;
        state.dseq = Some(123456);
        // No provider selected

        let result = workflow.advance(&mut state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_workflow_create_lease_bid_not_found() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::CreateLease;
        state.dseq = Some(123456);
        state.selected_provider = Some("akash1nonexistent".to_string());
        state.bids = vec![Bid {
            provider: "akash1other".to_string(),
            price_uakt: 1000,
            resources: Resources::default(),
        }];

        let result = workflow.advance(&mut state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_workflow_send_manifest_missing_lease_id() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::SendManifest;
        state.cert_pem = Some(vec![1, 2, 3]);
        state.key_pem = Some(vec![4, 5, 6]);
        state.sdl_content = Some(SIMPLE_SDL.to_string());
        // Missing lease_id

        let result = workflow.advance(&mut state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_workflow_send_manifest_missing_cert() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::SendManifest;
        state.lease_id = Some(LeaseId {
            owner: "akash1owner".to_string(),
            dseq: 123456,
            gseq: 1,
            oseq: 1,
            provider: "akash1provider".to_string(),
        });
        state.sdl_content = Some(SIMPLE_SDL.to_string());
        // Missing cert and key

        let result = workflow.advance(&mut state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_workflow_send_manifest_missing_key() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::SendManifest;
        state.lease_id = Some(LeaseId {
            owner: "akash1owner".to_string(),
            dseq: 123456,
            gseq: 1,
            oseq: 1,
            provider: "akash1provider".to_string(),
        });
        state.cert_pem = Some(vec![1, 2, 3]);
        state.sdl_content = Some(SIMPLE_SDL.to_string());
        // Missing key

        let result = workflow.advance(&mut state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_workflow_send_manifest_missing_sdl() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::SendManifest;
        state.lease_id = Some(LeaseId {
            owner: "akash1owner".to_string(),
            dseq: 123456,
            gseq: 1,
            oseq: 1,
            provider: "akash1provider".to_string(),
        });
        state.cert_pem = Some(vec![1, 2, 3]);
        state.key_pem = Some(vec![4, 5, 6]);
        // Missing SDL

        let result = workflow.advance(&mut state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_workflow_wait_for_endpoints_missing_key() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::WaitForEndpoints { attempts: 0 };
        state.lease_id = Some(LeaseId {
            owner: "akash1owner".to_string(),
            dseq: 123456,
            gseq: 1,
            oseq: 1,
            provider: "akash1provider".to_string(),
        });
        state.cert_pem = Some(vec![1, 2, 3]);
        // Missing key

        let result = workflow.advance(&mut state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_workflow_wait_for_endpoints_timeout() {
        let backend = MockBackend::new();
        // Status shows not ready
        backend.set_provider_status(ProviderLeaseStatus {
            ready: false,
            endpoints: vec![],
        });

        let signer = MockSigner;
        let mut config = WorkflowConfig::default();
        config.max_endpoint_wait_attempts = 1; // Short timeout
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::WaitForEndpoints { attempts: 0 };
        state.lease_id = Some(LeaseId {
            owner: "akash1owner".to_string(),
            dseq: 123456,
            gseq: 1,
            oseq: 1,
            provider: "akash1provider".to_string(),
        });
        state.cert_pem = Some(vec![1, 2, 3]);
        state.key_pem = Some(vec![4, 5, 6]);

        // First attempt - not ready, should retry
        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Continue));
        assert!(matches!(state.step, Step::WaitForEndpoints { attempts: 1 }));

        // Second attempt - max reached, should fail
        let result = workflow.advance(&mut state).await.unwrap();
        assert!(matches!(result, StepResult::Failed(_)));
    }

    #[tokio::test]
    async fn test_workflow_wait_for_bids_missing_dseq() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::WaitForBids { waited_blocks: 0 };
        // Missing dseq

        let result = workflow.advance(&mut state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_workflow_create_deployment_missing_sdl() {
        let backend = MockBackend::new();
        let signer = MockSigner;
        let config = WorkflowConfig::default();
        let workflow = DeploymentWorkflow::new(&backend, &signer, config);

        let mut state = DeploymentState::new("test", "akash1owner");
        state.step = Step::CreateDeployment;
        // Missing SDL

        let result = workflow.advance(&mut state).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_build_manifest_empty_sdl() {
        let result = build_manifest("akash1owner", "", 123);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DeployError::Manifest(_)));
    }

}
