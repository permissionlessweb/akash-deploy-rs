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

        // Get provider URI
        let provider_info = self
            .backend
            .query_provider_info(&lease.provider)
            .await?
            .ok_or_else(|| DeployError::Provider("provider not found".into()))?;

        // Build manifest from SDL using the actual ManifestBuilder
        let manifest = build_manifest(&state.owner, sdl, lease.dseq)?;

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

    #[test]
    fn test_default_config() {
        let config = WorkflowConfig::default();
        assert_eq!(config.min_balance_uakt, 5_000_000);
        assert!(!config.auto_select_cheapest_bid);
    }

    #[test]
    fn test_step_result_variants() {
        // Just make sure these compile
        let _ = StepResult::Continue;
        let _ = StepResult::Complete;
        let _ = StepResult::Failed("oops".into());
        let _ = StepResult::NeedsInput(InputRequired::ProvideSdl);
    }
}
