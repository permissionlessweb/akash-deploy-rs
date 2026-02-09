//! Deployment state machine definition.
//!
//! The state is the complete snapshot of a deployment workflow.
//! It's serializable, restorable, and the workflow engine doesn't
//! care how you persist it — that's the backend's problem.

use crate::types::{Bid, LeaseId, ServiceEndpoint};
use serde::{Deserialize, Serialize};

/// Workflow steps — the state machine's nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Step {
    /// Starting point.
    Init,
    /// Check account has enough AKT.
    CheckBalance,
    /// Ensure mTLS certificate exists on chain.
    EnsureCertificate,
    /// Create the deployment on chain.
    CreateDeployment,
    /// Wait for provider bids.
    WaitForBids { waited_blocks: u32 },
    /// Select a provider from available bids.
    SelectProvider,
    /// Create lease with selected provider.
    CreateLease,
    /// Send manifest to provider.
    SendManifest,
    /// Wait for provider to spin up and expose endpoints.
    WaitForEndpoints { attempts: u32 },
    /// Done.
    Complete,
    /// Failed, possibly recoverable.
    Failed { reason: String, recoverable: bool },
}

impl Step {
    /// Human-readable step name for logging/display.
    pub fn name(&self) -> &'static str {
        match self {
            Step::Init => "init",
            Step::CheckBalance => "check_balance",
            Step::EnsureCertificate => "ensure_certificate",
            Step::CreateDeployment => "create_deployment",
            Step::WaitForBids { .. } => "wait_for_bids",
            Step::SelectProvider => "select_provider",
            Step::CreateLease => "create_lease",
            Step::SendManifest => "send_manifest",
            Step::WaitForEndpoints { .. } => "wait_for_endpoints",
            Step::Complete => "complete",
            Step::Failed { .. } => "failed",
        }
    }
}

/// Full workflow state — serializable, restorable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentState {
    /// Unique session identifier.
    pub session_id: String,
    /// Current step in the workflow.
    pub step: Step,
    /// Account address that owns this deployment.
    pub owner: String,
    /// User-defined label for the deployment.
    pub label: String,

    // Populated as workflow progresses
    /// SDL content (YAML).
    pub sdl_content: Option<String>,

    // Template support (feature-gated)
    #[cfg(feature = "sdl-templates")]
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Template variable overrides.
    pub template_variables: Option<std::collections::HashMap<String, String>>,

    #[cfg(feature = "sdl-templates")]
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Template default values.
    pub template_defaults: Option<std::collections::HashMap<String, String>>,

    #[cfg(feature = "sdl-templates")]
    #[serde(default)]
    /// Whether the SDL content is a template.
    pub is_template: bool,
    /// Deposit amount in uakt.
    pub deposit_uakt: u64,
    /// Deployment sequence number (from chain).
    pub dseq: Option<u64>,
    /// Group sequence (usually 1).
    pub gseq: u32,
    /// Order sequence (usually 1).
    pub oseq: u32,

    // Certificate for mTLS
    /// Certificate PEM (public).
    pub cert_pem: Option<Vec<u8>>,
    /// Private key PEM (encrypted or plaintext depending on backend).
    pub key_pem: Option<Vec<u8>>,

    // Bids and selection
    /// Available bids from providers.
    pub bids: Vec<Bid>,
    /// Selected provider address.
    pub selected_provider: Option<String>,

    // Result
    /// Service endpoints after deployment.
    pub endpoints: Vec<ServiceEndpoint>,
    /// Lease ID once created.
    pub lease_id: Option<LeaseId>,

    // Audit
    /// Unix timestamp of creation.
    pub created_at: u64,
    /// Unix timestamp of last update.
    pub updated_at: u64,
    /// Transaction hashes for all txs in this workflow.
    pub tx_hashes: Vec<String>,
}

impl DeploymentState {
    /// Create a new deployment state.
    pub fn new(session_id: impl Into<String>, owner: impl Into<String>) -> Self {
        let now = current_unix_time();

        Self {
            session_id: session_id.into(),
            step: Step::Init,
            owner: owner.into(),
            label: String::new(),
            sdl_content: None,
            deposit_uakt: 5_000_000, // 5 AKT default
            dseq: None,
            gseq: 1,
            oseq: 1,
            cert_pem: None,
            key_pem: None,
            bids: Vec::new(),
            selected_provider: None,
            endpoints: Vec::new(),
            lease_id: None,
            created_at: now,
            updated_at: now,
            tx_hashes: Vec::new(),
            #[cfg(feature = "sdl-templates")]
            template_variables: None,
            #[cfg(feature = "sdl-templates")]
            template_defaults: None,
            #[cfg(feature = "sdl-templates")]
            is_template: false,
        }
    }

    /// Set the label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// Set the SDL content.
    pub fn with_sdl(mut self, sdl: impl Into<String>) -> Self {
        self.sdl_content = Some(sdl.into());
        self
    }

    /// Set the deposit amount.
    pub fn with_deposit(mut self, deposit_uakt: u64) -> Self {
        self.deposit_uakt = deposit_uakt;
        self
    }

    /// Set template defaults and mark as template.
    #[cfg(feature = "sdl-templates")]
    pub fn with_template(mut self, defaults: std::collections::HashMap<String, String>) -> Self {
        self.is_template = true;
        self.template_defaults = Some(defaults);
        self
    }

    /// Set template variable overrides.
    #[cfg(feature = "sdl-templates")]
    pub fn with_variables(
        mut self,
        variables: std::collections::HashMap<String, String>,
    ) -> Self {
        self.template_variables = Some(variables);
        self
    }

    /// Is this workflow in a terminal state?
    pub fn is_terminal(&self) -> bool {
        matches!(self.step, Step::Complete | Step::Failed { .. })
    }

    /// Is this workflow failed?
    pub fn is_failed(&self) -> bool {
        matches!(self.step, Step::Failed { .. })
    }

    /// Is this workflow complete?
    pub fn is_complete(&self) -> bool {
        matches!(self.step, Step::Complete)
    }

    /// Record a transaction hash.
    pub fn record_tx(&mut self, hash: impl Into<String>) {
        self.tx_hashes.push(hash.into());
        self.updated_at = current_unix_time();
    }

    /// Transition to a new step.
    pub fn transition(&mut self, step: Step) {
        self.step = step;
        self.updated_at = current_unix_time();
    }

    /// Fail the workflow.
    pub fn fail(&mut self, reason: impl Into<String>, recoverable: bool) {
        self.step = Step::Failed {
            reason: reason.into(),
            recoverable,
        };
        self.updated_at = current_unix_time();
    }
}

fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_state() {
        let state = DeploymentState::new("session-1", "akash1abc...");
        assert_eq!(state.session_id, "session-1");
        assert_eq!(state.owner, "akash1abc...");
        assert!(matches!(state.step, Step::Init));
        assert!(!state.is_terminal());
    }

    #[test]
    fn test_builder_pattern() {
        let state = DeploymentState::new("s1", "owner")
            .with_label("test-deploy")
            .with_sdl("version: 2")
            .with_deposit(10_000_000);

        assert_eq!(state.label, "test-deploy");
        assert_eq!(state.sdl_content, Some("version: 2".to_string()));
        assert_eq!(state.deposit_uakt, 10_000_000);
    }

    #[test]
    fn test_terminal_states() {
        let mut state = DeploymentState::new("s1", "owner");
        assert!(!state.is_terminal());

        state.transition(Step::Complete);
        assert!(state.is_terminal());
        assert!(state.is_complete());

        state.fail("something broke", true);
        assert!(state.is_terminal());
        assert!(state.is_failed());
    }

    #[test]
    fn test_step_names() {
        // Test all step name() variants
        assert_eq!(Step::Init.name(), "init");
        assert_eq!(Step::CheckBalance.name(), "check_balance");
        assert_eq!(Step::EnsureCertificate.name(), "ensure_certificate");
        assert_eq!(Step::CreateDeployment.name(), "create_deployment");
        assert_eq!(
            Step::WaitForBids { waited_blocks: 0 }.name(),
            "wait_for_bids"
        );
        assert_eq!(Step::SelectProvider.name(), "select_provider");
        assert_eq!(Step::CreateLease.name(), "create_lease");
        assert_eq!(Step::SendManifest.name(), "send_manifest");
        assert_eq!(
            Step::WaitForEndpoints { attempts: 0 }.name(),
            "wait_for_endpoints"
        );
        assert_eq!(Step::Complete.name(), "complete");
        assert_eq!(
            Step::Failed {
                reason: "test".to_string(),
                recoverable: false
            }
            .name(),
            "failed"
        );
    }
}
