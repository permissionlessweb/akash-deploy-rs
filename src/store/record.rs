//! [`DeploymentRecord`] — on-disk representation of a deployment.

use crate::auth::certificate::{decrypt_key, encrypt_key};
use crate::error::DeployError;
use crate::state::{DeploymentState, Step};
use crate::types::{Bid, LeaseId, ServiceEndpoint};
use serde::{Deserialize, Serialize};

/// On-disk representation of a deployment.
///
/// Mirrors [`DeploymentState`] but with encrypted sensitive fields.
/// The `key_pem` is always encrypted with ChaCha20-Poly1305 before storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentRecord {
    pub dseq: u64,
    pub owner: String,
    pub label: String,
    pub step: Step,
    pub sdl_content: Option<String>,
    pub deposit_uakt: u64,
    pub gseq: u32,
    pub oseq: u32,
    /// Public certificate — safe to store as-is.
    pub cert_pem: Option<Vec<u8>>,
    /// Private key encrypted with ChaCha20-Poly1305.
    pub encrypted_key_pem: Option<Vec<u8>>,
    pub bids: Vec<Bid>,
    pub selected_provider: Option<String>,
    pub endpoints: Vec<ServiceEndpoint>,
    pub lease_id: Option<LeaseId>,
    pub created_at: u64,
    pub updated_at: u64,
    pub tx_hashes: Vec<String>,

    #[cfg(feature = "sdl-templates")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_variables: Option<std::collections::HashMap<String, String>>,

    #[cfg(feature = "sdl-templates")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_defaults: Option<std::collections::HashMap<String, String>>,

    #[cfg(feature = "sdl-templates")]
    #[serde(default)]
    pub is_template: bool,
}

impl DeploymentRecord {
    /// Create a record from a [`DeploymentState`], encrypting the private key.
    ///
    /// The `password` is used to derive an encryption key via Argon2id.
    /// Returns an error if the state has no `dseq` assigned yet.
    pub fn from_state(state: &DeploymentState, password: &str) -> Result<Self, DeployError> {
        let dseq = state.dseq.ok_or_else(|| {
            DeployError::InvalidState("cannot persist deployment without dseq".into())
        })?;

        let encrypted_key_pem = match &state.key_pem {
            Some(key) => Some(encrypt_key(key, password)?),
            None => None,
        };

        Ok(Self {
            dseq,
            owner: state.owner.clone(),
            label: state.label.clone(),
            step: state.step.clone(),
            sdl_content: state.sdl_content.clone(),
            deposit_uakt: state.deposit_uakt,
            gseq: state.gseq,
            oseq: state.oseq,
            cert_pem: state.cert_pem.clone(),
            encrypted_key_pem,
            bids: state.bids.clone(),
            selected_provider: state.selected_provider.clone(),
            endpoints: state.endpoints.clone(),
            lease_id: state.lease_id.clone(),
            created_at: state.created_at,
            updated_at: state.updated_at,
            tx_hashes: state.tx_hashes.clone(),
            #[cfg(feature = "sdl-templates")]
            template_variables: state.template_variables.clone(),
            #[cfg(feature = "sdl-templates")]
            template_defaults: state.template_defaults.clone(),
            #[cfg(feature = "sdl-templates")]
            is_template: state.is_template,
        })
    }

    /// Convert this record back into a [`DeploymentState`], decrypting the private key.
    ///
    /// Requires a `session_id` (not stored in the record) and the `password`
    /// used during encryption.
    pub fn to_state(
        self,
        session_id: &str,
        password: &str,
    ) -> Result<DeploymentState, DeployError> {
        let key_pem = match self.encrypted_key_pem {
            Some(ref encrypted) => Some(decrypt_key(encrypted, password)?),
            None => None,
        };

        Ok(DeploymentState {
            session_id: session_id.to_string(),
            step: self.step,
            owner: self.owner,
            label: self.label,
            sdl_content: self.sdl_content,
            deposit_uakt: self.deposit_uakt,
            dseq: Some(self.dseq),
            gseq: self.gseq,
            oseq: self.oseq,
            cert_pem: self.cert_pem,
            key_pem,
            bids: self.bids,
            selected_provider: self.selected_provider,
            endpoints: self.endpoints,
            lease_id: self.lease_id,
            created_at: self.created_at,
            updated_at: self.updated_at,
            tx_hashes: self.tx_hashes,
            #[cfg(feature = "sdl-templates")]
            template_variables: self.template_variables,
            #[cfg(feature = "sdl-templates")]
            template_defaults: self.template_defaults,
            #[cfg(feature = "sdl-templates")]
            is_template: self.is_template,
        })
    }
}
