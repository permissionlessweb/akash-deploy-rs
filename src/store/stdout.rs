//! Stdout-based storage fallback.
//!
//! When the `file-storage` feature is disabled, this implementation outputs
//! state as JSON to stdout for interoperability with external tools and pipelines.
//! Read operations always return `None` / empty (no persistence across runs).

use crate::error::DeployError;
use crate::state::DeploymentState;
use crate::store::SessionStorage;
use crate::types::{CertificateInfo, ProviderInfo};
use async_trait::async_trait;

/// Storage backend that outputs JSON to stdout.
///
/// Write operations serialize to JSON and print to stdout.
/// Read operations return `None` — there is no persistence.
///
/// Useful for:
/// - Piping deployment state to other tools (`deploy | jq`)
/// - Environments without filesystem access (WASM, serverless)
/// - Debugging / logging all state transitions
pub struct StdoutStorage;

impl StdoutStorage {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StdoutStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionStorage for StdoutStorage {
    async fn save_session(&mut self, session: &DeploymentState) -> Result<(), DeployError> {
        let json = serde_json::to_string_pretty(session)
            .map_err(|e| DeployError::Storage(format!("failed to serialize session: {}", e)))?;
        println!("{}", json);
        Ok(())
    }

    async fn load_session(&self, _session_id: &str) -> Result<Option<DeploymentState>, DeployError> {
        Ok(None)
    }

    async fn list_sessions(&self) -> Result<Vec<String>, DeployError> {
        Ok(Vec::new())
    }

    async fn delete_session(&mut self, _session_id: &str) -> Result<(), DeployError> {
        Ok(())
    }

    async fn save_cert_key(&mut self, owner: &str, key_pem: &[u8]) -> Result<(), DeployError> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let json = serde_json::json!({
            "type": "cert_key",
            "owner": owner,
            "key_pem_base64": STANDARD.encode(key_pem),
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
        Ok(())
    }

    async fn load_cert_key(&self, _owner: &str) -> Result<Option<Vec<u8>>, DeployError> {
        Ok(None)
    }

    async fn delete_cert_key(&mut self, _owner: &str) -> Result<(), DeployError> {
        Ok(())
    }

    async fn cache_provider(&mut self, info: &ProviderInfo) -> Result<(), DeployError> {
        let json = serde_json::to_string_pretty(info)
            .map_err(|e| DeployError::Storage(format!("failed to serialize provider: {}", e)))?;
        println!("{}", json);
        Ok(())
    }

    async fn load_cached_provider(
        &self,
        _provider: &str,
    ) -> Result<Option<ProviderInfo>, DeployError> {
        Ok(None)
    }

    async fn cache_certificate(&mut self, info: &CertificateInfo) -> Result<(), DeployError> {
        let json = serde_json::to_string_pretty(info)
            .map_err(|e| DeployError::Storage(format!("failed to serialize certificate: {}", e)))?;
        println!("{}", json);
        Ok(())
    }

    async fn load_cached_certificate(
        &self,
        _owner: &str,
    ) -> Result<Option<CertificateInfo>, DeployError> {
        Ok(None)
    }
}
