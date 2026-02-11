//! [`DeploymentStore`] trait definition.

use crate::store::DeploymentRecord;
use crate::error::DeployError;
use async_trait::async_trait;

/// Trait for persisting deployment records indexed by dseq.
#[async_trait]
pub trait DeploymentStore: Send + Sync {
    /// Save a deployment record. Overwrites any existing record for this dseq.
    async fn save(&mut self, record: &DeploymentRecord) -> Result<(), DeployError>;

    /// Load a deployment record by dseq. Returns `None` if not found.
    async fn load(&self, dseq: u64) -> Result<Option<DeploymentRecord>, DeployError>;

    /// List all stored deployment records.
    async fn list(&self) -> Result<Vec<DeploymentRecord>, DeployError>;

    /// Delete a deployment record by dseq. Idempotent.
    async fn delete(&mut self, dseq: u64) -> Result<(), DeployError>;
}
