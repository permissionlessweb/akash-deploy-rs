//! File-backed deployment store.
//!
//! Stores each deployment record as `{dseq}/status.json` under
//! `~/.akash-deploy/deployments/`.

use crate::error::DeployError;
use crate::store::{DeploymentRecord, DeploymentStore};
use async_trait::async_trait;
use std::path::PathBuf;

/// File-backed implementation of [`DeploymentStore`].
///
/// Each deployment is stored as `{deployments_dir}/{dseq}/status.json`.
pub struct FileDeploymentStore {
    deployments_dir: PathBuf,
}

impl FileDeploymentStore {
    /// Create a store using the default directory (`~/.akash-deploy/deployments`).
    pub async fn new_default() -> Result<Self, DeployError> {
        let home = dirs::home_dir()
            .ok_or_else(|| DeployError::Storage("could not determine home directory".into()))?;
        let deployments_dir = home.join(".akash-deploy").join("deployments");
        Self::new(deployments_dir).await
    }

    /// Create a store at a custom directory path.
    pub async fn new(deployments_dir: PathBuf) -> Result<Self, DeployError> {
        tokio::fs::create_dir_all(&deployments_dir)
            .await
            .map_err(|e| {
                DeployError::Storage(format!("failed to create deployments dir: {}", e))
            })?;

        Ok(Self { deployments_dir })
    }

    fn record_path(&self, dseq: u64) -> PathBuf {
        self.deployments_dir
            .join(dseq.to_string())
            .join("status.json")
    }

    fn dseq_dir(&self, dseq: u64) -> PathBuf {
        self.deployments_dir.join(dseq.to_string())
    }
}

#[async_trait]
impl DeploymentStore for FileDeploymentStore {
    async fn save(&mut self, record: &DeploymentRecord) -> Result<(), DeployError> {
        let dir = self.dseq_dir(record.dseq);
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| DeployError::Storage(format!("failed to create dseq dir: {}", e)))?;

        let content = serde_json::to_string_pretty(record)
            .map_err(|e| DeployError::Storage(format!("failed to serialize record: {}", e)))?;

        let path = self.record_path(record.dseq);
        tokio::fs::write(&path, content)
            .await
            .map_err(|e| DeployError::Storage(format!("failed to write record: {}", e)))?;

        Ok(())
    }

    async fn load(&self, dseq: u64) -> Result<Option<DeploymentRecord>, DeployError> {
        let path = self.record_path(dseq);

        if tokio::fs::metadata(&path).await.is_err() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| DeployError::Storage(format!("failed to read record: {}", e)))?;

        let record = serde_json::from_str(&content)
            .map_err(|e| DeployError::Storage(format!("failed to parse record: {}", e)))?;

        Ok(Some(record))
    }

    async fn list(&self) -> Result<Vec<DeploymentRecord>, DeployError> {
        let mut records = Vec::new();

        let mut entries = tokio::fs::read_dir(&self.deployments_dir)
            .await
            .map_err(|e| DeployError::Storage(format!("failed to read deployments dir: {}", e)))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| DeployError::Storage(format!("failed to read dir entry: {}", e)))?
        {
            let status_path = entry.path().join("status.json");
            if let Ok(content) = tokio::fs::read_to_string(&status_path).await {
                if let Ok(record) = serde_json::from_str::<DeploymentRecord>(&content) {
                    records.push(record);
                }
            }
        }

        Ok(records)
    }

    async fn delete(&mut self, dseq: u64) -> Result<(), DeployError> {
        let dir = self.dseq_dir(dseq);
        if tokio::fs::metadata(&dir).await.is_ok() {
            tokio::fs::remove_dir_all(&dir)
                .await
                .map_err(|e| DeployError::Storage(format!("failed to delete record: {}", e)))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{DeploymentState, Step};

    fn make_record_with_dseq(dseq: u64) -> DeploymentRecord {
        let mut state = DeploymentState::new("s", "akash1owner")
            .with_label(format!("deploy-{}", dseq))
            .with_sdl("version: \"2.0\"");
        state.dseq = Some(dseq);
        state.transition(Step::Complete);
        DeploymentRecord::from_state(&state, "pw").unwrap()
    }

    fn make_test_record() -> DeploymentRecord {
        make_record_with_dseq(99999)
    }

    #[tokio::test]
    async fn test_file_deployment_store_lifecycle() {
        let temp_dir =
            std::env::temp_dir().join(format!("akash-deploy-test-{}", rand::random::<u32>()));
        let mut store = FileDeploymentStore::new(temp_dir.clone()).await.unwrap();

        let record = make_test_record();

        // Save
        store.save(&record).await.unwrap();

        // Load
        let loaded = store.load(99999).await.unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.dseq, 99999);
        assert_eq!(loaded.owner, "akash1owner");

        // List
        let all = store.list().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].dseq, 99999);

        // Load non-existent
        let missing = store.load(11111).await.unwrap();
        assert!(missing.is_none());

        // Delete
        store.delete(99999).await.unwrap();
        let deleted = store.load(99999).await.unwrap();
        assert!(deleted.is_none());

        // Delete idempotent
        store.delete(99999).await.unwrap();

        // Cleanup
        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }

    #[tokio::test]
    async fn test_file_deployment_store_overwrite() {
        let temp_dir =
            std::env::temp_dir().join(format!("akash-deploy-test-{}", rand::random::<u32>()));
        let mut store = FileDeploymentStore::new(temp_dir.clone()).await.unwrap();

        let mut record = make_test_record();
        store.save(&record).await.unwrap();

        // Overwrite with updated label
        record.label = "updated".to_string();
        store.save(&record).await.unwrap();

        let loaded = store.load(99999).await.unwrap().unwrap();
        assert_eq!(loaded.label, "updated");

        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }

    #[tokio::test]
    async fn test_file_deployment_store_list_multiple() {
        let temp_dir =
            std::env::temp_dir().join(format!("akash-deploy-test-{}", rand::random::<u32>()));
        let mut store = FileDeploymentStore::new(temp_dir.clone()).await.unwrap();

        // Save multiple records
        store.save(&make_record_with_dseq(100)).await.unwrap();
        store.save(&make_record_with_dseq(200)).await.unwrap();
        store.save(&make_record_with_dseq(300)).await.unwrap();

        let all = store.list().await.unwrap();
        assert_eq!(all.len(), 3);

        let mut dseqs: Vec<u64> = all.iter().map(|r| r.dseq).collect();
        dseqs.sort();
        assert_eq!(dseqs, vec![100, 200, 300]);

        // Delete one, list should have 2
        store.delete(200).await.unwrap();
        let all = store.list().await.unwrap();
        assert_eq!(all.len(), 2);

        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }

    #[tokio::test]
    async fn test_file_deployment_store_list_ignores_bad_files() {
        let temp_dir =
            std::env::temp_dir().join(format!("akash-deploy-test-{}", rand::random::<u32>()));
        let mut store = FileDeploymentStore::new(temp_dir.clone()).await.unwrap();

        // Save a valid record
        store.save(&make_test_record()).await.unwrap();

        // Write garbage in another dseq dir
        let bad_dir = temp_dir.join("77777");
        tokio::fs::create_dir_all(&bad_dir).await.unwrap();
        tokio::fs::write(bad_dir.join("status.json"), "not valid json")
            .await
            .unwrap();

        // Also create a dir without status.json
        let empty_dir = temp_dir.join("88888");
        tokio::fs::create_dir_all(&empty_dir).await.unwrap();

        // List should only return the valid record
        let all = store.list().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].dseq, 99999);

        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }

    #[tokio::test]
    async fn test_file_deployment_store_persist_across_instances() {
        let temp_dir =
            std::env::temp_dir().join(format!("akash-deploy-test-{}", rand::random::<u32>()));

        // Save in first instance
        {
            let mut store = FileDeploymentStore::new(temp_dir.clone()).await.unwrap();
            store.save(&make_record_with_dseq(555)).await.unwrap();
        }

        // New instance should be able to load it
        let store2 = FileDeploymentStore::new(temp_dir.clone()).await.unwrap();
        let loaded = store2.load(555).await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().label, "deploy-555");

        let all = store2.list().await.unwrap();
        assert_eq!(all.len(), 1);

        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }
}
