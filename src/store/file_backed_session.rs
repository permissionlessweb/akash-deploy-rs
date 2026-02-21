//! File-backed storage implementation with in-memory caching.
//!
//! This module provides `FileBackedStorage`, the default implementation of
//! `SessionStorage` that stores data in the file system with an in-memory cache.
//!
//! # Storage Layout
//!
//! ```text
//! ~/.akash-deploy/
//!   sessions/
//!     session-1.json
//!     session-2.json
//!   certs/
//!     akash1xxx.key (encrypted private key)
//!     akash1yyy.key
//!   providers.json (provider cache)
//!   certificates.json (certificate cache)
//! ```

use crate::error::DeployError;
use crate::state::DeploymentState;
use crate::store::SessionStorage;
use crate::types::{CertificateInfo, ProviderInfo};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;

/// File-backed storage with in-memory caching.
///
/// This implementation uses a hybrid memory + file approach:
/// - Sessions are cached in memory for fast access
/// - All data is persisted to disk for durability
/// - Provider/certificate info is cached to reduce chain queries
///
/// # Example
///
/// ```ignore
/// use akash_deploy_rs::storage::FileBackedStorage;
///
/// # tokio_test::block_on(async {
/// // Use default storage directory (~/.akash-deploy)
/// let storage = FileBackedStorage::new_default().await?;
///
/// // Or specify custom directory
/// let storage = FileBackedStorage::new("/path/to/storage").await?;
/// # Ok::<(), DeployError>(())
/// # });
/// ```
pub struct FileBackedStorage {
    /// Base directory for all storage
    storage_dir: PathBuf,

    /// In-memory session cache
    sessions: HashMap<String, DeploymentState>,

    /// In-memory provider cache
    providers: HashMap<String, ProviderInfo>,

    /// In-memory certificate cache
    certificates: HashMap<String, CertificateInfo>,
}

impl FileBackedStorage {
    /// Create storage in the default directory (~/.akash-deploy).
    pub async fn new_default() -> Result<Self, DeployError> {
        let home = dirs::home_dir()
            .ok_or_else(|| DeployError::Storage("could not determine home directory".into()))?;
        let storage_dir = home.join(".akash-deploy");
        Self::new(storage_dir).await
    }

    /// Create storage in a custom directory.
    ///
    /// The directory will be created if it doesn't exist, along with subdirectories:
    /// - `sessions/`
    /// - `certs/`
    pub async fn new(storage_dir: PathBuf) -> Result<Self, DeployError> {
        // Create directory structure
        tokio::fs::create_dir_all(&storage_dir)
            .await
            .map_err(|e| DeployError::Storage(format!("failed to create storage dir: {}", e)))?;

        let sessions_dir = storage_dir.join("sessions");
        tokio::fs::create_dir_all(&sessions_dir)
            .await
            .map_err(|e| DeployError::Storage(format!("failed to create sessions dir: {}", e)))?;

        let certs_dir = storage_dir.join("certs");
        tokio::fs::create_dir_all(&certs_dir)
            .await
            .map_err(|e| DeployError::Storage(format!("failed to create certs dir: {}", e)))?;

        let mut storage = Self {
            storage_dir,
            sessions: HashMap::new(),
            providers: HashMap::new(),
            certificates: HashMap::new(),
        };

        // Load existing data into memory
        storage.load_all().await?;

        Ok(storage)
    }

    /// Load all persisted data into memory caches.
    async fn load_all(&mut self) -> Result<(), DeployError> {
        // Load sessions
        self.load_sessions_from_disk().await?;

        // Load provider cache
        self.load_providers_from_disk().await?;

        // Load certificate cache
        self.load_certificates_from_disk().await?;

        Ok(())
    }

    /// Load all session files from disk into memory.
    async fn load_sessions_from_disk(&mut self) -> Result<(), DeployError> {
        let sessions_dir = self.storage_dir.join("sessions");

        let mut entries = tokio::fs::read_dir(&sessions_dir)
            .await
            .map_err(|e| DeployError::Storage(format!("failed to read sessions dir: {}", e)))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| DeployError::Storage(format!("failed to read session entry: {}", e)))?
        {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(content) = tokio::fs::read_to_string(&path).await {
                    if let Ok(state) = serde_json::from_str::<DeploymentState>(&content) {
                        self.sessions.insert(state.session_id.clone(), state);
                    }
                }
            }
        }

        Ok(())
    }

    /// Load provider cache from disk.
    async fn load_providers_from_disk(&mut self) -> Result<(), DeployError> {
        let providers_file = self.storage_dir.join("providers.json");

        if tokio::fs::metadata(&providers_file).await.is_ok() {
            let content = tokio::fs::read_to_string(&providers_file)
                .await
                .map_err(|e| DeployError::Storage(format!("failed to read providers: {}", e)))?;

            self.providers = serde_json::from_str(&content)
                .map_err(|e| DeployError::Storage(format!("failed to parse providers: {}", e)))?;
        }

        Ok(())
    }

    /// Load certificate cache from disk.
    async fn load_certificates_from_disk(&mut self) -> Result<(), DeployError> {
        let certs_file = self.storage_dir.join("certificates.json");

        if tokio::fs::metadata(&certs_file).await.is_ok() {
            let content = tokio::fs::read_to_string(&certs_file)
                .await
                .map_err(|e| DeployError::Storage(format!("failed to read certificates: {}", e)))?;

            self.certificates = serde_json::from_str(&content).map_err(|e| {
                DeployError::Storage(format!("failed to parse certificates: {}", e))
            })?;
        }

        Ok(())
    }

    /// Flush provider cache to disk.
    async fn flush_providers(&self) -> Result<(), DeployError> {
        let providers_file = self.storage_dir.join("providers.json");
        let content = serde_json::to_string_pretty(&self.providers)
            .map_err(|e| DeployError::Storage(format!("failed to serialize providers: {}", e)))?;

        tokio::fs::write(&providers_file, content)
            .await
            .map_err(|e| DeployError::Storage(format!("failed to write providers: {}", e)))?;

        Ok(())
    }

    /// Flush certificate cache to disk.
    async fn flush_certificates(&self) -> Result<(), DeployError> {
        let certs_file = self.storage_dir.join("certificates.json");
        let content = serde_json::to_string_pretty(&self.certificates).map_err(|e| {
            DeployError::Storage(format!("failed to serialize certificates: {}", e))
        })?;

        tokio::fs::write(&certs_file, content)
            .await
            .map_err(|e| DeployError::Storage(format!("failed to write certificates: {}", e)))?;

        Ok(())
    }

    /// Get the file path for a session.
    fn session_path(&self, session_id: &str) -> PathBuf {
        self.storage_dir
            .join("sessions")
            .join(format!("{}.json", session_id))
    }

    /// Get the file path for a certificate key.
    fn cert_key_path(&self, owner: &str) -> PathBuf {
        self.storage_dir
            .join("certs")
            .join(format!("{}.key", owner))
    }
}

#[async_trait]
impl SessionStorage for FileBackedStorage {
    async fn save_session(&mut self, session: &DeploymentState) -> Result<(), DeployError> {
        // Save to memory cache
        self.sessions
            .insert(session.session_id.clone(), session.clone());

        // Persist to disk
        let path = self.session_path(&session.session_id);
        let content = serde_json::to_string_pretty(session)
            .map_err(|e| DeployError::Storage(format!("failed to serialize session: {}", e)))?;

        tokio::fs::write(&path, content)
            .await
            .map_err(|e| DeployError::Storage(format!("failed to write session: {}", e)))?;

        Ok(())
    }

    async fn load_session(&self, session_id: &str) -> Result<Option<DeploymentState>, DeployError> {
        // Try memory cache first
        if let Some(session) = self.sessions.get(session_id) {
            return Ok(Some(session.clone()));
        }

        // Fallback to disk
        let path = self.session_path(session_id);
        if tokio::fs::metadata(&path).await.is_err() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| DeployError::Storage(format!("failed to read session: {}", e)))?;

        let session = serde_json::from_str(&content)
            .map_err(|e| DeployError::Storage(format!("failed to parse session: {}", e)))?;

        Ok(Some(session))
    }

    async fn list_sessions(&self) -> Result<Vec<String>, DeployError> {
        // Return session IDs from memory cache
        Ok(self.sessions.keys().cloned().collect())
    }

    async fn delete_session(&mut self, session_id: &str) -> Result<(), DeployError> {
        // Remove from memory
        self.sessions.remove(session_id);

        // Remove from disk
        let path = self.session_path(session_id);
        if tokio::fs::metadata(&path).await.is_ok() {
            tokio::fs::remove_file(&path)
                .await
                .map_err(|e| DeployError::Storage(format!("failed to delete session: {}", e)))?;
        }

        Ok(())
    }

    async fn save_cert_key(&mut self, owner: &str, key_pem: &[u8]) -> Result<(), DeployError> {
        let path = self.cert_key_path(owner);
        tokio::fs::write(&path, key_pem)
            .await
            .map_err(|e| DeployError::Storage(format!("failed to write cert key: {}", e)))?;

        Ok(())
    }

    async fn load_cert_key(&self, owner: &str) -> Result<Option<Vec<u8>>, DeployError> {
        let path = self.cert_key_path(owner);
        if tokio::fs::metadata(&path).await.is_err() {
            return Ok(None);
        }

        let key = tokio::fs::read(&path)
            .await
            .map_err(|e| DeployError::Storage(format!("failed to read cert key: {}", e)))?;

        Ok(Some(key))
    }

    async fn delete_cert_key(&mut self, owner: &str) -> Result<(), DeployError> {
        let path = self.cert_key_path(owner);
        if tokio::fs::metadata(&path).await.is_ok() {
            tokio::fs::remove_file(&path)
                .await
                .map_err(|e| DeployError::Storage(format!("failed to delete cert key: {}", e)))?;
        }

        Ok(())
    }

    async fn cache_provider(&mut self, info: &ProviderInfo) -> Result<(), DeployError> {
        self.providers.insert(info.address.clone(), info.clone());
        self.flush_providers().await?;
        Ok(())
    }

    async fn load_cached_provider(
        &self,
        provider: &str,
    ) -> Result<Option<ProviderInfo>, DeployError> {
        Ok(self.providers.get(provider).cloned())
    }

    async fn cache_certificate(&mut self, info: &CertificateInfo) -> Result<(), DeployError> {
        self.certificates.insert(info.owner.clone(), info.clone());
        self.flush_certificates().await?;
        Ok(())
    }

    async fn load_cached_certificate(
        &self,
        owner: &str,
    ) -> Result<Option<CertificateInfo>, DeployError> {
        Ok(self.certificates.get(owner).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Step;

    #[tokio::test]
    async fn test_file_backed_storage_session_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("akash-test-{}", rand::random::<u32>()));
        let mut storage = FileBackedStorage::new(temp_dir.clone()).await.unwrap();

        // Create a session
        let session = DeploymentState::new("test-1", "akash1test");

        // Save it
        storage.save_session(&session).await.unwrap();

        // Load it back
        let loaded = storage.load_session("test-1").await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().session_id, "test-1");

        // List sessions
        let sessions = storage.list_sessions().await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains(&"test-1".to_string()));

        // Delete it
        storage.delete_session("test-1").await.unwrap();
        let loaded = storage.load_session("test-1").await.unwrap();
        assert!(loaded.is_none());

        // Cleanup
        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }

    #[tokio::test]
    async fn test_file_backed_storage_cert_key() {
        let temp_dir = std::env::temp_dir().join(format!("akash-test-{}", rand::random::<u32>()));
        let mut storage = FileBackedStorage::new(temp_dir.clone()).await.unwrap();

        let key = b"test private key";

        // Save key
        storage.save_cert_key("akash1test", key).await.unwrap();

        // Load key
        let loaded = storage.load_cert_key("akash1test").await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap(), key);

        // Delete key
        storage.delete_cert_key("akash1test").await.unwrap();
        let loaded = storage.load_cert_key("akash1test").await.unwrap();
        assert!(loaded.is_none());

        // Cleanup
        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }

    #[tokio::test]
    async fn test_provider_cache_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("akash-test-{}", rand::random::<u32>()));
        let mut storage = FileBackedStorage::new(temp_dir.clone()).await.unwrap();

        let provider = ProviderInfo {
            address: "akash1provider".to_string(),
            host_uri: "https://provider.example.com".to_string(),
            email: "test@example.com".to_string(),
            website: "https://example.com".to_string(),
            attributes: vec![("region".to_string(), "us-west".to_string())],
            cached_at: 1000,
        };

        // Cache provider
        storage.cache_provider(&provider).await.unwrap();

        // Load from memory
        let loaded = storage
            .load_cached_provider("akash1provider")
            .await
            .unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.address, "akash1provider");
        assert_eq!(loaded.host_uri, "https://provider.example.com");

        // Load non-existent
        let missing = storage.load_cached_provider("akash1missing").await.unwrap();
        assert!(missing.is_none());

        // Verify persisted to disk — create new storage from same dir
        let storage2 = FileBackedStorage::new(temp_dir.clone()).await.unwrap();
        let reloaded = storage2
            .load_cached_provider("akash1provider")
            .await
            .unwrap();
        assert!(reloaded.is_some());
        assert_eq!(reloaded.unwrap().host_uri, "https://provider.example.com");

        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }

    #[tokio::test]
    async fn test_certificate_cache_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("akash-test-{}", rand::random::<u32>()));
        let mut storage = FileBackedStorage::new(temp_dir.clone()).await.unwrap();

        let cert_info = CertificateInfo {
            owner: "akash1owner".to_string(),
            cert_pem: b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_vec(),
            serial: "abc123".to_string(),
        };

        // Cache certificate
        storage.cache_certificate(&cert_info).await.unwrap();

        // Load from memory
        let loaded = storage
            .load_cached_certificate("akash1owner")
            .await
            .unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().serial, "abc123");

        // Load non-existent
        let missing = storage
            .load_cached_certificate("akash1missing")
            .await
            .unwrap();
        assert!(missing.is_none());

        // Verify persisted — create new storage from same dir
        let storage2 = FileBackedStorage::new(temp_dir.clone()).await.unwrap();
        let reloaded = storage2
            .load_cached_certificate("akash1owner")
            .await
            .unwrap();
        assert!(reloaded.is_some());
        assert_eq!(reloaded.unwrap().serial, "abc123");

        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }

    #[tokio::test]
    async fn test_sessions_persist_across_instances() {
        let temp_dir = std::env::temp_dir().join(format!("akash-test-{}", rand::random::<u32>()));

        // Save sessions in first instance
        {
            let mut storage = FileBackedStorage::new(temp_dir.clone()).await.unwrap();
            let s1 = DeploymentState::new("persist-1", "akash1a");
            let s2 = DeploymentState::new("persist-2", "akash1b");
            storage.save_session(&s1).await.unwrap();
            storage.save_session(&s2).await.unwrap();
        }

        // New instance should load them from disk
        let storage2 = FileBackedStorage::new(temp_dir.clone()).await.unwrap();
        let sessions = storage2.list_sessions().await.unwrap();
        assert_eq!(sessions.len(), 2);

        let loaded = storage2.load_session("persist-1").await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().owner, "akash1a");

        let loaded = storage2.load_session("persist-2").await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().owner, "akash1b");

        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }

    #[tokio::test]
    async fn test_load_session_from_disk_fallback() {
        let temp_dir = std::env::temp_dir().join(format!("akash-test-{}", rand::random::<u32>()));

        // Write a session file directly to disk (bypassing memory cache)
        let sessions_dir = temp_dir.join("sessions");
        tokio::fs::create_dir_all(&sessions_dir).await.unwrap();
        let certs_dir = temp_dir.join("certs");
        tokio::fs::create_dir_all(&certs_dir).await.unwrap();

        let state = DeploymentState::new("disk-only", "akash1disk");
        let json = serde_json::to_string_pretty(&state).unwrap();
        tokio::fs::write(sessions_dir.join("disk-only.json"), &json)
            .await
            .unwrap();

        // Create storage (will load into memory via load_sessions_from_disk)
        let storage = FileBackedStorage::new(temp_dir.clone()).await.unwrap();
        let loaded = storage.load_session("disk-only").await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().owner, "akash1disk");

        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }

    #[tokio::test]
    async fn test_delete_session_idempotent() {
        let temp_dir = std::env::temp_dir().join(format!("akash-test-{}", rand::random::<u32>()));
        let mut storage = FileBackedStorage::new(temp_dir.clone()).await.unwrap();

        // Delete non-existent session should succeed
        storage.delete_session("nonexistent").await.unwrap();

        // Delete cert key that doesn't exist
        storage.delete_cert_key("akash1nobody").await.unwrap();

        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }

    #[tokio::test]
    async fn test_load_session_disk_fallback_bypassing_memory() {
        let temp_dir = std::env::temp_dir().join(format!("akash-test-{}", rand::random::<u32>()));
        let storage = FileBackedStorage::new(temp_dir.clone()).await.unwrap();

        // Write a session file AFTER storage creation so it's not in memory
        let state = DeploymentState::new("late-add", "akash1late");
        let json = serde_json::to_string_pretty(&state).unwrap();
        tokio::fs::write(temp_dir.join("sessions").join("late-add.json"), &json)
            .await
            .unwrap();

        // load_session should miss memory and fall back to disk read+parse
        let loaded = storage.load_session("late-add").await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().owner, "akash1late");

        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }

    #[tokio::test]
    async fn test_load_sessions_skips_invalid_json() {
        let temp_dir = std::env::temp_dir().join(format!("akash-test-{}", rand::random::<u32>()));

        // Pre-populate sessions dir with bad files before creating storage
        let sessions_dir = temp_dir.join("sessions");
        tokio::fs::create_dir_all(&sessions_dir).await.unwrap();
        tokio::fs::create_dir_all(temp_dir.join("certs"))
            .await
            .unwrap();

        // Valid session
        let state = DeploymentState::new("good", "akash1good");
        let json = serde_json::to_string_pretty(&state).unwrap();
        tokio::fs::write(sessions_dir.join("good.json"), &json)
            .await
            .unwrap();

        // Invalid JSON in a .json file (covers lines 140 failure → 142-143)
        tokio::fs::write(sessions_dir.join("bad.json"), "not valid json {{{")
            .await
            .unwrap();

        // Non-.json file (covers line 138 else → 144)
        tokio::fs::write(sessions_dir.join("readme.txt"), "ignore me")
            .await
            .unwrap();

        // Storage should load only the valid session, silently skipping bad ones
        let storage = FileBackedStorage::new(temp_dir.clone()).await.unwrap();
        let sessions = storage.list_sessions().await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains(&"good".to_string()));

        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }

    #[tokio::test]
    async fn test_invalid_certificates_json_fails() {
        let temp_dir = std::env::temp_dir().join(format!("akash-test-{}", rand::random::<u32>()));

        // Set up dir structure manually
        tokio::fs::create_dir_all(temp_dir.join("sessions"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(temp_dir.join("certs"))
            .await
            .unwrap();

        // Write invalid certificates.json (covers lines 175-177)
        tokio::fs::write(temp_dir.join("certificates.json"), "broken!")
            .await
            .unwrap();

        match FileBackedStorage::new(temp_dir.clone()).await {
            Ok(_) => panic!("expected error for invalid certificates.json"),
            Err(e) => assert!(
                e.to_string().contains("failed to parse certificates"),
                "unexpected error: {}",
                e
            ),
        }

        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }

    #[tokio::test]
    async fn test_invalid_providers_json_fails() {
        let temp_dir = std::env::temp_dir().join(format!("akash-test-{}", rand::random::<u32>()));

        tokio::fs::create_dir_all(temp_dir.join("sessions"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(temp_dir.join("certs"))
            .await
            .unwrap();

        // Write invalid providers.json (covers lines 159-160)
        tokio::fs::write(temp_dir.join("providers.json"), "{bad json")
            .await
            .unwrap();

        match FileBackedStorage::new(temp_dir.clone()).await {
            Ok(_) => panic!("expected error for invalid providers.json"),
            Err(e) => assert!(
                e.to_string().contains("failed to parse providers"),
                "unexpected error: {}",
                e
            ),
        }

        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }
}
