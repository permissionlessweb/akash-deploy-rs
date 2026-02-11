//! Persistence layer for deployments and sessions.
//!
//! This module contains:
//! - [`SessionStorage`] trait + [`FileBackedStorage`] — session, cert key, and cache persistence
//! - [`DeploymentStore`] trait + [`FileDeploymentStore`] — deployment record persistence by dseq
//! - [`DeploymentRecord`] — on-disk representation with encrypted sensitive fields

mod record;
mod session;
mod store;

#[cfg(feature = "file-storage")]
pub mod file_backed;
#[cfg(feature = "file-storage")]
pub mod file_backed_session;

pub use record::DeploymentRecord;
pub use session::SessionStorage;
pub use store::DeploymentStore;

#[cfg(feature = "file-storage")]
pub use file_backed::FileDeploymentStore;
#[cfg(feature = "file-storage")]
pub use file_backed_session::FileBackedStorage;

#[cfg(test)]
mod tests;
