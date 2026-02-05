//! Error types for Akash deployment workflow.
//!
//! No `anyhow` leakage. Explicit, typed errors.

#[derive(Debug, thiserror::Error)]
pub enum DeployError {
    #[error("chain query failed: {0}")]
    Query(String),

    #[error("transaction failed: code={code}, log={log}")]
    Transaction { code: u32, log: String },

    #[error("provider communication failed: {0}")]
    Provider(String),

    #[error("invalid SDL: {0}")]
    Sdl(String),

    #[error("manifest build failed: {0}")]
    Manifest(String),

    #[error("invalid workflow state: {0}")]
    InvalidState(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("JWT error: {0}")]
    Jwt(String),

    #[error("timeout: {0}")]
    Timeout(String),
}

impl DeployError {
    /// Whether this error might be recoverable by retry.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            DeployError::Query(_)
                | DeployError::Provider(_)
                | DeployError::Timeout(_)
        )
    }
}
