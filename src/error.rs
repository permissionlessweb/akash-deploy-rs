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

    #[error("template error: {0}")]
    Template(String),

    #[error("signer error: {0}")]
    Signer(String),
}

impl DeployError {
    /// Whether this error might be recoverable by retry.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            DeployError::Query(_) | DeployError::Provider(_) | DeployError::Timeout(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = DeployError::Query("connection failed".to_string());
        assert_eq!(err.to_string(), "chain query failed: connection failed");

        let err = DeployError::Transaction {
            code: 5,
            log: "insufficient funds".to_string(),
        };
        assert!(err.to_string().contains("code=5"));
        assert!(err.to_string().contains("insufficient funds"));

        let err = DeployError::Provider("404".to_string());
        assert_eq!(err.to_string(), "provider communication failed: 404");

        let err = DeployError::Sdl("invalid yaml".to_string());
        assert_eq!(err.to_string(), "invalid SDL: invalid yaml");

        let err = DeployError::Manifest("parsing failed".to_string());
        assert_eq!(err.to_string(), "manifest build failed: parsing failed");

        let err = DeployError::InvalidState("bad transition".to_string());
        assert_eq!(err.to_string(), "invalid workflow state: bad transition");

        let err = DeployError::Storage("disk full".to_string());
        assert_eq!(err.to_string(), "storage error: disk full");

        let err = DeployError::Certificate("expired".to_string());
        assert_eq!(err.to_string(), "certificate error: expired");

        let err = DeployError::Jwt("invalid signature".to_string());
        assert_eq!(err.to_string(), "JWT error: invalid signature");

        let err = DeployError::Timeout("30s".to_string());
        assert_eq!(err.to_string(), "timeout: 30s");

        let err = DeployError::Template("missing variable".to_string());
        assert_eq!(err.to_string(), "template error: missing variable");
    }

    #[test]
    fn test_error_is_recoverable() {
        assert!(DeployError::Query("test".to_string()).is_recoverable());
        assert!(DeployError::Provider("test".to_string()).is_recoverable());
        assert!(DeployError::Timeout("test".to_string()).is_recoverable());

        assert!(!DeployError::Sdl("test".to_string()).is_recoverable());
        assert!(!DeployError::Manifest("test".to_string()).is_recoverable());
        assert!(!DeployError::InvalidState("test".to_string()).is_recoverable());
        assert!(!DeployError::Certificate("test".to_string()).is_recoverable());
        assert!(!DeployError::Jwt("test".to_string()).is_recoverable());
        assert!(!DeployError::Template("test".to_string()).is_recoverable());
    }
}
