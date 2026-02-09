//! Akash Deploy Library
//!
//! Standalone, trait-based deployment workflow engine for Akash Network.
//!
//! # Design
//!
//! This library provides the deployment workflow logic without coupling to
//! any specific storage, signing, or transport implementation. You implement
//! the [`AkashBackend`] trait with your infrastructure, and the workflow
//! engine handles the state machine.
//!
//! # Usage
//!
//! ```ignore
//! use akash_deploy_rs::{
//!     AkashBackend, DeploymentState, DeploymentWorkflow, WorkflowConfig, StepResult,
//! };
//!
//! // Implement AkashBackend for your infrastructure
//! struct MyBackend { /* ... */ }
//! impl AkashBackend for MyBackend { /* ... */ }
//!
//! // Create workflow
//! let backend = MyBackend::new();
//! let signer = MySigner::new();
//! let config = WorkflowConfig::default();
//! let workflow = DeploymentWorkflow::new(&backend, &signer, config);
//!
//! // Create state
//! let mut state = DeploymentState::new("session-1", "akash1...")
//!     .with_sdl(sdl_content)
//!     .with_label("my-deploy");
//!
//! // Run to completion
//! match workflow.run_to_completion(&mut state).await? {
//!     StepResult::Complete => println!("Deployed!"),
//!     StepResult::NeedsInput(input) => { /* handle user input */ },
//!     StepResult::Failed(reason) => println!("Failed: {}", reason),
//!     _ => {}
//! }
//! ```

pub mod backend;
pub mod canonical;
pub mod certificate;
pub mod error;
pub mod jwt;
pub mod manifest;
pub mod sdl;
pub mod state;
#[cfg(feature = "sdl-templates")]
pub mod template;
pub mod types;
pub mod workflow;

// Re-export the main types at crate root for convenience
pub use backend::AkashBackend;
pub use canonical::to_canonical_json;
pub use certificate::{decrypt_key, encrypt_key, generate_certificate, GeneratedCertificate};
pub use error::DeployError;
pub use jwt::{CachedJwt, JwtBuilder, JwtClaims, JwtLeases};
pub use manifest::{
    ManifestBuilder, ManifestCredentials, ManifestCpu, ManifestGroup, ManifestGpu,
    ManifestHttpOptions, ManifestMemory, ManifestResourceValue, ManifestResources,
    ManifestService, ManifestServiceExpose, ManifestServiceParams, ManifestStorage,
    ManifestStorageParams,
};
pub use state::{DeploymentState, Step};
#[cfg(feature = "sdl-templates")]
pub use template::{
    apply_template, extract_variables, validate_template, SdlTemplate, TemplateDefaults,
    TemplateVariables,
};
pub use types::*;
pub use workflow::{DeploymentWorkflow, InputRequired, StepResult, WorkflowConfig};
