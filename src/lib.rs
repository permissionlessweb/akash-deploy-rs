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

pub mod auth;
pub mod error;
pub mod gen;
pub mod manifest;
pub mod sdl;
pub mod state;
pub mod store;
pub mod traits;
pub mod types;
pub mod workflow;
pub mod logs;

#[cfg(feature = "default-client")]
pub mod authz;
#[cfg(feature = "default-client")]
pub mod client;
#[cfg(feature = "default-client")]
pub mod rest;

// Re-export the main types at crate root for convenience
pub use auth::{
    certificate::{decrypt_key, encrypt_key, generate_certificate, GeneratedCertificate},
    jwt::{CachedJwt, JwtBuilder, JwtClaims, JwtLeases},
    AuthMode,
};
pub use error::DeployError;
pub use manifest::{
    canonical::to_canonical_json,
    manifest::{
        ManifestBuilder, ManifestCpu, ManifestCredentials, ManifestGpu, ManifestGroup,
        ManifestHttpOptions, ManifestMemory, ManifestResourceValue, ManifestResources,
        ManifestService, ManifestServiceExpose, ManifestServiceParams, ManifestStorage,
        ManifestStorageParams,
    },
};
#[cfg(feature = "sdl-templates")]
pub use sdl::template::{
    apply_template, apply_template_partial, extract_variables, substitute_partial, validate_template, SdlTemplate, TemplateDefaults,
    TemplateVariables,
};
pub use state::{DeploymentState, Step};
#[cfg(feature = "file-storage")]
pub use store::FileBackedStorage;
#[cfg(feature = "file-storage")]
pub use store::FileDeploymentStore;
pub use store::{DeploymentRecord, DeploymentStore, SessionStorage, StdoutStorage};
pub use traits::AkashBackend;
pub use types::*;
pub use workflow::{DeploymentWorkflow, InputRequired, StepResult, WorkflowConfig};
pub use logs::{LogLine, LogStreamConfig};
#[cfg(feature = "log-streaming")]
pub use logs::ws::WsLogStream;

#[cfg(all(feature = "default-client", feature = "file-storage"))]
pub use client::{export_sessions, import_sessions};
#[cfg(feature = "default-client")]
pub use client::{AkashClient, KeySigner};
#[cfg(feature = "default-client")]
pub use client::{
    broadcast_multi_signer, broadcast_with_fee_granter, build_bank_send_msg,
    build_close_deployment_msg, build_create_lease_msg, build_mint_act_msg,
    MultiSignerTxResult, SignerEntry,
};
#[cfg(feature = "default-client")]
pub use authz::{
    authz_msg_type_urls, build_authz_grant_msgs, build_authz_revoke_msgs,
    build_feegrant_msg, build_feegrant_revoke_msg, wrap_in_msg_exec, AuthzConfig,
};

#[cfg(feature = "python")]
mod py;
