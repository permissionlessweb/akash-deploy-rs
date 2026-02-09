//! Generated Akash Network protobuf types
//!
//! This module contains Rust types generated from Akash Network's protobuf definitions.
//! These types are used for chain queries, transaction broadcasting, and provider communication.

// Disable doctests for this module - generated proto files contain non-Rust code examples
#![cfg_attr(test, allow(rustdoc::invalid_rust_codeblocks))]

// We include the generated files using their exact filenames
// and let the compiler resolve the module paths as they were generated

// Include all generated modules
include!("cosmos_proto.rs");

// Create proper module hierarchy to match the generated code's expectations
pub mod cosmos {
    pub mod base {
        pub mod v1beta1 {
            include!("cosmos.base.v1beta1.rs");
        }
        pub mod query {
            pub mod v1beta1 {
                include!("cosmos.base.query.v1beta1.rs");
            }
        }
    }
}

pub mod google {
    pub mod api {
        include!("google.api.rs");
    }
}

pub mod k8s {
    pub mod io {
        pub mod apimachinery {
            pub mod pkg {
                pub mod api {
                    pub mod resource {
                        include!("k8s.io.apimachinery.pkg.api.resource.rs");
                    }
                }
            }
        }
    }
}

pub mod akash {
    pub mod base {
        pub mod v1beta3 {
            include!("akash.base.v1beta3.rs");
        }
        pub mod attributes {
            pub mod v1 {
                include!("akash.base.attributes.v1.rs");
            }
        }
        pub mod deposit {
            pub mod v1 {
                include!("akash.base.deposit.v1.rs");
            }
        }
        pub mod resources {
            pub mod v1beta4 {
                include!("akash.base.resources.v1beta4.rs");
            }
        }
    }

    pub mod cert {
        pub mod v1 {
            include!("akash.cert.v1.rs");
        }
    }

    pub mod deployment {
        pub mod v1 {
            include!("akash.deployment.v1.rs");
        }
        pub mod v1beta3 {
            include!("akash.deployment.v1beta3.rs");
        }
        pub mod v1beta4 {
            include!("akash.deployment.v1beta4.rs");
        }
        pub mod v1beta5 {
            include!("akash.deployment.v1beta5.rs");
        }
    }

    pub mod market {
        pub mod v1 {
            include!("akash.market.v1.rs");
        }
        pub mod v1beta4 {
            include!("akash.market.v1beta4.rs");
        }
        pub mod v1beta5 {
            include!("akash.market.v1beta5.rs");
        }
        pub mod v2beta1 {
            include!("akash.market.v2beta1.rs");
        }
    }

    pub mod escrow {
        pub mod id {
            pub mod v1 {
                include!("akash.escrow.id.v1.rs");
            }
        }
        pub mod types {
            pub mod v1 {
                include!("akash.escrow.types.v1.rs");
            }
        }
        pub mod v1 {
            include!("akash.escrow.v1.rs");
        }
    }

    pub mod provider {
        pub mod v1 {
            include!("akash.provider.v1.rs");
        }
        pub mod v1beta3 {
            include!("akash.provider.v1beta3.rs");
        }
        pub mod v1beta4 {
            include!("akash.provider.v1beta4.rs");
        }
    }

    pub mod manifest {
        pub mod v2beta3 {
            include!("akash.manifest.v2beta3.rs");
        }
    }

    pub mod inventory {
        pub mod v1 {
            include!("akash.inventory.v1.rs");
        }
    }

    pub mod discovery {
        pub mod v1 {
            include!("akash.discovery.v1.rs");
        }
    }
}

// Re-export commonly used types for convenience
pub mod prelude {
    // Certificate types
    pub use super::akash::cert::v1::*;

    // Deployment types (v1beta5 is the latest)
    pub use super::akash::deployment::v1beta5::*;

    // Market types (v2beta1 is the latest)
    pub use super::akash::market::v2beta1::*;

    // Escrow types
    pub use super::akash::escrow::v1::*;

    // Provider types (v1beta4 is the latest)
    pub use super::akash::provider::v1beta4::*;

    // Manifest types
    pub use super::akash::manifest::v2beta3::*;

    // Base types
    pub use super::akash::base::attributes::v1::*;
    pub use super::akash::base::deposit::v1::*;
    pub use super::akash::base::resources::v1beta4::*;

    // Cosmos base types
    pub use super::cosmos::base::v1beta1::*;
}