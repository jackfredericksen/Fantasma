//! Fantasma OIDC Provider
//!
//! OIDC-compliant identity provider with zero-knowledge claims.

pub mod claims;
pub mod config;
pub mod discovery;
pub mod scopes;
pub mod token;

pub use claims::ZkClaims;
pub use config::OidcConfig;
pub use discovery::DiscoveryDocument;
pub use scopes::ZkScope;
pub use token::{IdToken, IdTokenClaims};
