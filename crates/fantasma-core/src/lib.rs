//! Fantasma Core
//!
//! Core domain types for the Fantasma ZK identity layer.
//! This crate defines the fundamental data structures used across
//! the entire Fantasma ecosystem.

pub mod claim;
pub mod credential;
pub mod error;
pub mod issuer;
pub mod proof;

pub use claim::{ClaimRequest, ClaimType, KycLevel};
pub use credential::{AttributeValue, Credential, CredentialId, CredentialType, SchemaId};
pub use error::FantasmaError;
pub use issuer::{IssuerId, IssuerInfo, TrustAnchor};
pub use proof::{GeneratedProof, ProofId, ProofRef, ProofRequest, ProofResponse};
