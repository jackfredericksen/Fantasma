//! Error types for Fantasma

use thiserror::Error;

/// Main error type for Fantasma operations
#[derive(Error, Debug)]
pub enum FantasmaError {
    #[error("Invalid credential: {0}")]
    InvalidCredential(String),

    #[error("Credential expired")]
    CredentialExpired,

    #[error("Credential revoked")]
    CredentialRevoked,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    #[error("Invalid claim type: {0}")]
    InvalidClaimType(String),

    #[error("Insufficient claim level: required {required}, got {actual}")]
    InsufficientClaimLevel { required: String, actual: String },

    #[error("Merkle proof invalid")]
    InvalidMerkleProof,

    #[error("Nullifier already used")]
    NullifierReused,

    #[error("Issuer not trusted: {0}")]
    UntrustedIssuer(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

impl From<serde_json::Error> for FantasmaError {
    fn from(err: serde_json::Error) -> Self {
        FantasmaError::Serialization(err.to_string())
    }
}
