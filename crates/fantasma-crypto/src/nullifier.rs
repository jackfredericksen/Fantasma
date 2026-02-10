//! Nullifier generation for replay prevention
//!
//! Nullifiers are used to prevent the same credential from being used twice
//! while maintaining privacy (nullifiers are unlinkable to credentials).

use crate::hash::{poseidon_hash, sha3_256};
use serde::{Deserialize, Serialize};

/// A nullifier that prevents replay attacks
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    /// Create a nullifier from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Generate a nullifier from credential and context
    ///
    /// The nullifier is derived from:
    /// - credential_commitment: Commitment to the credential
    /// - user_secret: User's secret key (ensures only user can generate)
    /// - verifier_domain: Domain of the verifying service (domain binding)
    /// - nonce: Request nonce (freshness)
    ///
    /// This ensures:
    /// - Different nullifiers per credential
    /// - Different nullifiers per verifier (prevents cross-site tracking)
    /// - Different nullifiers per request (prevents replay)
    pub fn generate(
        credential_commitment: &[u8; 32],
        user_secret: &[u8; 32],
        verifier_domain: &str,
        nonce: &[u8; 32],
    ) -> Self {
        // Hash the domain to fixed size
        let domain_hash = sha3_256(verifier_domain.as_bytes());

        // Compute nullifier: H(H(credential, secret), H(domain, nonce))
        let inner = poseidon_hash(&[*credential_commitment, *user_secret]);
        let outer = poseidon_hash(&[domain_hash, *nonce]);
        let nullifier = poseidon_hash(&[inner, outer]);

        Self(nullifier)
    }
}

impl std::fmt::Display for Nullifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Nullifier store for tracking used nullifiers
pub trait NullifierStore {
    /// Check if a nullifier has been used
    fn is_used(&self, nullifier: &Nullifier) -> bool;

    /// Mark a nullifier as used
    fn mark_used(&mut self, nullifier: Nullifier) -> Result<(), NullifierError>;
}

#[derive(Debug, thiserror::Error)]
pub enum NullifierError {
    #[error("Nullifier already used")]
    AlreadyUsed,

    #[error("Storage error: {0}")]
    Storage(String),
}

/// In-memory nullifier store (for testing/development)
pub struct InMemoryNullifierStore {
    used: std::collections::HashSet<Nullifier>,
}

impl InMemoryNullifierStore {
    pub fn new() -> Self {
        Self {
            used: std::collections::HashSet::new(),
        }
    }
}

impl Default for InMemoryNullifierStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NullifierStore for InMemoryNullifierStore {
    fn is_used(&self, nullifier: &Nullifier) -> bool {
        self.used.contains(nullifier)
    }

    fn mark_used(&mut self, nullifier: Nullifier) -> Result<(), NullifierError> {
        if self.used.contains(&nullifier) {
            return Err(NullifierError::AlreadyUsed);
        }
        self.used.insert(nullifier);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_generation() {
        let credential = [1u8; 32];
        let secret = [2u8; 32];
        let domain = "example.com";
        let nonce = [3u8; 32];

        let nullifier1 = Nullifier::generate(&credential, &secret, domain, &nonce);
        let nullifier2 = Nullifier::generate(&credential, &secret, domain, &nonce);

        // Same inputs should produce same nullifier
        assert_eq!(nullifier1, nullifier2);
    }

    #[test]
    fn test_nullifier_different_domains() {
        let credential = [1u8; 32];
        let secret = [2u8; 32];
        let nonce = [3u8; 32];

        let nullifier1 = Nullifier::generate(&credential, &secret, "example.com", &nonce);
        let nullifier2 = Nullifier::generate(&credential, &secret, "other.com", &nonce);

        // Different domains should produce different nullifiers
        assert_ne!(nullifier1, nullifier2);
    }

    #[test]
    fn test_nullifier_different_nonces() {
        let credential = [1u8; 32];
        let secret = [2u8; 32];
        let domain = "example.com";

        let nullifier1 = Nullifier::generate(&credential, &secret, domain, &[1u8; 32]);
        let nullifier2 = Nullifier::generate(&credential, &secret, domain, &[2u8; 32]);

        // Different nonces should produce different nullifiers
        assert_ne!(nullifier1, nullifier2);
    }

    #[test]
    fn test_nullifier_store() {
        let mut store = InMemoryNullifierStore::new();
        let nullifier = Nullifier::from_bytes([1u8; 32]);

        assert!(!store.is_used(&nullifier));

        store.mark_used(nullifier.clone()).unwrap();

        assert!(store.is_used(&nullifier));

        // Second mark should fail
        assert!(store.mark_used(nullifier).is_err());
    }
}
