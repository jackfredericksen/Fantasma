//! Fantasma Proof Store
//!
//! Storage service for STARK proofs (which are too large for JWTs).

use chrono::{DateTime, Utc};
use fantasma_core::proof::ProofId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProofStoreError {
    #[error("Proof not found: {0}")]
    NotFound(String),

    #[error("Proof expired")]
    Expired,

    #[error("Storage error: {0}")]
    Storage(String),
}

/// A stored proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProof {
    /// Proof ID
    pub id: ProofId,

    /// Proof bytes
    pub proof_bytes: Vec<u8>,

    /// Hash of proof bytes
    pub hash: [u8; 32],

    /// Circuit type
    pub circuit_type: String,

    /// When the proof was stored
    pub stored_at: DateTime<Utc>,

    /// When the proof expires
    pub expires_at: DateTime<Utc>,
}

impl StoredProof {
    /// Create a new stored proof
    pub fn new(proof_bytes: Vec<u8>, circuit_type: String, ttl_seconds: i64) -> Self {
        use sha3::{Digest, Sha3_256};

        let mut hasher = Sha3_256::new();
        hasher.update(&proof_bytes);
        let hash: [u8; 32] = hasher.finalize().into();

        let now = Utc::now();

        Self {
            id: ProofId::generate(),
            proof_bytes,
            hash,
            circuit_type,
            stored_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_seconds),
        }
    }

    /// Check if the proof has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// Trait for proof storage backends
#[async_trait::async_trait]
pub trait ProofStore: Send + Sync {
    /// Store a proof
    async fn store(&self, proof: StoredProof) -> Result<ProofId, ProofStoreError>;

    /// Retrieve a proof by ID
    async fn get(&self, id: &ProofId) -> Result<StoredProof, ProofStoreError>;

    /// Delete a proof
    async fn delete(&self, id: &ProofId) -> Result<(), ProofStoreError>;

    /// Clean up expired proofs
    async fn cleanup_expired(&self) -> Result<usize, ProofStoreError>;
}

/// In-memory proof store (for development/testing)
pub struct InMemoryProofStore {
    proofs: RwLock<HashMap<String, StoredProof>>,
    default_ttl: i64,
}

impl InMemoryProofStore {
    pub fn new(default_ttl_seconds: i64) -> Self {
        Self {
            proofs: RwLock::new(HashMap::new()),
            default_ttl: default_ttl_seconds,
        }
    }
}

impl Default for InMemoryProofStore {
    fn default() -> Self {
        Self::new(3600) // 1 hour default
    }
}

#[async_trait::async_trait]
impl ProofStore for InMemoryProofStore {
    async fn store(&self, proof: StoredProof) -> Result<ProofId, ProofStoreError> {
        let id = proof.id.clone();
        let mut proofs = self
            .proofs
            .write()
            .map_err(|e| ProofStoreError::Storage(e.to_string()))?;
        proofs.insert(id.0.clone(), proof);
        Ok(id)
    }

    async fn get(&self, id: &ProofId) -> Result<StoredProof, ProofStoreError> {
        let proofs = self
            .proofs
            .read()
            .map_err(|e| ProofStoreError::Storage(e.to_string()))?;

        let proof = proofs
            .get(&id.0)
            .ok_or_else(|| ProofStoreError::NotFound(id.0.clone()))?;

        if proof.is_expired() {
            return Err(ProofStoreError::Expired);
        }

        Ok(proof.clone())
    }

    async fn delete(&self, id: &ProofId) -> Result<(), ProofStoreError> {
        let mut proofs = self
            .proofs
            .write()
            .map_err(|e| ProofStoreError::Storage(e.to_string()))?;

        proofs.remove(&id.0);
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<usize, ProofStoreError> {
        let mut proofs = self
            .proofs
            .write()
            .map_err(|e| ProofStoreError::Storage(e.to_string()))?;

        let before = proofs.len();
        proofs.retain(|_, p| !p.is_expired());
        let after = proofs.len();

        Ok(before - after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_and_get() {
        let store = InMemoryProofStore::new(3600);

        let proof = StoredProof::new(vec![1, 2, 3, 4], "test_circuit".to_string(), 3600);

        let id = store.store(proof.clone()).await.unwrap();
        let retrieved = store.get(&id).await.unwrap();

        assert_eq!(retrieved.proof_bytes, vec![1, 2, 3, 4]);
    }
}
