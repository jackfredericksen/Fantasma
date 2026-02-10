//! Proof types for Fantasma
//!
//! These types represent ZK proofs and proof requests/responses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::claim::{ClaimRequest, ClaimType};

/// Unique identifier for a stored proof
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProofId(pub String);

impl ProofId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn generate() -> Self {
        Self(format!("prf_{}", uuid::Uuid::new_v4().simple()))
    }
}

impl std::fmt::Display for ProofId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Reference to a proof stored externally (for large STARK proofs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRef {
    /// Unique proof identifier
    pub id: ProofId,

    /// Hash of the proof bytes for integrity
    #[serde(with = "hex_bytes")]
    pub hash: [u8; 32],

    /// URL where the full proof can be fetched
    pub url: Option<String>,

    /// Size of the proof in bytes
    pub size_bytes: u64,
}

/// A request for ZK proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequest {
    /// Unique request identifier
    pub request_id: String,

    /// Claims being requested
    pub requested_claims: Vec<ClaimRequest>,

    /// Verifier's nonce for freshness
    pub nonce: String,

    /// Domain of the requesting service
    pub verifier_domain: String,

    /// When this request expires
    pub expires_at: DateTime<Utc>,
}

impl ProofRequest {
    /// Create a new proof request
    pub fn new(
        verifier_domain: impl Into<String>,
        claims: Vec<ClaimRequest>,
        validity_seconds: i64,
    ) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            requested_claims: claims,
            nonce: uuid::Uuid::new_v4().to_string(),
            verifier_domain: verifier_domain.into(),
            expires_at: Utc::now() + chrono::Duration::seconds(validity_seconds),
        }
    }

    /// Check if this request has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// A generated ZK proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedProof {
    /// Which claim this proves
    pub claim_type: ClaimType,

    /// The ZK proof bytes (STARK proof, typically 50-200KB)
    pub proof_bytes: Vec<u8>,

    /// Public inputs used in verification
    pub public_inputs: Vec<String>,

    /// Circuit identifier
    pub circuit_id: String,

    /// Nullifier to prevent replay attacks
    #[serde(with = "hex_bytes")]
    pub nullifier: [u8; 32],

    /// When this proof was generated
    pub generated_at: DateTime<Utc>,
}

impl GeneratedProof {
    /// Calculate the hash of this proof for integrity
    pub fn hash(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&self.proof_bytes);
        hasher.finalize().into()
    }

    /// Convert to a proof reference (for storage)
    pub fn to_ref(&self, url: Option<String>) -> ProofRef {
        ProofRef {
            id: ProofId::generate(),
            hash: self.hash(),
            url,
            size_bytes: self.proof_bytes.len() as u64,
        }
    }
}

/// Response containing generated ZK proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResponse {
    /// Request this responds to
    pub request_id: String,

    /// Generated proofs (or references to stored proofs)
    pub proofs: Vec<GeneratedProof>,

    /// Proof references (for large STARK proofs)
    pub proof_refs: Vec<ProofRef>,

    /// Pseudonymous subject identifier
    pub subject_id: String,

    /// When this response was generated
    pub generated_at: DateTime<Utc>,
}

/// Verification result for a proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the proof is valid
    pub valid: bool,

    /// The claim that was verified
    pub claim_type: ClaimType,

    /// Error message if invalid
    pub error: Option<String>,

    /// When verification was performed
    pub verified_at: DateTime<Utc>,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid byte length"))
    }
}
