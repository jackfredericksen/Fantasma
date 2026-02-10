//! ZK claims for ID tokens

use fantasma_core::claim::KycLevel;
use fantasma_core::proof::ProofRef;
use serde::{Deserialize, Serialize};

/// ZK age claim in an ID token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkAgeClaim {
    /// The age threshold that was verified
    pub threshold: u8,

    /// Whether the claim was verified
    pub verified: bool,

    /// Reference to the proof
    pub proof_ref: Option<ProofRef>,

    /// Circuit version used
    pub circuit_version: String,
}

/// ZK credential claim in an ID token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkCredentialClaim {
    /// The credential type that was verified
    pub credential_type: String,

    /// Whether the claim was verified
    pub verified: bool,

    /// Reference to the proof
    pub proof_ref: Option<ProofRef>,

    /// Circuit version used
    pub circuit_version: String,
}

/// ZK KYC claim in an ID token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkKycClaim {
    /// The KYC level that was verified
    pub level: KycLevel,

    /// Whether the claim was verified
    pub verified: bool,

    /// Reference to the proof
    pub proof_ref: Option<ProofRef>,

    /// Circuit version used
    pub circuit_version: String,

    /// Maximum age of KYC that was allowed (in seconds)
    pub max_age_seconds: Option<u64>,
}

/// Collection of ZK claims in an ID token
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ZkClaims {
    /// Age verification claim
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zk_age_claim: Option<ZkAgeClaim>,

    /// Credential verification claim
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zk_credential_claim: Option<ZkCredentialClaim>,

    /// KYC verification claim
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zk_kyc_claim: Option<ZkKycClaim>,
}

impl ZkClaims {
    /// Create empty claims
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any claims are present
    pub fn is_empty(&self) -> bool {
        self.zk_age_claim.is_none()
            && self.zk_credential_claim.is_none()
            && self.zk_kyc_claim.is_none()
    }

    /// Add an age claim
    pub fn with_age_claim(mut self, threshold: u8, proof_ref: Option<ProofRef>) -> Self {
        self.zk_age_claim = Some(ZkAgeClaim {
            threshold,
            verified: true,
            proof_ref,
            circuit_version: "age_verification_v1".to_string(),
        });
        self
    }

    /// Add a credential claim
    pub fn with_credential_claim(
        mut self,
        credential_type: String,
        proof_ref: Option<ProofRef>,
    ) -> Self {
        self.zk_credential_claim = Some(ZkCredentialClaim {
            credential_type,
            verified: true,
            proof_ref,
            circuit_version: "credential_verification_v1".to_string(),
        });
        self
    }

    /// Add a KYC claim
    pub fn with_kyc_claim(
        mut self,
        level: KycLevel,
        proof_ref: Option<ProofRef>,
        max_age: Option<u64>,
    ) -> Self {
        self.zk_kyc_claim = Some(ZkKycClaim {
            level,
            verified: true,
            proof_ref,
            circuit_version: "kyc_verification_v1".to_string(),
            max_age_seconds: max_age,
        });
        self
    }
}
