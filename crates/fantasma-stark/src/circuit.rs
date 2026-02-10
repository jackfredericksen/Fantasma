//! Circuit definitions and metadata

use serde::{Deserialize, Serialize};

/// Type of circuit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CircuitType {
    AgeVerification,
    CredentialVerification,
    KycVerification,
}

impl CircuitType {
    /// Get the circuit identifier string
    pub fn id(&self) -> &'static str {
        match self {
            CircuitType::AgeVerification => "age_verification_v1",
            CircuitType::CredentialVerification => "credential_verification_v1",
            CircuitType::KycVerification => "kyc_verification_v1",
        }
    }

    /// Parse from string
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "age_verification_v1" => Some(CircuitType::AgeVerification),
            "credential_verification_v1" => Some(CircuitType::CredentialVerification),
            "kyc_verification_v1" => Some(CircuitType::KycVerification),
            _ => None,
        }
    }
}

/// Circuit metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Circuit {
    /// Circuit type
    pub circuit_type: CircuitType,

    /// Version string
    pub version: String,

    /// Description
    pub description: String,

    /// Hash of the compiled circuit bytecode
    pub bytecode_hash: [u8; 32],

    /// Expected public input count
    pub public_input_count: usize,
}

impl Circuit {
    /// Get the age verification circuit metadata
    pub fn age_verification() -> Self {
        Self {
            circuit_type: CircuitType::AgeVerification,
            version: "1.0.0".to_string(),
            description: "Proves age >= threshold without revealing birthdate".to_string(),
            bytecode_hash: [0u8; 32], // Placeholder - set after compilation
            public_input_count: 4,     // threshold, date, commitment, issuer
        }
    }

    /// Get the credential verification circuit metadata
    pub fn credential_verification() -> Self {
        Self {
            circuit_type: CircuitType::CredentialVerification,
            version: "1.0.0".to_string(),
            description: "Proves credential possession without revealing details".to_string(),
            bytecode_hash: [0u8; 32],
            public_input_count: 6,
        }
    }

    /// Get the KYC verification circuit metadata
    pub fn kyc_verification() -> Self {
        Self {
            circuit_type: CircuitType::KycVerification,
            version: "1.0.0".to_string(),
            description: "Proves KYC status without revealing personal data".to_string(),
            bytecode_hash: [0u8; 32],
            public_input_count: 5,
        }
    }
}
