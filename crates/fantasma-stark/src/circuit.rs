//! Circuit definitions and metadata

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

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

/// Loader for compiled Cairo circuit artifacts (Sierra JSON)
pub struct CircuitLoader {
    circuits: HashMap<CircuitType, Circuit>,
}

impl CircuitLoader {
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
        }
    }

    /// Load circuit metadata from a Sierra JSON artifact directory.
    /// Expects the compiled output from `scarb build`.
    pub fn load_from_dir(circuits_path: &Path) -> Result<Self, String> {
        let sierra_path = circuits_path.join("target/dev/fantasma_circuits.sierra.json");
        let mut loader = Self::new();

        if sierra_path.exists() {
            let contents = std::fs::read_to_string(&sierra_path)
                .map_err(|e| format!("Failed to read Sierra JSON: {}", e))?;

            let bytecode_hash = {
                use sha3::{Digest, Sha3_256};
                let mut hasher = Sha3_256::new();
                hasher.update(contents.as_bytes());
                let result: [u8; 32] = hasher.finalize().into();
                result
            };

            // Register all circuit types with the computed hash
            for circuit_type in &[
                CircuitType::AgeVerification,
                CircuitType::CredentialVerification,
                CircuitType::KycVerification,
            ] {
                let mut circuit = match circuit_type {
                    CircuitType::AgeVerification => Circuit::age_verification(),
                    CircuitType::CredentialVerification => Circuit::credential_verification(),
                    CircuitType::KycVerification => Circuit::kyc_verification(),
                };
                circuit.bytecode_hash = bytecode_hash;
                loader.circuits.insert(*circuit_type, circuit);
            }

            tracing::info!(
                "Loaded Sierra circuits from {}, hash: {}",
                sierra_path.display(),
                hex::encode(bytecode_hash)
            );
        } else {
            tracing::warn!(
                "Sierra JSON not found at {}, using placeholder hashes",
                sierra_path.display()
            );
            // Fall back to placeholder circuits
            loader.circuits.insert(CircuitType::AgeVerification, Circuit::age_verification());
            loader.circuits.insert(CircuitType::CredentialVerification, Circuit::credential_verification());
            loader.circuits.insert(CircuitType::KycVerification, Circuit::kyc_verification());
        }

        Ok(loader)
    }

    /// Load with placeholder hashes (for development/testing)
    pub fn with_defaults() -> Self {
        let mut loader = Self::new();
        loader.circuits.insert(CircuitType::AgeVerification, Circuit::age_verification());
        loader.circuits.insert(CircuitType::CredentialVerification, Circuit::credential_verification());
        loader.circuits.insert(CircuitType::KycVerification, Circuit::kyc_verification());
        loader
    }

    /// Get circuit metadata by type
    pub fn get(&self, circuit_type: CircuitType) -> Option<&Circuit> {
        self.circuits.get(&circuit_type)
    }

    /// Get all loaded circuits
    pub fn all(&self) -> &HashMap<CircuitType, Circuit> {
        &self.circuits
    }

    /// Get the bytecode hash for a circuit type
    pub fn bytecode_hash(&self, circuit_type: CircuitType) -> Option<[u8; 32]> {
        self.circuits.get(&circuit_type).map(|c| c.bytecode_hash)
    }
}

impl Default for CircuitLoader {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_loader_defaults() {
        let loader = CircuitLoader::with_defaults();
        assert!(loader.get(CircuitType::AgeVerification).is_some());
        assert!(loader.get(CircuitType::KycVerification).is_some());
        assert!(loader.get(CircuitType::CredentialVerification).is_some());
        assert_eq!(loader.all().len(), 3);
    }

    #[test]
    fn test_circuit_type_roundtrip() {
        for ct in &[
            CircuitType::AgeVerification,
            CircuitType::CredentialVerification,
            CircuitType::KycVerification,
        ] {
            assert_eq!(CircuitType::from_id(ct.id()), Some(*ct));
        }
    }
}
