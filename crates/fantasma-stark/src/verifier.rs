//! STARK proof verification

use crate::circuit::CircuitType;
use crate::prover::StarkProof;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerifierError {
    #[error("Invalid proof format")]
    InvalidProofFormat,

    #[error("Invalid public inputs")]
    InvalidPublicInputs,

    #[error("Verification failed")]
    VerificationFailed,

    #[error("Circuit mismatch")]
    CircuitMismatch,

    #[error("Proof expired")]
    ProofExpired,
}

/// Result of proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the proof is valid
    pub valid: bool,

    /// Circuit type verified
    pub circuit_type: CircuitType,

    /// Public inputs that were verified
    pub public_inputs: Vec<[u8; 32]>,

    /// Error message if invalid
    pub error: Option<String>,
}

/// STARK proof verifier
pub struct Verifier {
    /// Verification keys for each circuit
    verification_keys: std::collections::HashMap<CircuitType, VerificationKey>,
}

/// Verification key for a circuit (placeholder)
struct VerificationKey {
    _circuit_type: CircuitType,
    _key_bytes: Vec<u8>,
}

impl Verifier {
    /// Create a new verifier
    pub fn new() -> Self {
        Self {
            verification_keys: std::collections::HashMap::new(),
        }
    }

    /// Load verification key for a circuit
    pub fn load_verification_key(&mut self, circuit_type: CircuitType) -> Result<(), VerifierError> {
        // In a real implementation, this would load the actual verification key
        let vk = VerificationKey {
            _circuit_type: circuit_type,
            _key_bytes: Vec::new(),
        };
        self.verification_keys.insert(circuit_type, vk);
        Ok(())
    }

    /// Verify a STARK proof
    pub fn verify(&self, proof: &StarkProof) -> Result<VerificationResult, VerifierError> {
        let _vk = self
            .verification_keys
            .get(&proof.circuit_type)
            .ok_or(VerifierError::CircuitMismatch)?;

        // In a real implementation, this would:
        // 1. Parse the STARK proof
        // 2. Verify the FRI commitment
        // 3. Check the execution trace validity
        // 4. Verify public inputs match
        //
        // For now, we do basic validation

        // Check proof format (mock validation)
        if proof.proof_bytes.len() < 100 {
            return Ok(VerificationResult {
                valid: false,
                circuit_type: proof.circuit_type,
                public_inputs: proof.public_inputs.clone(),
                error: Some("Proof too small".to_string()),
            });
        }

        // Check for mock proof header
        if !proof.proof_bytes.starts_with(b"STARK_PROOF_V1") {
            return Ok(VerificationResult {
                valid: false,
                circuit_type: proof.circuit_type,
                public_inputs: proof.public_inputs.clone(),
                error: Some("Invalid proof header".to_string()),
            });
        }

        // Mock verification passes
        Ok(VerificationResult {
            valid: true,
            circuit_type: proof.circuit_type,
            public_inputs: proof.public_inputs.clone(),
            error: None,
        })
    }

    /// Verify a proof from bytes
    pub fn verify_bytes(
        &self,
        proof_bytes: &[u8],
        circuit_type: CircuitType,
        public_inputs: Vec<[u8; 32]>,
    ) -> Result<VerificationResult, VerifierError> {
        let proof = StarkProof {
            proof_bytes: proof_bytes.to_vec(),
            circuit_type,
            public_inputs,
            size_bytes: proof_bytes.len(),
        };
        self.verify(&proof)
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::Prover;
    use crate::witness::AgeVerificationWitnessBuilder;

    #[tokio::test]
    async fn test_verify_proof() {
        // Generate a proof
        let mut prover = Prover::new();
        prover.load_circuit(CircuitType::AgeVerification).unwrap();

        let witness = AgeVerificationWitnessBuilder::new()
            .birthdate(20000101)
            .salt([1u8; 32])
            .signature_hash([2u8; 32])
            .threshold(18)
            .verification_date(20260210)
            .credential_commitment([3u8; 32])
            .issuer_pubkey_hash([4u8; 32])
            .build()
            .unwrap();

        let proof = prover.prove(witness).await.unwrap();

        // Verify the proof
        let mut verifier = Verifier::new();
        verifier
            .load_verification_key(CircuitType::AgeVerification)
            .unwrap();

        let result = verifier.verify(&proof).unwrap();
        assert!(result.valid);
    }
}
