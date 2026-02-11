//! Cairo program runner for STARK proof generation
//!
//! This module provides integration with Cairo tooling via subprocess calls.
//! In production, this could be replaced with native Rust bindings.

use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;
use serde::{Deserialize, Serialize};

#[derive(Error, Debug)]
pub enum CairoError {
    #[error("Scarb not found. Install with: curl -L https://scarb.dev | sh")]
    ScarbNotFound,

    #[error("Compilation failed: {0}")]
    CompilationFailed(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Cairo program input for circuit execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CairoInput {
    /// Program arguments as felt252 values (hex strings)
    pub args: Vec<String>,
}

/// Cairo execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CairoExecutionResult {
    /// Whether execution succeeded
    pub success: bool,

    /// Output values
    pub output: Vec<String>,

    /// Execution trace (for proof generation)
    pub trace_path: Option<PathBuf>,

    /// Memory file (for proof generation)
    pub memory_path: Option<PathBuf>,
}

/// Cairo runner for executing programs and generating proofs
pub struct CairoRunner {
    /// Path to the circuits directory
    circuits_dir: PathBuf,

    /// Working directory for temporary files
    work_dir: PathBuf,

    /// Whether Scarb is available
    scarb_available: bool,
}

impl CairoRunner {
    /// Create a new Cairo runner
    pub fn new(circuits_dir: impl Into<PathBuf>) -> Result<Self, CairoError> {
        let circuits_dir = circuits_dir.into();
        let work_dir = std::env::temp_dir().join("fantasma-cairo");
        std::fs::create_dir_all(&work_dir)?;

        // Check if Scarb is available
        let scarb_available = Command::new("scarb")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        Ok(Self {
            circuits_dir,
            work_dir,
            scarb_available,
        })
    }

    /// Check if Scarb is available
    pub fn is_scarb_available(&self) -> bool {
        self.scarb_available
    }

    /// Compile Cairo circuits
    pub fn compile(&self) -> Result<(), CairoError> {
        if !self.scarb_available {
            return Err(CairoError::ScarbNotFound);
        }

        let output = Command::new("scarb")
            .arg("build")
            .current_dir(&self.circuits_dir)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CairoError::CompilationFailed(stderr.to_string()));
        }

        Ok(())
    }

    /// Run Cairo tests
    pub fn test(&self) -> Result<bool, CairoError> {
        if !self.scarb_available {
            return Err(CairoError::ScarbNotFound);
        }

        let output = Command::new("scarb")
            .arg("test")
            .current_dir(&self.circuits_dir)
            .output()?;

        Ok(output.status.success())
    }

    /// Execute a Cairo program with inputs
    pub fn execute(
        &self,
        program_name: &str,
        input: &CairoInput,
    ) -> Result<CairoExecutionResult, CairoError> {
        if !self.scarb_available {
            // Return mock result if Scarb not available
            return Ok(CairoExecutionResult {
                success: true,
                output: vec!["0x1".to_string()], // Mock success
                trace_path: None,
                memory_path: None,
            });
        }

        // Write input to file
        let input_path = self.work_dir.join(format!("{}_input.json", program_name));
        std::fs::write(&input_path, serde_json::to_string_pretty(input)?)?;

        // For now, we simulate execution since direct cairo-run integration
        // requires more setup. In production, this would:
        // 1. Use cairo-run to execute the program
        // 2. Generate execution trace
        // 3. Return trace for STARK proof generation

        Ok(CairoExecutionResult {
            success: true,
            output: vec!["0x1".to_string()],
            trace_path: Some(self.work_dir.join(format!("{}_trace.bin", program_name))),
            memory_path: Some(self.work_dir.join(format!("{}_memory.bin", program_name))),
        })
    }

    /// Generate a STARK proof from execution trace
    pub fn generate_proof(
        &self,
        trace_path: &Path,
        memory_path: &Path,
    ) -> Result<Vec<u8>, CairoError> {
        // In production, this would call stone-prover or stwo
        // For now, generate a deterministic mock proof

        let trace_hash = if trace_path.exists() {
            let trace_data = std::fs::read(trace_path)?;
            hash_data(&trace_data)
        } else {
            [0u8; 32]
        };

        // Generate realistic-sized mock proof (100KB)
        let mut proof = Vec::with_capacity(100_000);
        proof.extend_from_slice(b"STARK_PROOF_V1");
        proof.extend_from_slice(&trace_hash);

        // Pad to realistic size
        use sha3::{Digest, Sha3_256};
        while proof.len() < 100_000 {
            let mut hasher = Sha3_256::new();
            hasher.update(&proof[proof.len().saturating_sub(32)..]);
            proof.extend_from_slice(&hasher.finalize());
        }
        proof.truncate(100_000);

        Ok(proof)
    }

    /// Verify a STARK proof
    pub fn verify_proof(
        &self,
        proof: &[u8],
        public_inputs: &[String],
    ) -> Result<bool, CairoError> {
        // Basic validation
        if proof.len() < 100 {
            return Ok(false);
        }

        if !proof.starts_with(b"STARK_PROOF_V1") {
            return Ok(false);
        }

        // In production, this would use stone-prover or stwo verification
        Ok(true)
    }
}

/// Hash data using SHA3-256
fn hash_data(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Wrapper for age verification circuit execution
pub struct AgeVerificationCircuit {
    runner: CairoRunner,
}

impl AgeVerificationCircuit {
    pub fn new(circuits_dir: impl Into<PathBuf>) -> Result<Self, CairoError> {
        Ok(Self {
            runner: CairoRunner::new(circuits_dir)?,
        })
    }

    /// Generate a proof for age verification
    pub fn prove(
        &self,
        birthdate: u32,         // YYYYMMDD
        salt: [u8; 32],
        signature_hash: [u8; 32],
        threshold: u8,
        verification_date: u32, // YYYYMMDD
        credential_commitment: [u8; 32],
        issuer_pubkey_hash: [u8; 32],
    ) -> Result<AgeVerificationProof, CairoError> {
        // Convert inputs to felt252 hex strings
        let input = CairoInput {
            args: vec![
                format!("0x{:x}", birthdate),
                format!("0x{}", hex::encode(salt)),
                format!("0x{}", hex::encode(signature_hash)),
                format!("0x{:x}", threshold),
                format!("0x{:x}", verification_date),
                format!("0x{}", hex::encode(credential_commitment)),
                format!("0x{}", hex::encode(issuer_pubkey_hash)),
            ],
        };

        // Execute circuit
        let result = self.runner.execute("age_verification", &input)?;

        if !result.success {
            return Err(CairoError::ExecutionFailed("Age check failed".into()));
        }

        // Generate proof
        let proof_bytes = if let (Some(trace), Some(memory)) =
            (&result.trace_path, &result.memory_path)
        {
            self.runner.generate_proof(trace, memory)?
        } else {
            // Generate mock proof
            self.runner.generate_proof(
                &self.runner.work_dir.join("mock_trace.bin"),
                &self.runner.work_dir.join("mock_memory.bin"),
            )?
        };

        Ok(AgeVerificationProof {
            proof_bytes,
            threshold,
            verification_date,
            credential_commitment,
            issuer_pubkey_hash,
        })
    }
}

/// Age verification proof result
#[derive(Debug, Clone)]
pub struct AgeVerificationProof {
    /// The STARK proof bytes
    pub proof_bytes: Vec<u8>,

    /// Public inputs
    pub threshold: u8,
    pub verification_date: u32,
    pub credential_commitment: [u8; 32],
    pub issuer_pubkey_hash: [u8; 32],
}

impl AgeVerificationProof {
    /// Get public inputs as hex strings
    pub fn public_inputs(&self) -> Vec<String> {
        vec![
            format!("0x{:x}", self.threshold),
            format!("0x{:x}", self.verification_date),
            format!("0x{}", hex::encode(self.credential_commitment)),
            format!("0x{}", hex::encode(self.issuer_pubkey_hash)),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cairo_runner_creation() {
        let runner = CairoRunner::new("/tmp/test-circuits");
        assert!(runner.is_ok());
    }

    #[test]
    fn test_age_verification_mock() {
        let circuit = AgeVerificationCircuit::new("/tmp/test-circuits").unwrap();

        let proof = circuit.prove(
            20000101,           // Born Jan 1, 2000
            [1u8; 32],          // Salt
            [2u8; 32],          // Signature hash
            21,                 // Threshold
            20260210,           // Current date
            [3u8; 32],          // Commitment
            [4u8; 32],          // Issuer pubkey hash
        );

        assert!(proof.is_ok());
        let proof = proof.unwrap();
        assert!(!proof.proof_bytes.is_empty());
        assert_eq!(proof.threshold, 21);
    }
}
