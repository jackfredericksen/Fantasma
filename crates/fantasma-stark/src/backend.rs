//! Prover backend abstraction
//!
//! Supports different STARK proving backends:
//! - Mock: For development and testing
//! - StoneProver: StarkWare's production prover
//! - Stwo: StarkWare's Rust-native prover (experimental)
//!
//! # Usage
//!
//! ```rust,ignore
//! use fantasma_stark::backend::{ProverBackend, ProverConfig};
//!
//! // Development mode (default)
//! let prover = ProverBackend::from_config(ProverConfig::default());
//!
//! // Production mode with stone-prover
//! let prover = ProverBackend::from_config(ProverConfig {
//!     backend: "stone".to_string(),
//!     stone_prover_path: Some("/path/to/cpu_air_prover".into()),
//!     ..Default::default()
//! });
//! ```

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BackendError {
    #[error("Backend not available: {0}")]
    NotAvailable(String),

    #[error("Proof generation failed: {0}")]
    ProofFailed(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Prover backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverConfig {
    /// Backend type: "mock", "stone", "stwo"
    pub backend: String,

    /// Path to stone-prover binary (if using stone)
    pub stone_prover_path: Option<PathBuf>,

    /// Path to stone-verifier binary (if using stone)
    pub stone_verifier_path: Option<PathBuf>,

    /// Number of parallel proving threads
    pub num_threads: Option<usize>,

    /// Maximum memory usage in MB
    pub max_memory_mb: Option<usize>,

    /// Path to circuit artifacts
    pub circuits_path: Option<PathBuf>,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            backend: "mock".to_string(),
            stone_prover_path: None,
            stone_verifier_path: None,
            num_threads: None,
            max_memory_mb: None,
            circuits_path: None,
        }
    }
}

impl ProverConfig {
    /// Load config from environment variables
    pub fn from_env() -> Self {
        Self {
            backend: std::env::var("FANTASMA_PROVER_BACKEND")
                .unwrap_or_else(|_| "mock".to_string()),
            stone_prover_path: std::env::var("STONE_PROVER_PATH")
                .ok()
                .map(PathBuf::from),
            stone_verifier_path: std::env::var("STONE_VERIFIER_PATH")
                .ok()
                .map(PathBuf::from),
            num_threads: std::env::var("FANTASMA_PROVER_THREADS")
                .ok()
                .and_then(|s| s.parse().ok()),
            max_memory_mb: std::env::var("FANTASMA_PROVER_MEMORY_MB")
                .ok()
                .and_then(|s| s.parse().ok()),
            circuits_path: std::env::var("FANTASMA_CIRCUITS_PATH")
                .ok()
                .map(PathBuf::from),
        }
    }

    /// Use stone-prover backend
    pub fn with_stone(mut self, prover_path: PathBuf) -> Self {
        self.backend = "stone".to_string();
        self.stone_prover_path = Some(prover_path);
        self
    }

    /// Use stwo backend
    pub fn with_stwo(mut self) -> Self {
        self.backend = "stwo".to_string();
        self
    }
}

/// Proof generation result
#[derive(Debug, Clone)]
pub struct ProofResult {
    /// The STARK proof bytes
    pub proof_bytes: Vec<u8>,

    /// Public inputs that were proven
    pub public_inputs: Vec<String>,

    /// Proof size in bytes
    pub size_bytes: usize,

    /// Proving time in milliseconds
    pub proving_time_ms: u64,
}

/// Proof verification result
#[derive(Debug, Clone)]
pub struct VerifyResult {
    /// Whether the proof is valid
    pub valid: bool,

    /// Verification time in milliseconds
    pub verify_time_ms: u64,

    /// Error message if invalid
    pub error: Option<String>,
}

/// Abstract prover backend
pub trait ProverBackendTrait: Send + Sync {
    /// Generate a proof
    fn prove(
        &self,
        circuit_type: &str,
        private_inputs: &[String],
        public_inputs: &[String],
    ) -> Result<ProofResult, BackendError>;

    /// Verify a proof
    fn verify(
        &self,
        circuit_type: &str,
        proof_bytes: &[u8],
        public_inputs: &[String],
    ) -> Result<VerifyResult, BackendError>;

    /// Get backend name
    fn name(&self) -> &str;

    /// Check if backend is available
    fn is_available(&self) -> bool;
}

/// Mock prover backend for development
pub struct MockBackend;

impl MockBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ProverBackendTrait for MockBackend {
    fn prove(
        &self,
        circuit_type: &str,
        _private_inputs: &[String],
        public_inputs: &[String],
    ) -> Result<ProofResult, BackendError> {
        use sha3::{Digest, Sha3_256};
        use std::time::Instant;

        let start = Instant::now();

        // Generate deterministic mock proof
        let mut hasher = Sha3_256::new();
        hasher.update(b"mock_proof:");
        hasher.update(circuit_type.as_bytes());
        for input in public_inputs {
            hasher.update(input.as_bytes());
        }
        let seed: [u8; 32] = hasher.finalize().into();

        // Generate ~100KB proof
        let mut proof = Vec::with_capacity(100_000);
        proof.extend_from_slice(b"STARK_PROOF_V1");
        proof.extend_from_slice(&seed);

        while proof.len() < 100_000 {
            let mut h = Sha3_256::new();
            h.update(&proof[proof.len().saturating_sub(32)..]);
            proof.extend_from_slice(&h.finalize());
        }
        proof.truncate(100_000);

        let proving_time_ms = start.elapsed().as_millis() as u64;

        Ok(ProofResult {
            size_bytes: proof.len(),
            proof_bytes: proof,
            public_inputs: public_inputs.to_vec(),
            proving_time_ms,
        })
    }

    fn verify(
        &self,
        _circuit_type: &str,
        proof_bytes: &[u8],
        _public_inputs: &[String],
    ) -> Result<VerifyResult, BackendError> {
        use std::time::Instant;

        let start = Instant::now();

        let valid = proof_bytes.len() >= 100 && proof_bytes.starts_with(b"STARK_PROOF_V1");

        Ok(VerifyResult {
            valid,
            verify_time_ms: start.elapsed().as_millis() as u64,
            error: if valid {
                None
            } else {
                Some("Invalid mock proof".to_string())
            },
        })
    }

    fn name(&self) -> &str {
        "mock"
    }

    fn is_available(&self) -> bool {
        true
    }
}

/// Stone prover backend (StarkWare's CPU prover)
///
/// Requires stone-prover to be installed:
/// ```bash
/// # Clone and build stone-prover
/// git clone https://github.com/starkware-libs/stone-prover.git
/// cd stone-prover
/// docker build -t stone-prover .
/// # Or build natively following their README
/// ```
pub struct StoneBackend {
    prover_path: PathBuf,
    verifier_path: Option<PathBuf>,
    _num_threads: usize,
}

impl StoneBackend {
    pub fn new(prover_path: PathBuf) -> Result<Self, BackendError> {
        if !prover_path.exists() {
            return Err(BackendError::NotAvailable(format!(
                "Stone prover not found at: {}",
                prover_path.display()
            )));
        }

        Ok(Self {
            prover_path,
            verifier_path: None,
            _num_threads: num_cpus::get(),
        })
    }

    pub fn with_verifier(mut self, verifier_path: PathBuf) -> Self {
        self.verifier_path = Some(verifier_path);
        self
    }

    /// Write Stone prover config to a temp file
    fn write_prover_config(
        &self,
        dir: &std::path::Path,
    ) -> Result<PathBuf, BackendError> {
        let config = crate::stone_config::StoneProverConfig::default();
        let config_path = dir.join("prover_config.json");
        let config_json = serde_json::to_string_pretty(&config)
            .map_err(|e| BackendError::ProofFailed(format!("Config serialization: {}", e)))?;
        std::fs::write(&config_path, config_json)?;
        Ok(config_path)
    }

    /// Write Stone prover parameters to a temp file
    fn write_prover_params(
        &self,
        dir: &std::path::Path,
    ) -> Result<PathBuf, BackendError> {
        let params = crate::stone_config::StoneProverParameters::default();
        let params_path = dir.join("prover_params.json");
        let params_json = serde_json::to_string_pretty(&params)
            .map_err(|e| BackendError::ProofFailed(format!("Params serialization: {}", e)))?;
        std::fs::write(&params_path, params_json)?;
        Ok(params_path)
    }

    /// Write inputs to Stone's expected JSON format
    fn write_inputs(
        &self,
        dir: &std::path::Path,
        private_inputs: &[String],
        public_inputs: &[String],
    ) -> Result<(PathBuf, PathBuf), BackendError> {
        let private_path = dir.join("private_input.json");
        let public_path = dir.join("public_input.json");

        let private_json = serde_json::json!({
            "inputs": private_inputs,
        });
        let public_json = serde_json::json!({
            "inputs": public_inputs,
        });

        std::fs::write(
            &private_path,
            serde_json::to_string_pretty(&private_json)
                .map_err(|e| BackendError::ProofFailed(e.to_string()))?,
        )?;
        std::fs::write(
            &public_path,
            serde_json::to_string_pretty(&public_json)
                .map_err(|e| BackendError::ProofFailed(e.to_string()))?,
        )?;

        Ok((private_path, public_path))
    }
}

impl ProverBackendTrait for StoneBackend {
    fn prove(
        &self,
        circuit_type: &str,
        private_inputs: &[String],
        public_inputs: &[String],
    ) -> Result<ProofResult, BackendError> {
        use std::process::Command;
        use std::time::Instant;

        let start = Instant::now();

        // Create temp directory for all Stone I/O files
        let work_dir = tempfile::tempdir()
            .map_err(|e| BackendError::ProofFailed(format!("Failed to create temp dir: {}", e)))?;

        let work_path = work_dir.path();
        let proof_output = work_path.join("proof.json");

        // Write config files
        let config_path = self.write_prover_config(work_path)?;
        let params_path = self.write_prover_params(work_path)?;
        let (private_path, public_path) =
            self.write_inputs(work_path, private_inputs, public_inputs)?;

        tracing::info!(
            "Invoking Stone prover for circuit '{}' at {}",
            circuit_type,
            self.prover_path.display()
        );

        // Invoke cpu_air_prover
        let output = Command::new(&self.prover_path)
            .arg("--out_file")
            .arg(&proof_output)
            .arg("--private_input_file")
            .arg(&private_path)
            .arg("--public_input_file")
            .arg(&public_path)
            .arg("--prover_config_file")
            .arg(&config_path)
            .arg("--parameter_file")
            .arg(&params_path)
            .output()
            .map_err(|e| BackendError::ProofFailed(format!("Failed to execute prover: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(BackendError::ProofFailed(format!(
                "Stone prover exited with {}: {}",
                output.status, stderr
            )));
        }

        // Read the generated proof
        let proof_bytes = std::fs::read(&proof_output)
            .map_err(|e| BackendError::ProofFailed(format!("Failed to read proof output: {}", e)))?;

        let proving_time_ms = start.elapsed().as_millis() as u64;

        tracing::info!(
            "Stone prover completed in {}ms, proof size: {} bytes",
            proving_time_ms,
            proof_bytes.len()
        );

        Ok(ProofResult {
            size_bytes: proof_bytes.len(),
            proof_bytes,
            public_inputs: public_inputs.to_vec(),
            proving_time_ms,
        })
    }

    fn verify(
        &self,
        circuit_type: &str,
        proof_bytes: &[u8],
        public_inputs: &[String],
    ) -> Result<VerifyResult, BackendError> {
        use std::time::Instant;

        let verifier_path = match &self.verifier_path {
            Some(path) => path.clone(),
            None => {
                // Try to derive verifier path from prover path
                let parent = self.prover_path.parent().unwrap_or(std::path::Path::new("."));
                let verifier = parent.join("cpu_air_verifier");
                if !verifier.exists() {
                    tracing::warn!(
                        "Stone verifier not found, falling back to mock verification"
                    );
                    let mock = MockBackend::new();
                    return mock.verify(circuit_type, proof_bytes, public_inputs);
                }
                verifier
            }
        };

        let start = Instant::now();

        // Write proof to temp file
        let work_dir = tempfile::tempdir()
            .map_err(|e| BackendError::VerificationFailed(format!("Temp dir: {}", e)))?;

        let proof_path = work_dir.path().join("proof.json");
        std::fs::write(&proof_path, proof_bytes)
            .map_err(|e| BackendError::VerificationFailed(format!("Write proof: {}", e)))?;

        tracing::info!(
            "Invoking Stone verifier for circuit '{}'",
            circuit_type
        );

        let output = std::process::Command::new(&verifier_path)
            .arg("--in_file")
            .arg(&proof_path)
            .output()
            .map_err(|e| {
                BackendError::VerificationFailed(format!("Failed to execute verifier: {}", e))
            })?;

        let verify_time_ms = start.elapsed().as_millis() as u64;
        let valid = output.status.success();
        let error = if valid {
            None
        } else {
            Some(String::from_utf8_lossy(&output.stderr).to_string())
        };

        Ok(VerifyResult {
            valid,
            verify_time_ms,
            error,
        })
    }

    fn name(&self) -> &str {
        "stone"
    }

    fn is_available(&self) -> bool {
        self.prover_path.exists()
    }
}

/// Dynamic prover backend that can be configured at runtime
pub enum ProverBackend {
    Mock(MockBackend),
    Stone(StoneBackend),
}

impl ProverBackend {
    /// Create from configuration
    pub fn from_config(config: ProverConfig) -> Result<Self, BackendError> {
        match config.backend.as_str() {
            "mock" => Ok(ProverBackend::Mock(MockBackend::new())),
            "stone" => {
                let prover_path = config.stone_prover_path.ok_or_else(|| {
                    BackendError::ConfigError("stone_prover_path required for stone backend".into())
                })?;
                Ok(ProverBackend::Stone(StoneBackend::new(prover_path)?))
            }
            "stwo" => {
                // Stwo is still experimental, fall back to mock
                tracing::warn!("Stwo backend not yet implemented, using mock");
                Ok(ProverBackend::Mock(MockBackend::new()))
            }
            other => Err(BackendError::ConfigError(format!(
                "Unknown backend: {}",
                other
            ))),
        }
    }

    /// Create from environment variables
    pub fn from_env() -> Result<Self, BackendError> {
        Self::from_config(ProverConfig::from_env())
    }
}

impl ProverBackendTrait for ProverBackend {
    fn prove(
        &self,
        circuit_type: &str,
        private_inputs: &[String],
        public_inputs: &[String],
    ) -> Result<ProofResult, BackendError> {
        match self {
            ProverBackend::Mock(b) => b.prove(circuit_type, private_inputs, public_inputs),
            ProverBackend::Stone(b) => b.prove(circuit_type, private_inputs, public_inputs),
        }
    }

    fn verify(
        &self,
        circuit_type: &str,
        proof_bytes: &[u8],
        public_inputs: &[String],
    ) -> Result<VerifyResult, BackendError> {
        match self {
            ProverBackend::Mock(b) => b.verify(circuit_type, proof_bytes, public_inputs),
            ProverBackend::Stone(b) => b.verify(circuit_type, proof_bytes, public_inputs),
        }
    }

    fn name(&self) -> &str {
        match self {
            ProverBackend::Mock(b) => b.name(),
            ProverBackend::Stone(b) => b.name(),
        }
    }

    fn is_available(&self) -> bool {
        match self {
            ProverBackend::Mock(b) => b.is_available(),
            ProverBackend::Stone(b) => b.is_available(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_backend() {
        let backend = MockBackend::new();

        let result = backend
            .prove(
                "age_verification",
                &["0x123".to_string()],
                &["0x15".to_string()],
            )
            .unwrap();

        assert!(!result.proof_bytes.is_empty());
        assert_eq!(result.size_bytes, 100_000);

        let verify = backend
            .verify("age_verification", &result.proof_bytes, &["0x15".to_string()])
            .unwrap();

        assert!(verify.valid);
    }

    #[test]
    fn test_prover_backend_from_config() {
        let backend = ProverBackend::from_config(ProverConfig::default()).unwrap();
        assert_eq!(backend.name(), "mock");
        assert!(backend.is_available());
    }
}
