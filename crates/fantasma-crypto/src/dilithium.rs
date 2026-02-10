//! Dilithium signatures (NIST ML-DSA)
//!
//! Post-quantum secure digital signatures using the Dilithium algorithm,
//! a NIST PQC standardized signature scheme.

use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Error, Debug)]
pub enum DilithiumError {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid secret key")]
    InvalidSecretKey,

    #[error("Signature verification failed")]
    VerificationFailed,
}

/// Dilithium public key (Dilithium3 - NIST Level 3)
#[derive(Clone, Serialize, Deserialize)]
pub struct DilithiumPublicKey {
    bytes: Vec<u8>,
}

impl DilithiumPublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DilithiumError> {
        // Validate by attempting to parse
        dilithium3::PublicKey::from_bytes(bytes).map_err(|_| DilithiumError::InvalidPublicKey)?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Compute hash of the public key (for circuit binding)
    pub fn hash(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&self.bytes);
        hasher.finalize().into()
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &DilithiumSignature) -> Result<(), DilithiumError> {
        let pk = dilithium3::PublicKey::from_bytes(&self.bytes)
            .map_err(|_| DilithiumError::InvalidPublicKey)?;

        // Combine signature and message for verification
        let signed_msg = dilithium3::SignedMessage::from_bytes(&signature.bytes)
            .map_err(|_| DilithiumError::InvalidSignature)?;

        let opened = dilithium3::open(&signed_msg, &pk);
        if opened.is_err() {
            return Err(DilithiumError::VerificationFailed);
        }

        // Verify the message matches
        let opened_msg = opened.unwrap();
        if opened_msg != message {
            return Err(DilithiumError::VerificationFailed);
        }

        Ok(())
    }
}

impl std::fmt::Debug for DilithiumPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DilithiumPublicKey({} bytes)", self.bytes.len())
    }
}

/// Dilithium secret key (zeroed on drop for security)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DilithiumSecretKey {
    bytes: Vec<u8>,
}

impl DilithiumSecretKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DilithiumError> {
        dilithium3::SecretKey::from_bytes(bytes).map_err(|_| DilithiumError::InvalidSecretKey)?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Get raw bytes (use carefully!)
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> DilithiumSignature {
        let sk =
            dilithium3::SecretKey::from_bytes(&self.bytes).expect("Already validated secret key");
        let signed_msg = dilithium3::sign(message, &sk);
        DilithiumSignature {
            bytes: signed_msg.as_bytes().to_vec(),
        }
    }
}

impl std::fmt::Debug for DilithiumSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DilithiumSecretKey([REDACTED])")
    }
}

/// Dilithium signature
#[derive(Clone, Serialize, Deserialize)]
pub struct DilithiumSignature {
    bytes: Vec<u8>,
}

impl DilithiumSignature {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Compute hash of the signature (for circuit binding)
    pub fn hash(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&self.bytes);
        hasher.finalize().into()
    }
}

impl std::fmt::Debug for DilithiumSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DilithiumSignature({} bytes)", self.bytes.len())
    }
}

/// Dilithium keypair
pub struct DilithiumKeypair {
    pub public_key: DilithiumPublicKey,
    pub secret_key: DilithiumSecretKey,
}

impl DilithiumKeypair {
    /// Generate a new keypair
    pub fn generate() -> Self {
        let (pk, sk) = dilithium3::keypair();
        Self {
            public_key: DilithiumPublicKey {
                bytes: pk.as_bytes().to_vec(),
            },
            secret_key: DilithiumSecretKey {
                bytes: sk.as_bytes().to_vec(),
            },
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> DilithiumSignature {
        self.secret_key.sign(message)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &DilithiumSignature) -> Result<(), DilithiumError> {
        self.public_key.verify(message, signature)
    }
}

impl std::fmt::Debug for DilithiumKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DilithiumKeypair")
            .field("public_key", &self.public_key)
            .field("secret_key", &self.secret_key)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = DilithiumKeypair::generate();
        assert!(!keypair.public_key.as_bytes().is_empty());
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = DilithiumKeypair::generate();
        let message = b"Hello, Fantasma!";

        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_verify_wrong_message() {
        let keypair = DilithiumKeypair::generate();
        let message = b"Hello, Fantasma!";
        let wrong_message = b"Wrong message";

        let signature = keypair.sign(message);
        assert!(keypair.verify(wrong_message, &signature).is_err());
    }
}
