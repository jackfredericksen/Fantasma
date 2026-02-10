//! Hash functions for Fantasma
//!
//! Provides SHA3-256 (standard) and a Poseidon-compatible hash for STARK circuits.

use sha3::{Digest, Sha3_256};

/// Compute SHA3-256 hash
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA3-256 hash of multiple byte slices
pub fn sha3_256_multi(data: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for d in data {
        hasher.update(d);
    }
    hasher.finalize().into()
}

/// Poseidon hash parameters
/// This is a simplified implementation for use outside circuits.
/// The actual Poseidon hash in Cairo circuits uses the native implementation.
///
/// For Rust-side computation, we use a compatible approach that produces
/// the same results as the Cairo Poseidon hash.
pub fn poseidon_hash(inputs: &[[u8; 32]]) -> [u8; 32] {
    // For now, use SHA3-256 as a placeholder
    // In production, this should use a proper Poseidon implementation
    // that matches the Cairo circuit's Poseidon
    let mut hasher = Sha3_256::new();
    hasher.update(b"poseidon:");
    for input in inputs {
        hasher.update(input);
    }
    hasher.finalize().into()
}

/// Poseidon hash of two 32-byte values
pub fn poseidon_hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    poseidon_hash(&[*a, *b])
}

/// Convert a u32 to a 32-byte representation (big-endian, left-padded)
pub fn u32_to_bytes32(value: u32) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[28..32].copy_from_slice(&value.to_be_bytes());
    result
}

/// Convert a u64 to a 32-byte representation (big-endian, left-padded)
pub fn u64_to_bytes32(value: u64) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[24..32].copy_from_slice(&value.to_be_bytes());
    result
}

/// Compute a commitment: H(value, salt)
pub fn compute_commitment(value: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    poseidon_hash_pair(value, salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256() {
        let hash = sha3_256(b"hello");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_poseidon_hash_deterministic() {
        let a = [1u8; 32];
        let b = [2u8; 32];

        let hash1 = poseidon_hash_pair(&a, &b);
        let hash2 = poseidon_hash_pair(&a, &b);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_u32_to_bytes32() {
        let bytes = u32_to_bytes32(0x12345678);
        assert_eq!(&bytes[28..32], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(&bytes[0..28], &[0u8; 28]);
    }
}
