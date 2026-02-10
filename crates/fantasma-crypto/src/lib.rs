//! Fantasma Crypto
//!
//! Post-quantum cryptographic primitives for the Fantasma ZK identity layer.
//! Uses Dilithium signatures (NIST ML-DSA) and Poseidon hash.

pub mod dilithium;
pub mod hash;
pub mod merkle;
pub mod nullifier;

pub use dilithium::{DilithiumKeypair, DilithiumPublicKey, DilithiumSignature};
pub use hash::{poseidon_hash, poseidon_hash_pair, sha3_256};
pub use merkle::{MerkleProof, MerkleTree};
pub use nullifier::Nullifier;
