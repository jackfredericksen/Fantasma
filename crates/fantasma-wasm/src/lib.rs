//! Fantasma WASM Witness Generation
//!
//! Compiles witness generation logic to WebAssembly so private user data
//! (birthdate, KYC details, credentials) never leaves the browser.
//! The browser generates the witness locally, then sends only the
//! public inputs to the server for STARK proving.

use chrono::Datelike;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use wasm_bindgen::prelude::*;

/// Result of witness generation, returned as JSON to JavaScript
#[derive(Serialize, Deserialize)]
pub struct WitnessResult {
    /// Circuit type identifier
    pub circuit_type: String,
    /// Private inputs as hex-encoded field elements
    pub private_inputs: Vec<String>,
    /// Public inputs as hex-encoded field elements
    pub public_inputs: Vec<String>,
}

/// Error result
#[derive(Serialize, Deserialize)]
pub struct WitnessError {
    pub error: String,
}

fn sha3_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn u32_to_hex(v: u32) -> String {
    let mut bytes = [0u8; 32];
    bytes[28..32].copy_from_slice(&v.to_be_bytes());
    to_hex(&bytes)
}

fn u8_to_hex(v: u8) -> String {
    let mut bytes = [0u8; 32];
    bytes[31] = v;
    to_hex(&bytes)
}

fn u64_to_hex(v: u64) -> String {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&v.to_be_bytes());
    to_hex(&bytes)
}

/// Generate a witness for age verification.
///
/// Private data (birthdate, salt) stays in the browser.
/// Returns a JSON object with private_inputs and public_inputs.
#[wasm_bindgen]
pub fn generate_age_witness(
    birthdate_yyyymmdd: u32,
    salt_hex: &str,
    signature_hash_hex: &str,
    threshold: u8,
    verification_date_yyyymmdd: u32,
    credential_commitment_hex: &str,
    issuer_pubkey_hash_hex: &str,
) -> JsValue {
    let result = WitnessResult {
        circuit_type: "age_verification_v1".to_string(),
        private_inputs: vec![
            u32_to_hex(birthdate_yyyymmdd),
            salt_hex.to_string(),
            signature_hash_hex.to_string(),
        ],
        public_inputs: vec![
            u8_to_hex(threshold),
            u32_to_hex(verification_date_yyyymmdd),
            credential_commitment_hex.to_string(),
            issuer_pubkey_hash_hex.to_string(),
        ],
    };

    serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
}

/// Generate a witness for KYC verification.
#[wasm_bindgen]
pub fn generate_kyc_witness(
    user_id_hash_hex: &str,
    kyc_provider_id_hex: &str,
    kyc_level: u8,
    verification_timestamp: u64,
    kyc_data_hash_hex: &str,
    provider_signature_hash_hex: &str,
    salt_hex: &str,
    expected_level: u8,
    max_age_seconds: u64,
    current_timestamp: u64,
    provider_pubkey_hash_hex: &str,
    kyc_commitment_hex: &str,
) -> JsValue {
    let result = WitnessResult {
        circuit_type: "kyc_verification_v1".to_string(),
        private_inputs: vec![
            user_id_hash_hex.to_string(),
            kyc_provider_id_hex.to_string(),
            u8_to_hex(kyc_level),
            u64_to_hex(verification_timestamp),
            kyc_data_hash_hex.to_string(),
            provider_signature_hash_hex.to_string(),
            salt_hex.to_string(),
        ],
        public_inputs: vec![
            u8_to_hex(expected_level),
            u64_to_hex(max_age_seconds),
            u64_to_hex(current_timestamp),
            provider_pubkey_hash_hex.to_string(),
            kyc_commitment_hex.to_string(),
        ],
    };

    serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
}

/// Generate a witness for credential verification.
#[wasm_bindgen]
pub fn generate_credential_witness(
    credential_type_hex: &str,
    credential_details_hash_hex: &str,
    salt_hex: &str,
    user_secret_hex: &str,
    merkle_proof_hex: &str, // Comma-separated hex hashes
    merkle_indices: &str,   // Comma-separated "0" or "1"
    credential_type_hash_hex: &str,
    merkle_root_hex: &str,
    issuer_pubkey_hash_hex: &str,
    nullifier_hex: &str,
    verifier_domain_hash_hex: &str,
    nonce_hex: &str,
) -> JsValue {
    let proof_elements: Vec<String> = if merkle_proof_hex.is_empty() {
        vec![]
    } else {
        merkle_proof_hex.split(',').map(|s| s.trim().to_string()).collect()
    };

    let index_elements: Vec<String> = if merkle_indices.is_empty() {
        vec![]
    } else {
        merkle_indices.split(',').map(|s| s.trim().to_string()).collect()
    };

    let result = WitnessResult {
        circuit_type: "credential_verification_v1".to_string(),
        private_inputs: vec![
            credential_type_hex.to_string(),
            credential_details_hash_hex.to_string(),
            salt_hex.to_string(),
            user_secret_hex.to_string(),
            serde_json::to_string(&proof_elements).unwrap_or_default(),
            serde_json::to_string(&index_elements).unwrap_or_default(),
        ],
        public_inputs: vec![
            credential_type_hash_hex.to_string(),
            merkle_root_hex.to_string(),
            issuer_pubkey_hash_hex.to_string(),
            nullifier_hex.to_string(),
            verifier_domain_hash_hex.to_string(),
            nonce_hex.to_string(),
        ],
    };

    serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
}

/// Compute a Poseidon-style commitment: H(value || salt)
/// Uses SHA3-256 as a stand-in (STARK-compatible in our circuit design)
#[wasm_bindgen]
pub fn compute_commitment(value_hex: &str, salt_hex: &str) -> String {
    let value_bytes = hex::decode(value_hex).unwrap_or_default();
    let salt_bytes = hex::decode(salt_hex).unwrap_or_default();

    let mut data = Vec::with_capacity(value_bytes.len() + salt_bytes.len());
    data.extend_from_slice(&value_bytes);
    data.extend_from_slice(&salt_bytes);

    to_hex(&sha3_hash(&data))
}

/// Compute a nullifier: H(H(H(credential_leaf, user_secret), verifier_domain), nonce)
#[wasm_bindgen]
pub fn compute_nullifier(
    credential_leaf_hex: &str,
    user_secret_hex: &str,
    verifier_domain_hash_hex: &str,
    nonce_hex: &str,
) -> String {
    let leaf = hex::decode(credential_leaf_hex).unwrap_or_default();
    let secret = hex::decode(user_secret_hex).unwrap_or_default();
    let domain = hex::decode(verifier_domain_hash_hex).unwrap_or_default();
    let nonce = hex::decode(nonce_hex).unwrap_or_default();

    let inner = sha3_hash(&[leaf.as_slice(), secret.as_slice()].concat());
    let domain_bound = sha3_hash(&[inner.as_slice(), domain.as_slice()].concat());
    let nullifier = sha3_hash(&[domain_bound.as_slice(), nonce.as_slice()].concat());

    to_hex(&nullifier)
}

/// Hash arbitrary data with SHA3-256
#[wasm_bindgen]
pub fn sha3_256(data_hex: &str) -> String {
    let bytes = hex::decode(data_hex).unwrap_or_default();
    to_hex(&sha3_hash(&bytes))
}

/// Get the current date in YYYYMMDD format
#[wasm_bindgen]
pub fn current_date_yyyymmdd() -> u32 {
    let now = chrono::Utc::now();
    now.year() as u32 * 10000 + now.month() * 100 + now.day()
}

/// Get the current Unix timestamp in seconds
#[wasm_bindgen]
pub fn current_timestamp() -> u64 {
    chrono::Utc::now().timestamp() as u64
}

/// Version string for the WASM module
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// Hex encoding dependency (re-export sha3 for internal use)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_commitment() {
        let value = "0000000000000000000000000000000000000000000000000000000000000001";
        let salt = "0000000000000000000000000000000000000000000000000000000000000002";
        let commitment = compute_commitment(value, salt);
        assert_eq!(commitment.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_compute_nullifier() {
        let leaf = "aa".repeat(32);
        let secret = "bb".repeat(32);
        let domain = "cc".repeat(32);
        let nonce = "dd".repeat(32);
        let nullifier = compute_nullifier(&leaf, &secret, &domain, &nonce);
        assert_eq!(nullifier.len(), 64);
    }

    #[test]
    fn test_sha3_256() {
        let hash = sha3_256("48656c6c6f"); // "Hello" in hex
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_current_date() {
        let date = current_date_yyyymmdd();
        assert!(date > 20200000);
        assert!(date < 21000000);
    }
}
