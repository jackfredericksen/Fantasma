//! Witness generation for STARK circuits

use chrono::Datelike;
use fantasma_core::{ClaimType, Credential};
use fantasma_crypto::hash::{sha3_256, u32_to_bytes32};
use serde::{Deserialize, Serialize};

use crate::circuit::CircuitType;

/// Witness data for circuit execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Witness {
    /// Circuit type this witness is for
    pub circuit_type: CircuitType,

    /// Private inputs (not revealed)
    pub private_inputs: Vec<WitnessValue>,

    /// Public inputs (revealed to verifier)
    pub public_inputs: Vec<WitnessValue>,
}

/// A value in the witness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WitnessValue {
    /// Field element (32 bytes)
    Field([u8; 32]),

    /// Unsigned 8-bit integer
    U8(u8),

    /// Unsigned 32-bit integer
    U32(u32),

    /// Unsigned 64-bit integer
    U64(u64),

    /// Boolean
    Bool(bool),

    /// Array of field elements
    FieldArray(Vec<[u8; 32]>),

    /// Array of booleans
    BoolArray(Vec<bool>),
}

impl WitnessValue {
    /// Convert to field bytes
    pub fn to_field_bytes(&self) -> [u8; 32] {
        match self {
            WitnessValue::Field(f) => *f,
            WitnessValue::U8(v) => {
                let mut bytes = [0u8; 32];
                bytes[31] = *v;
                bytes
            }
            WitnessValue::U32(v) => u32_to_bytes32(*v),
            WitnessValue::U64(v) => {
                let mut bytes = [0u8; 32];
                bytes[24..32].copy_from_slice(&v.to_be_bytes());
                bytes
            }
            WitnessValue::Bool(b) => {
                let mut bytes = [0u8; 32];
                bytes[31] = if *b { 1 } else { 0 };
                bytes
            }
            _ => panic!("Cannot convert array to single field"),
        }
    }
}

/// Builder for age verification witness
pub struct AgeVerificationWitnessBuilder {
    birthdate: Option<u32>,
    salt: Option<[u8; 32]>,
    signature_hash: Option<[u8; 32]>,
    threshold: Option<u8>,
    verification_date: Option<u32>,
    credential_commitment: Option<[u8; 32]>,
    issuer_pubkey_hash: Option<[u8; 32]>,
}

impl AgeVerificationWitnessBuilder {
    pub fn new() -> Self {
        Self {
            birthdate: None,
            salt: None,
            signature_hash: None,
            threshold: None,
            verification_date: None,
            credential_commitment: None,
            issuer_pubkey_hash: None,
        }
    }

    pub fn birthdate(mut self, date: u32) -> Self {
        self.birthdate = Some(date);
        self
    }

    pub fn salt(mut self, salt: [u8; 32]) -> Self {
        self.salt = Some(salt);
        self
    }

    pub fn signature_hash(mut self, hash: [u8; 32]) -> Self {
        self.signature_hash = Some(hash);
        self
    }

    pub fn threshold(mut self, threshold: u8) -> Self {
        self.threshold = Some(threshold);
        self
    }

    pub fn verification_date(mut self, date: u32) -> Self {
        self.verification_date = Some(date);
        self
    }

    pub fn credential_commitment(mut self, commitment: [u8; 32]) -> Self {
        self.credential_commitment = Some(commitment);
        self
    }

    pub fn issuer_pubkey_hash(mut self, hash: [u8; 32]) -> Self {
        self.issuer_pubkey_hash = Some(hash);
        self
    }

    pub fn build(self) -> Result<Witness, &'static str> {
        Ok(Witness {
            circuit_type: CircuitType::AgeVerification,
            private_inputs: vec![
                WitnessValue::U32(self.birthdate.ok_or("birthdate required")?),
                WitnessValue::Field(self.salt.ok_or("salt required")?),
                WitnessValue::Field(self.signature_hash.ok_or("signature_hash required")?),
            ],
            public_inputs: vec![
                WitnessValue::U8(self.threshold.ok_or("threshold required")?),
                WitnessValue::U32(self.verification_date.ok_or("verification_date required")?),
                WitnessValue::Field(
                    self.credential_commitment
                        .ok_or("credential_commitment required")?,
                ),
                WitnessValue::Field(
                    self.issuer_pubkey_hash
                        .ok_or("issuer_pubkey_hash required")?,
                ),
            ],
        })
    }
}

impl Default for AgeVerificationWitnessBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for KYC verification witness
pub struct KycWitnessBuilder {
    // Private inputs
    user_id_hash: Option<[u8; 32]>,
    kyc_provider_id: Option<[u8; 32]>,
    kyc_level: Option<u8>,
    verification_timestamp: Option<u64>,
    kyc_data_hash: Option<[u8; 32]>,
    provider_signature_hash: Option<[u8; 32]>,
    salt: Option<[u8; 32]>,
    // Public inputs
    expected_level: Option<u8>,
    max_age_seconds: Option<u64>,
    current_timestamp: Option<u64>,
    provider_pubkey_hash: Option<[u8; 32]>,
    kyc_commitment: Option<[u8; 32]>,
}

impl KycWitnessBuilder {
    pub fn new() -> Self {
        Self {
            user_id_hash: None,
            kyc_provider_id: None,
            kyc_level: None,
            verification_timestamp: None,
            kyc_data_hash: None,
            provider_signature_hash: None,
            salt: None,
            expected_level: None,
            max_age_seconds: None,
            current_timestamp: None,
            provider_pubkey_hash: None,
            kyc_commitment: None,
        }
    }

    pub fn user_id_hash(mut self, hash: [u8; 32]) -> Self {
        self.user_id_hash = Some(hash);
        self
    }

    pub fn kyc_provider_id(mut self, id: [u8; 32]) -> Self {
        self.kyc_provider_id = Some(id);
        self
    }

    pub fn kyc_level(mut self, level: u8) -> Self {
        self.kyc_level = Some(level);
        self
    }

    pub fn verification_timestamp(mut self, ts: u64) -> Self {
        self.verification_timestamp = Some(ts);
        self
    }

    pub fn kyc_data_hash(mut self, hash: [u8; 32]) -> Self {
        self.kyc_data_hash = Some(hash);
        self
    }

    pub fn provider_signature_hash(mut self, hash: [u8; 32]) -> Self {
        self.provider_signature_hash = Some(hash);
        self
    }

    pub fn salt(mut self, salt: [u8; 32]) -> Self {
        self.salt = Some(salt);
        self
    }

    pub fn expected_level(mut self, level: u8) -> Self {
        self.expected_level = Some(level);
        self
    }

    pub fn max_age_seconds(mut self, max_age: u64) -> Self {
        self.max_age_seconds = Some(max_age);
        self
    }

    pub fn current_timestamp(mut self, ts: u64) -> Self {
        self.current_timestamp = Some(ts);
        self
    }

    pub fn provider_pubkey_hash(mut self, hash: [u8; 32]) -> Self {
        self.provider_pubkey_hash = Some(hash);
        self
    }

    pub fn kyc_commitment(mut self, commitment: [u8; 32]) -> Self {
        self.kyc_commitment = Some(commitment);
        self
    }

    pub fn build(self) -> Result<Witness, &'static str> {
        Ok(Witness {
            circuit_type: CircuitType::KycVerification,
            private_inputs: vec![
                WitnessValue::Field(self.user_id_hash.ok_or("user_id_hash required")?),
                WitnessValue::Field(self.kyc_provider_id.ok_or("kyc_provider_id required")?),
                WitnessValue::U8(self.kyc_level.ok_or("kyc_level required")?),
                WitnessValue::U64(
                    self.verification_timestamp
                        .ok_or("verification_timestamp required")?,
                ),
                WitnessValue::Field(self.kyc_data_hash.ok_or("kyc_data_hash required")?),
                WitnessValue::Field(
                    self.provider_signature_hash
                        .ok_or("provider_signature_hash required")?,
                ),
                WitnessValue::Field(self.salt.ok_or("salt required")?),
            ],
            public_inputs: vec![
                WitnessValue::U8(self.expected_level.ok_or("expected_level required")?),
                WitnessValue::U64(self.max_age_seconds.ok_or("max_age_seconds required")?),
                WitnessValue::U64(self.current_timestamp.ok_or("current_timestamp required")?),
                WitnessValue::Field(
                    self.provider_pubkey_hash
                        .ok_or("provider_pubkey_hash required")?,
                ),
                WitnessValue::Field(self.kyc_commitment.ok_or("kyc_commitment required")?),
            ],
        })
    }
}

impl Default for KycWitnessBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for credential verification witness
pub struct CredentialWitnessBuilder {
    // Private inputs
    credential_type: Option<[u8; 32]>,
    credential_details_hash: Option<[u8; 32]>,
    salt: Option<[u8; 32]>,
    user_secret: Option<[u8; 32]>,
    merkle_proof: Option<Vec<[u8; 32]>>,
    merkle_indices: Option<Vec<bool>>,
    // Public inputs
    credential_type_hash: Option<[u8; 32]>,
    merkle_root: Option<[u8; 32]>,
    issuer_pubkey_hash: Option<[u8; 32]>,
    nullifier: Option<[u8; 32]>,
    verifier_domain_hash: Option<[u8; 32]>,
    nonce: Option<[u8; 32]>,
}

impl CredentialWitnessBuilder {
    pub fn new() -> Self {
        Self {
            credential_type: None,
            credential_details_hash: None,
            salt: None,
            user_secret: None,
            merkle_proof: None,
            merkle_indices: None,
            credential_type_hash: None,
            merkle_root: None,
            issuer_pubkey_hash: None,
            nullifier: None,
            verifier_domain_hash: None,
            nonce: None,
        }
    }

    pub fn credential_type(mut self, ct: [u8; 32]) -> Self {
        self.credential_type = Some(ct);
        self
    }

    pub fn credential_details_hash(mut self, hash: [u8; 32]) -> Self {
        self.credential_details_hash = Some(hash);
        self
    }

    pub fn salt(mut self, salt: [u8; 32]) -> Self {
        self.salt = Some(salt);
        self
    }

    pub fn user_secret(mut self, secret: [u8; 32]) -> Self {
        self.user_secret = Some(secret);
        self
    }

    pub fn merkle_proof(mut self, proof: Vec<[u8; 32]>) -> Self {
        self.merkle_proof = Some(proof);
        self
    }

    pub fn merkle_indices(mut self, indices: Vec<bool>) -> Self {
        self.merkle_indices = Some(indices);
        self
    }

    pub fn credential_type_hash(mut self, hash: [u8; 32]) -> Self {
        self.credential_type_hash = Some(hash);
        self
    }

    pub fn merkle_root(mut self, root: [u8; 32]) -> Self {
        self.merkle_root = Some(root);
        self
    }

    pub fn issuer_pubkey_hash(mut self, hash: [u8; 32]) -> Self {
        self.issuer_pubkey_hash = Some(hash);
        self
    }

    pub fn nullifier(mut self, nullifier: [u8; 32]) -> Self {
        self.nullifier = Some(nullifier);
        self
    }

    pub fn verifier_domain_hash(mut self, hash: [u8; 32]) -> Self {
        self.verifier_domain_hash = Some(hash);
        self
    }

    pub fn nonce(mut self, nonce: [u8; 32]) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn build(self) -> Result<Witness, &'static str> {
        Ok(Witness {
            circuit_type: CircuitType::CredentialVerification,
            private_inputs: vec![
                WitnessValue::Field(self.credential_type.ok_or("credential_type required")?),
                WitnessValue::Field(
                    self.credential_details_hash
                        .ok_or("credential_details_hash required")?,
                ),
                WitnessValue::Field(self.salt.ok_or("salt required")?),
                WitnessValue::Field(self.user_secret.ok_or("user_secret required")?),
                WitnessValue::FieldArray(self.merkle_proof.ok_or("merkle_proof required")?),
                WitnessValue::BoolArray(self.merkle_indices.ok_or("merkle_indices required")?),
            ],
            public_inputs: vec![
                WitnessValue::Field(
                    self.credential_type_hash
                        .ok_or("credential_type_hash required")?,
                ),
                WitnessValue::Field(self.merkle_root.ok_or("merkle_root required")?),
                WitnessValue::Field(
                    self.issuer_pubkey_hash
                        .ok_or("issuer_pubkey_hash required")?,
                ),
                WitnessValue::Field(self.nullifier.ok_or("nullifier required")?),
                WitnessValue::Field(
                    self.verifier_domain_hash
                        .ok_or("verifier_domain_hash required")?,
                ),
                WitnessValue::Field(self.nonce.ok_or("nonce required")?),
            ],
        })
    }
}

impl Default for CredentialWitnessBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate witness from credential and claim
pub fn generate_witness(
    credential: &Credential,
    claim: &ClaimType,
    user_secret: &[u8; 32],
    verifier_domain: &str,
    nonce: &[u8; 32],
) -> Result<Witness, String> {
    match claim {
        ClaimType::AgeAtLeast { threshold } => {
            let birthdate = credential
                .birthdate()
                .ok_or("Credential has no birthdate")?;

            let now = chrono::Utc::now();
            let verification_date = now.year() as u32 * 10000 + now.month() * 100 + now.day();

            let builder = AgeVerificationWitnessBuilder::new()
                .birthdate(
                    birthdate.year() as u32 * 10000
                        + birthdate.month() as u32 * 100
                        + birthdate.day() as u32,
                )
                .salt(credential.commitment_salt)
                .signature_hash(sha3_256(&credential.signature.bytes))
                .threshold(*threshold)
                .verification_date(verification_date)
                .credential_commitment(credential.commitment)
                .issuer_pubkey_hash([0u8; 32]); // TODO: Get from issuer

            builder.build().map_err(|e| e.to_string())
        }

        ClaimType::KycStatus {
            level,
            max_age_seconds,
            ..
        } => {
            let (provider, kyc_level, verified_at, data_hash) = match &credential.credential_type {
                fantasma_core::credential::CredentialType::Kyc {
                    provider,
                    level,
                    verified_at,
                    data_hash,
                } => (provider, level, verified_at, data_hash),
                _ => return Err("Credential is not a KYC credential".to_string()),
            };

            let now = chrono::Utc::now();
            let current_ts = now.timestamp() as u64;
            let verification_ts = verified_at.timestamp() as u64;

            let provider_id_hash = sha3_256(provider.as_bytes());
            let user_id_hash = sha3_256(&credential.id.0);

            let builder = KycWitnessBuilder::new()
                .user_id_hash(user_id_hash)
                .kyc_provider_id(provider_id_hash)
                .kyc_level(kyc_level.as_u8())
                .verification_timestamp(verification_ts)
                .kyc_data_hash(*data_hash)
                .provider_signature_hash(sha3_256(&credential.signature.bytes))
                .salt(credential.commitment_salt)
                .expected_level(level.as_u8())
                .max_age_seconds(max_age_seconds.unwrap_or(31_536_000)) // Default 1 year
                .current_timestamp(current_ts)
                .provider_pubkey_hash([0u8; 32]) // TODO: Get from provider
                .kyc_commitment(credential.commitment);

            builder.build().map_err(|e| e.to_string())
        }

        ClaimType::HoldsCredential {
            credential_type, ..
        } => {
            let credential_type_bytes = sha3_256(credential_type.as_bytes());
            let verifier_domain_hash = sha3_256(verifier_domain.as_bytes());

            // Compute credential details hash from credential ID
            let credential_details_hash = sha3_256(&credential.id.0);

            // Compute nullifier: H(H(credential_leaf, user_secret), verifier_domain, nonce)
            let credential_leaf = sha3_256(
                &[
                    credential_type_bytes.as_slice(),
                    credential.commitment.as_slice(),
                ]
                .concat(),
            );
            let inner = sha3_256(&[credential_leaf.as_slice(), user_secret.as_slice()].concat());
            let domain_bound =
                sha3_256(&[inner.as_slice(), verifier_domain_hash.as_slice()].concat());
            let nullifier = sha3_256(&[domain_bound.as_slice(), nonce.as_slice()].concat());

            // For now, use single-element Merkle tree (leaf = root)
            // In production, this would be populated from the credential registry
            let merkle_root = credential_leaf;

            let builder = CredentialWitnessBuilder::new()
                .credential_type(credential_type_bytes)
                .credential_details_hash(credential_details_hash)
                .salt(credential.commitment_salt)
                .user_secret(*user_secret)
                .merkle_proof(vec![]) // Single-element tree
                .merkle_indices(vec![])
                .credential_type_hash(credential_type_bytes)
                .merkle_root(merkle_root)
                .issuer_pubkey_hash([0u8; 32]) // TODO: Get from issuer
                .nullifier(nullifier)
                .verifier_domain_hash(verifier_domain_hash)
                .nonce(*nonce);

            builder.build().map_err(|e| e.to_string())
        }

        ClaimType::SetMembership { .. } => {
            Err("SetMembership claim type not yet supported".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyc_witness_builder() {
        let witness = KycWitnessBuilder::new()
            .user_id_hash([1u8; 32])
            .kyc_provider_id([2u8; 32])
            .kyc_level(2)
            .verification_timestamp(1700000000)
            .kyc_data_hash([3u8; 32])
            .provider_signature_hash([4u8; 32])
            .salt([5u8; 32])
            .expected_level(1)
            .max_age_seconds(31_536_000)
            .current_timestamp(1705000000)
            .provider_pubkey_hash([6u8; 32])
            .kyc_commitment([7u8; 32])
            .build()
            .unwrap();

        assert_eq!(witness.circuit_type, CircuitType::KycVerification);
        assert_eq!(witness.private_inputs.len(), 7);
        assert_eq!(witness.public_inputs.len(), 5);
    }

    #[test]
    fn test_credential_witness_builder() {
        let witness = CredentialWitnessBuilder::new()
            .credential_type([1u8; 32])
            .credential_details_hash([2u8; 32])
            .salt([3u8; 32])
            .user_secret([4u8; 32])
            .merkle_proof(vec![])
            .merkle_indices(vec![])
            .credential_type_hash([1u8; 32])
            .merkle_root([5u8; 32])
            .issuer_pubkey_hash([6u8; 32])
            .nullifier([7u8; 32])
            .verifier_domain_hash([8u8; 32])
            .nonce([9u8; 32])
            .build()
            .unwrap();

        assert_eq!(witness.circuit_type, CircuitType::CredentialVerification);
        assert_eq!(witness.private_inputs.len(), 6);
        assert_eq!(witness.public_inputs.len(), 6);
    }

    #[test]
    fn test_kyc_witness_builder_missing_field() {
        let result = KycWitnessBuilder::new()
            .user_id_hash([1u8; 32])
            // Missing other required fields
            .build();

        assert!(result.is_err());
    }
}
