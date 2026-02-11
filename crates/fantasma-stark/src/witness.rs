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

/// Generate witness from credential and claim
pub fn generate_witness(
    credential: &Credential,
    claim: &ClaimType,
    _user_secret: &[u8; 32],
    _verifier_domain: &str,
    _nonce: &[u8; 32],
) -> Result<Witness, String> {
    match claim {
        ClaimType::AgeAtLeast { threshold } => {
            let birthdate = credential
                .birthdate()
                .ok_or("Credential has no birthdate")?;

            // Get current date in YYYYMMDD format
            let now = chrono::Utc::now();
            let verification_date =
                now.year() as u32 * 10000 + now.month() * 100 + now.day();

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
        _ => Err("Unsupported claim type".to_string()),
    }
}
