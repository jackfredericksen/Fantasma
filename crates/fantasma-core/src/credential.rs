//! Credential types for Fantasma
//!
//! Credentials are signed attestations from issuers containing user attributes.
//! They form the basis for zero-knowledge proofs.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::issuer::IssuerId;

/// Unique identifier for a credential (32-byte hash)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialId(pub [u8; 32]);

impl CredentialId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for CredentialId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Schema identifier for credential structure
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SchemaId(pub String);

impl SchemaId {
    pub const IDENTITY_V1: &'static str = "fantasma:identity:v1";
    pub const DEGREE_V1: &'static str = "fantasma:degree:v1";
    pub const LICENSE_V1: &'static str = "fantasma:license:v1";
    pub const MEMBERSHIP_V1: &'static str = "fantasma:membership:v1";
    pub const KYC_V1: &'static str = "fantasma:kyc:v1";

    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

/// Attribute values that can be stored in credentials
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub enum AttributeValue {
    /// Date value (used for birthdates, graduation dates, etc.)
    Date(NaiveDate),

    /// Numeric value (age thresholds, levels, etc.)
    Number(u64),

    /// String value (names, identifiers, etc.)
    String(String),

    /// Boolean flag (KYC passed, membership active, etc.)
    Boolean(bool),

    /// Hash of arbitrary data (for privacy-preserving storage)
    Hash([u8; 32]),
}

impl AttributeValue {
    /// Convert date to u32 in YYYYMMDD format for circuit compatibility
    pub fn date_to_circuit_format(date: &NaiveDate) -> u32 {
        let year = date.year() as u32;
        let month = date.month();
        let day = date.day();
        year * 10000 + month * 100 + day
    }
}

/// Type of credential being stored
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialType {
    /// Identity credential with birthdate for age verification
    Identity {
        birthdate: NaiveDate,
        /// Hash of full identity data (name, address, etc.)
        identity_hash: [u8; 32],
    },

    /// Academic degree credential
    Degree {
        institution: String,
        degree_type: String,
        field_of_study: String,
        graduation_date: NaiveDate,
    },

    /// Professional license credential
    License {
        license_type: String,
        jurisdiction: String,
        /// Hash of license number for privacy
        license_number_hash: [u8; 32],
        issued_date: NaiveDate,
        expiry_date: Option<NaiveDate>,
    },

    /// Membership credential
    Membership {
        organization: String,
        membership_type: String,
        member_since: NaiveDate,
        expires: Option<NaiveDate>,
    },

    /// KYC/AML verification credential
    Kyc {
        provider: String,
        level: crate::claim::KycLevel,
        verified_at: DateTime<Utc>,
        /// Hash of KYC data
        data_hash: [u8; 32],
    },
}

/// Signature from issuer (Dilithium signature)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerSignature {
    /// The signature bytes (Dilithium signatures are ~2.4 KB)
    pub bytes: Vec<u8>,
    /// Algorithm identifier
    pub algorithm: SignatureAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// Dilithium level 3 (NIST security level 3)
    Dilithium3,
    /// Dilithium level 5 (NIST security level 5)
    Dilithium5,
}

/// A signed credential from an issuer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Unique credential identifier (hash of contents)
    pub id: CredentialId,

    /// The issuer's identifier
    pub issuer: IssuerId,

    /// Schema defining the credential structure
    pub schema: SchemaId,

    /// The credential type and its attributes
    pub credential_type: CredentialType,

    /// Salt used for Pedersen/Poseidon commitment
    #[serde(with = "hex_bytes")]
    pub commitment_salt: [u8; 32],

    /// Pre-computed commitment for quick verification
    #[serde(with = "hex_bytes")]
    pub commitment: [u8; 32],

    /// Issuer's signature over the credential
    pub signature: IssuerSignature,

    /// When the credential was issued
    pub issued_at: DateTime<Utc>,

    /// Optional expiration time
    pub expires_at: Option<DateTime<Utc>>,
}

impl Credential {
    /// Check if the credential has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }

    /// Get the birthdate if this is an identity credential
    pub fn birthdate(&self) -> Option<NaiveDate> {
        match &self.credential_type {
            CredentialType::Identity { birthdate, .. } => Some(*birthdate),
            _ => None,
        }
    }

    /// Get the KYC level if this is a KYC credential
    pub fn kyc_level(&self) -> Option<crate::claim::KycLevel> {
        match &self.credential_type {
            CredentialType::Kyc { level, .. } => Some(*level),
            _ => None,
        }
    }
}

/// Hex serialization for byte arrays
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid byte length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_date_to_circuit_format() {
        let date = NaiveDate::from_ymd_opt(1990, 5, 15).unwrap();
        assert_eq!(AttributeValue::date_to_circuit_format(&date), 19900515);

        let date2 = NaiveDate::from_ymd_opt(2000, 12, 31).unwrap();
        assert_eq!(AttributeValue::date_to_circuit_format(&date2), 20001231);
    }
}
