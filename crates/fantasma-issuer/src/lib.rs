//! Fantasma Issuer
//!
//! Credential issuance service.

use chrono::{NaiveDate, Utc};
use fantasma_core::claim::KycLevel;
use fantasma_core::credential::{
    Credential, CredentialId, CredentialType, IssuerSignature, SchemaId, SignatureAlgorithm,
};
use fantasma_core::issuer::{IssuerId, IssuerInfo, TrustAnchor};
use fantasma_crypto::dilithium::DilithiumKeypair;
use fantasma_crypto::hash::{poseidon_hash_pair, sha3_256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IssuerError {
    #[error("Invalid attribute: {0}")]
    InvalidAttribute(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Invalid credential request")]
    InvalidRequest,
}

/// Credential issuer service
pub struct Issuer {
    /// Issuer information
    pub info: IssuerInfo,

    /// Signing keypair
    keypair: DilithiumKeypair,
}

impl Issuer {
    /// Create a new issuer
    pub fn new(id: impl Into<String>, name: impl Into<String>, trust_anchor: TrustAnchor) -> Self {
        let keypair = DilithiumKeypair::generate();
        let public_key = keypair.public_key.as_bytes().to_vec();

        let info = IssuerInfo {
            id: IssuerId::new(id),
            name: name.into(),
            public_key,
            trust_anchor,
            metadata_url: None,
            status_url: None,
            supported_schemas: vec![
                SchemaId::IDENTITY_V1.to_string(),
                SchemaId::DEGREE_V1.to_string(),
                SchemaId::LICENSE_V1.to_string(),
                SchemaId::MEMBERSHIP_V1.to_string(),
                SchemaId::KYC_V1.to_string(),
            ],
        };

        Self { info, keypair }
    }

    /// Issue an identity credential
    pub fn issue_identity(
        &self,
        birthdate: NaiveDate,
        identity_hash: [u8; 32],
    ) -> Result<Credential, IssuerError> {
        let credential_type = CredentialType::Identity {
            birthdate,
            identity_hash,
        };

        self.issue_credential(credential_type, SchemaId::new(SchemaId::IDENTITY_V1))
    }

    /// Issue a degree credential
    pub fn issue_degree(
        &self,
        institution: String,
        degree_type: String,
        field_of_study: String,
        graduation_date: NaiveDate,
    ) -> Result<Credential, IssuerError> {
        let credential_type = CredentialType::Degree {
            institution,
            degree_type,
            field_of_study,
            graduation_date,
        };

        self.issue_credential(credential_type, SchemaId::new(SchemaId::DEGREE_V1))
    }

    /// Issue a KYC credential
    pub fn issue_kyc(
        &self,
        provider: String,
        level: KycLevel,
        data_hash: [u8; 32],
    ) -> Result<Credential, IssuerError> {
        let credential_type = CredentialType::Kyc {
            provider,
            level,
            verified_at: Utc::now(),
            data_hash,
        };

        self.issue_credential(credential_type, SchemaId::new(SchemaId::KYC_V1))
    }

    /// Issue a generic credential
    fn issue_credential(
        &self,
        credential_type: CredentialType,
        schema: SchemaId,
    ) -> Result<Credential, IssuerError> {
        use rand::RngCore;

        // Generate commitment salt
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        // Compute credential data hash
        let data_hash = sha3_256(&serde_json::to_vec(&credential_type).unwrap());

        // Compute commitment
        let commitment = poseidon_hash_pair(&data_hash, &salt);

        // Compute credential ID
        let id_input = sha3_256(&commitment);
        let id = CredentialId::from_bytes(id_input);

        // Sign the commitment
        let signature_bytes = self.keypair.sign(&commitment);
        let signature = IssuerSignature {
            bytes: signature_bytes.as_bytes().to_vec(),
            algorithm: SignatureAlgorithm::Dilithium3,
        };

        let now = Utc::now();

        Ok(Credential {
            id,
            issuer: self.info.id.clone(),
            schema,
            credential_type,
            commitment_salt: salt,
            commitment,
            signature,
            issued_at: now,
            expires_at: Some(now + chrono::Duration::days(365)), // 1 year validity
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_identity() {
        let issuer = Issuer::new(
            "test-issuer",
            "Test Issuer",
            TrustAnchor::SelfDeclared {
                domain: "test.example".to_string(),
            },
        );

        let birthdate = NaiveDate::from_ymd_opt(2000, 1, 1).unwrap();
        let credential = issuer.issue_identity(birthdate, [0u8; 32]).unwrap();

        assert!(!credential.is_expired());
        assert_eq!(credential.birthdate(), Some(birthdate));
    }

    #[test]
    fn test_issue_kyc() {
        let issuer = Issuer::new(
            "kyc-provider",
            "KYC Provider",
            TrustAnchor::Accredited {
                accreditor: "FinReg".to_string(),
                accreditation_id: None,
            },
        );

        let credential = issuer
            .issue_kyc("Provider".to_string(), KycLevel::Enhanced, [0u8; 32])
            .unwrap();

        assert_eq!(credential.kyc_level(), Some(KycLevel::Enhanced));
    }
}
