//! Seed data for development and testing
//!
//! Provides demo credentials and test users for local development.

use chrono::{NaiveDate, Utc};
use fantasma_core::claim::KycLevel;
use fantasma_core::credential::{
    Credential, CredentialId, CredentialType, IssuerSignature, SchemaId, SignatureAlgorithm,
};
use fantasma_core::issuer::{IssuerId, IssuerInfo, TrustAnchor};
use serde::{Deserialize, Serialize};

/// Demo user with pre-generated credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoUser {
    pub id: String,
    pub name: String,
    pub email: String,
    pub credentials: Vec<Credential>,
}

/// Demo issuer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoIssuer {
    pub info: IssuerInfo,
}

/// All seed data for the demo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedData {
    pub users: Vec<DemoUser>,
    pub issuers: Vec<DemoIssuer>,
}

impl SeedData {
    /// Generate seed data for development
    pub fn generate() -> Self {
        let issuers = Self::create_issuers();
        let users = Self::create_users(&issuers);

        Self { users, issuers }
    }

    fn create_issuers() -> Vec<DemoIssuer> {
        vec![
            DemoIssuer {
                info: IssuerInfo {
                    id: IssuerId::new("gov-identity"),
                    name: "Government Identity Authority".to_string(),
                    public_key: vec![0u8; 32], // Placeholder
                    trust_anchor: TrustAnchor::Government {
                        country: "US".to_string(),
                        department: Some("DHS".to_string()),
                    },
                    metadata_url: None,
                    status_url: None,
                    supported_schemas: vec![SchemaId::IDENTITY_V1.to_string()],
                },
            },
            DemoIssuer {
                info: IssuerInfo {
                    id: IssuerId::new("acme-kyc"),
                    name: "ACME KYC Services".to_string(),
                    public_key: vec![0u8; 32],
                    trust_anchor: TrustAnchor::Accredited {
                        accreditor: "FinCEN".to_string(),
                        accreditation_id: Some("KYC-2024-001".to_string()),
                    },
                    metadata_url: None,
                    status_url: None,
                    supported_schemas: vec![SchemaId::KYC_V1.to_string()],
                },
            },
            DemoIssuer {
                info: IssuerInfo {
                    id: IssuerId::new("state-university"),
                    name: "State University".to_string(),
                    public_key: vec![0u8; 32],
                    trust_anchor: TrustAnchor::SelfDeclared {
                        domain: "stateuniversity.edu".to_string(),
                    },
                    metadata_url: None,
                    status_url: None,
                    supported_schemas: vec![SchemaId::DEGREE_V1.to_string()],
                },
            },
        ]
    }

    fn create_users(issuers: &[DemoIssuer]) -> Vec<DemoUser> {
        let gov_issuer = &issuers[0].info.id;
        let kyc_issuer = &issuers[1].info.id;
        let uni_issuer = &issuers[2].info.id;

        vec![
            // Alice: Over 21, has all credentials
            DemoUser {
                id: "alice".to_string(),
                name: "Alice Anderson".to_string(),
                email: "alice@example.com".to_string(),
                credentials: vec![
                    Self::create_identity_credential(
                        gov_issuer,
                        NaiveDate::from_ymd_opt(1990, 5, 15).unwrap(),
                    ),
                    Self::create_kyc_credential(kyc_issuer, KycLevel::Enhanced),
                    Self::create_degree_credential(
                        uni_issuer,
                        "State University",
                        "Bachelor of Science",
                        "Computer Science",
                        NaiveDate::from_ymd_opt(2012, 5, 20).unwrap(),
                    ),
                ],
            },
            // Bob: Between 18 and 21
            DemoUser {
                id: "bob".to_string(),
                name: "Bob Brown".to_string(),
                email: "bob@example.com".to_string(),
                credentials: vec![
                    Self::create_identity_credential(
                        gov_issuer,
                        NaiveDate::from_ymd_opt(2005, 8, 22).unwrap(),
                    ),
                    Self::create_kyc_credential(kyc_issuer, KycLevel::Basic),
                ],
            },
            // Carol: Under 18 (for testing rejection)
            DemoUser {
                id: "carol".to_string(),
                name: "Carol Chen".to_string(),
                email: "carol@example.com".to_string(),
                credentials: vec![Self::create_identity_credential(
                    gov_issuer,
                    NaiveDate::from_ymd_opt(2010, 3, 10).unwrap(),
                )],
            },
            // Dave: Accredited investor
            DemoUser {
                id: "dave".to_string(),
                name: "Dave Davis".to_string(),
                email: "dave@example.com".to_string(),
                credentials: vec![
                    Self::create_identity_credential(
                        gov_issuer,
                        NaiveDate::from_ymd_opt(1975, 11, 30).unwrap(),
                    ),
                    Self::create_kyc_credential(kyc_issuer, KycLevel::Accredited),
                ],
            },
        ]
    }

    fn create_identity_credential(issuer: &IssuerId, birthdate: NaiveDate) -> Credential {
        let salt = random_bytes();
        let commitment = random_bytes();
        let id = CredentialId::from_bytes(random_bytes());

        Credential {
            id,
            issuer: issuer.clone(),
            schema: SchemaId::new(SchemaId::IDENTITY_V1),
            credential_type: CredentialType::Identity {
                birthdate,
                identity_hash: random_bytes(),
            },
            commitment_salt: salt,
            commitment,
            signature: placeholder_signature(),
            issued_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
        }
    }

    fn create_kyc_credential(issuer: &IssuerId, level: KycLevel) -> Credential {
        let salt = random_bytes();
        let commitment = random_bytes();
        let id = CredentialId::from_bytes(random_bytes());

        Credential {
            id,
            issuer: issuer.clone(),
            schema: SchemaId::new(SchemaId::KYC_V1),
            credential_type: CredentialType::Kyc {
                provider: "ACME KYC".to_string(),
                level,
                verified_at: Utc::now(),
                data_hash: random_bytes(),
            },
            commitment_salt: salt,
            commitment,
            signature: placeholder_signature(),
            issued_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
        }
    }

    fn create_degree_credential(
        issuer: &IssuerId,
        institution: &str,
        degree_type: &str,
        field: &str,
        graduation_date: NaiveDate,
    ) -> Credential {
        let salt = random_bytes();
        let commitment = random_bytes();
        let id = CredentialId::from_bytes(random_bytes());

        Credential {
            id,
            issuer: issuer.clone(),
            schema: SchemaId::new(SchemaId::DEGREE_V1),
            credential_type: CredentialType::Degree {
                institution: institution.to_string(),
                degree_type: degree_type.to_string(),
                field_of_study: field.to_string(),
                graduation_date,
            },
            commitment_salt: salt,
            commitment,
            signature: placeholder_signature(),
            issued_at: Utc::now(),
            expires_at: None, // Degrees don't expire
        }
    }
}

fn random_bytes() -> [u8; 32] {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn placeholder_signature() -> IssuerSignature {
    IssuerSignature {
        bytes: vec![0u8; 2420], // Dilithium3 signature size
        algorithm: SignatureAlgorithm::Dilithium3,
    }
}

/// Export seed data as JSON (for wallet extension)
pub fn export_seed_data_json() -> String {
    let data = SeedData::generate();
    serde_json::to_string_pretty(&data).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn test_seed_data_generation() {
        let data = SeedData::generate();
        assert_eq!(data.users.len(), 4);
        assert_eq!(data.issuers.len(), 3);

        // Alice should have 3 credentials
        let alice = &data.users[0];
        assert_eq!(alice.credentials.len(), 3);

        // Bob should be between 18-21
        let bob = &data.users[1];
        let birthdate = bob.credentials[0].birthdate().unwrap();
        assert!(birthdate.year() >= 2003 && birthdate.year() <= 2007);
    }
}
