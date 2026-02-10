//! OIDC Discovery document

use crate::config::OidcConfig;
use serde::{Deserialize, Serialize};

/// OIDC Discovery document (OpenID Provider Configuration)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    /// Issuer identifier
    pub issuer: String,

    /// Authorization endpoint URL
    pub authorization_endpoint: String,

    /// Token endpoint URL
    pub token_endpoint: String,

    /// UserInfo endpoint URL
    pub userinfo_endpoint: String,

    /// JWKS URI
    pub jwks_uri: String,

    /// Supported scopes
    pub scopes_supported: Vec<String>,

    /// Supported response types
    pub response_types_supported: Vec<String>,

    /// Supported grant types
    pub grant_types_supported: Vec<String>,

    /// Supported subject types
    pub subject_types_supported: Vec<String>,

    /// Supported ID token signing algorithms
    pub id_token_signing_alg_values_supported: Vec<String>,

    /// Supported claims
    pub claims_supported: Vec<String>,

    /// Code challenge methods supported
    pub code_challenge_methods_supported: Vec<String>,

    /// ZK circuit information
    pub zk_circuits: ZkCircuitInfo,
}

/// Information about available ZK circuits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkCircuitInfo {
    pub age_verification_v1: CircuitMetadata,
    pub credential_verification_v1: CircuitMetadata,
    pub kyc_verification_v1: CircuitMetadata,
}

/// Metadata for a ZK circuit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitMetadata {
    /// Human-readable description
    pub description: String,

    /// Hash of the circuit bytecode
    pub bytecode_hash: String,

    /// Hash of the verification key
    pub verification_key_hash: String,
}

impl DiscoveryDocument {
    /// Create a discovery document from config
    pub fn from_config(config: &OidcConfig) -> Self {
        Self {
            issuer: config.issuer.clone(),
            authorization_endpoint: config.endpoint_url(&config.authorization_endpoint),
            token_endpoint: config.endpoint_url(&config.token_endpoint),
            userinfo_endpoint: config.endpoint_url(&config.userinfo_endpoint),
            jwks_uri: config.endpoint_url(&config.jwks_endpoint),
            scopes_supported: config.supported_scopes.clone(),
            response_types_supported: config.supported_response_types.clone(),
            grant_types_supported: config.supported_grant_types.clone(),
            subject_types_supported: vec!["pairwise".to_string()],
            id_token_signing_alg_values_supported: vec![
                "HS256".to_string(), // For demo
                "EdDSA".to_string(), // Classical
                // In future: "MLDSA65".to_string(), // Dilithium
            ],
            claims_supported: vec![
                "sub".to_string(),
                "iss".to_string(),
                "aud".to_string(),
                "exp".to_string(),
                "iat".to_string(),
                "nonce".to_string(),
                "auth_time".to_string(),
                "zk_age_claim".to_string(),
                "zk_credential_claim".to_string(),
                "zk_kyc_claim".to_string(),
            ],
            code_challenge_methods_supported: vec!["S256".to_string()],
            zk_circuits: ZkCircuitInfo {
                age_verification_v1: CircuitMetadata {
                    description: "Proves age >= threshold without revealing birthdate".to_string(),
                    bytecode_hash: "0x...".to_string(), // Set after compilation
                    verification_key_hash: "0x...".to_string(),
                },
                credential_verification_v1: CircuitMetadata {
                    description: "Proves credential possession without revealing details".to_string(),
                    bytecode_hash: "0x...".to_string(),
                    verification_key_hash: "0x...".to_string(),
                },
                kyc_verification_v1: CircuitMetadata {
                    description: "Proves KYC status without revealing personal data".to_string(),
                    bytecode_hash: "0x...".to_string(),
                    verification_key_hash: "0x...".to_string(),
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_document() {
        let config = OidcConfig::with_issuer("https://fantasma.example");
        let doc = DiscoveryDocument::from_config(&config);

        assert_eq!(doc.issuer, "https://fantasma.example");
        assert!(doc.scopes_supported.contains(&"openid".to_string()));
        assert!(doc.scopes_supported.contains(&"zk:age:18+".to_string()));
    }
}
