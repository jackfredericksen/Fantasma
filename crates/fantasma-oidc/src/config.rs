//! OIDC provider configuration

use serde::{Deserialize, Serialize};

/// OIDC provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// Issuer URL (e.g., "https://fantasma.example")
    pub issuer: String,

    /// Authorization endpoint path
    pub authorization_endpoint: String,

    /// Token endpoint path
    pub token_endpoint: String,

    /// UserInfo endpoint path
    pub userinfo_endpoint: String,

    /// JWKS endpoint path
    pub jwks_endpoint: String,

    /// Proof storage endpoint
    pub proof_storage_endpoint: String,

    /// Token expiration in seconds
    pub token_expiration_seconds: u64,

    /// Authorization code expiration in seconds
    pub auth_code_expiration_seconds: u64,

    /// Supported scopes
    pub supported_scopes: Vec<String>,

    /// Supported response types
    pub supported_response_types: Vec<String>,

    /// Supported grant types
    pub supported_grant_types: Vec<String>,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer: "https://fantasma.example".to_string(),
            authorization_endpoint: "/authorize".to_string(),
            token_endpoint: "/token".to_string(),
            userinfo_endpoint: "/userinfo".to_string(),
            jwks_endpoint: "/.well-known/jwks.json".to_string(),
            proof_storage_endpoint: "/proofs".to_string(),
            token_expiration_seconds: 3600,
            auth_code_expiration_seconds: 600,
            supported_scopes: vec![
                "openid".to_string(),
                "zk:age:18+".to_string(),
                "zk:age:21+".to_string(),
                "zk:credential".to_string(),
                "zk:credential:degree".to_string(),
                "zk:credential:license".to_string(),
                "zk:kyc:basic".to_string(),
                "zk:kyc:enhanced".to_string(),
                "zk:kyc:accredited".to_string(),
            ],
            supported_response_types: vec!["code".to_string()],
            supported_grant_types: vec!["authorization_code".to_string()],
        }
    }
}

impl OidcConfig {
    /// Create a new config with a custom issuer
    pub fn with_issuer(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            ..Default::default()
        }
    }

    /// Get the full URL for an endpoint
    pub fn endpoint_url(&self, path: &str) -> String {
        format!("{}{}", self.issuer, path)
    }
}
