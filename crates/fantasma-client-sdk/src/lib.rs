//! Fantasma Client SDK
//!
//! SDK for relying parties to integrate with Fantasma.

use fantasma_core::proof::ProofRef;
use fantasma_oidc::claims::{ZkAgeClaim, ZkCredentialClaim, ZkKycClaim};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Proof not found")]
    ProofNotFound,
}

/// Fantasma client for relying parties
pub struct FantasmaClient {
    /// Issuer URL
    issuer_url: String,

    /// HTTP client
    client: reqwest::Client,
}

impl FantasmaClient {
    /// Create a new client
    pub fn new(issuer_url: impl Into<String>) -> Self {
        Self {
            issuer_url: issuer_url.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Get the discovery document
    pub async fn discover(&self) -> Result<fantasma_oidc::DiscoveryDocument, ClientError> {
        let url = format!("{}/.well-known/openid-configuration", self.issuer_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;

        response
            .json()
            .await
            .map_err(|e| ClientError::InvalidResponse(e.to_string()))
    }

    /// Fetch a proof by reference
    pub async fn fetch_proof(&self, proof_ref: &ProofRef) -> Result<Vec<u8>, ClientError> {
        let url = proof_ref.url.as_ref().ok_or(ClientError::ProofNotFound)?;

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;

        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| ClientError::InvalidResponse(e.to_string()))
    }

    /// Verify an age claim from an ID token
    pub fn verify_age_claim(&self, claim: &ZkAgeClaim, min_threshold: u8) -> bool {
        claim.verified && claim.threshold >= min_threshold
    }

    /// Verify a credential claim from an ID token
    pub fn verify_credential_claim(
        &self,
        claim: &ZkCredentialClaim,
        expected_type: Option<&str>,
    ) -> bool {
        if !claim.verified {
            return false;
        }

        match expected_type {
            Some(t) => claim.credential_type == t,
            None => true,
        }
    }

    /// Verify a KYC claim from an ID token
    pub fn verify_kyc_claim(
        &self,
        claim: &ZkKycClaim,
        min_level: fantasma_core::claim::KycLevel,
    ) -> bool {
        claim.verified && claim.level >= min_level
    }
}

/// Helper to build authorization URLs
pub struct AuthorizationUrlBuilder {
    base_url: String,
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
}

impl AuthorizationUrlBuilder {
    pub fn new(
        authorization_endpoint: impl Into<String>,
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            base_url: authorization_endpoint.into(),
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            scopes: vec!["openid".to_string()],
            state: None,
            nonce: None,
            code_challenge: None,
        }
    }

    /// Add a scope
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// Add age verification scope
    pub fn require_age(self, threshold: u8) -> Self {
        self.scope(format!("zk:age:{}+", threshold))
    }

    /// Add KYC verification scope
    pub fn require_kyc(self, level: &str) -> Self {
        self.scope(format!("zk:kyc:{}", level))
    }

    /// Set state parameter
    pub fn state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    /// Set nonce parameter
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Set PKCE code challenge
    pub fn code_challenge(mut self, challenge: impl Into<String>) -> Self {
        self.code_challenge = Some(challenge.into());
        self
    }

    /// Build the authorization URL
    pub fn build(self) -> String {
        let mut url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}",
            self.base_url,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.redirect_uri),
            urlencoding::encode(&self.scopes.join(" ")),
        );

        if let Some(state) = self.state {
            url.push_str(&format!("&state={}", urlencoding::encode(&state)));
        }

        if let Some(nonce) = self.nonce {
            url.push_str(&format!("&nonce={}", urlencoding::encode(&nonce)));
        }

        if let Some(challenge) = self.code_challenge {
            url.push_str(&format!(
                "&code_challenge={}&code_challenge_method=S256",
                urlencoding::encode(&challenge)
            ));
        }

        url
    }
}

// Add urlencoding as a simple module
mod urlencoding {
    pub fn encode(s: &str) -> String {
        url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
    }
}
