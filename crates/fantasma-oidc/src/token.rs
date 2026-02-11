//! ID token generation and validation

use crate::claims::ZkClaims;
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("Token encoding failed: {0}")]
    EncodingFailed(String),

    #[error("Token decoding failed: {0}")]
    DecodingFailed(String),

    #[error("Token expired")]
    Expired,

    #[error("Invalid issuer")]
    InvalidIssuer,

    #[error("Invalid audience")]
    InvalidAudience,
}

/// Standard OIDC ID token claims plus ZK claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer (iss)
    pub iss: String,

    /// Subject (sub) - pseudonymous identifier
    pub sub: String,

    /// Audience (aud) - client ID
    pub aud: String,

    /// Expiration time (exp)
    pub exp: u64,

    /// Issued at (iat)
    pub iat: u64,

    /// Nonce (if provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Auth time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<u64>,

    /// ZK claims
    #[serde(flatten)]
    pub zk_claims: ZkClaims,
}

impl IdTokenClaims {
    /// Create new ID token claims
    pub fn new(
        issuer: impl Into<String>,
        subject: impl Into<String>,
        audience: impl Into<String>,
        expiration_seconds: u64,
    ) -> Self {
        let now = Utc::now().timestamp() as u64;
        Self {
            iss: issuer.into(),
            sub: subject.into(),
            aud: audience.into(),
            exp: now + expiration_seconds,
            iat: now,
            nonce: None,
            auth_time: Some(now),
            zk_claims: ZkClaims::new(),
        }
    }

    /// Set the nonce
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Set the ZK claims
    pub fn with_zk_claims(mut self, claims: ZkClaims) -> Self {
        self.zk_claims = claims;
        self
    }

    /// Check if the token has expired
    pub fn is_expired(&self) -> bool {
        let now = Utc::now().timestamp() as u64;
        now > self.exp
    }
}

/// A signed ID token
#[derive(Debug, Clone)]
pub struct IdToken {
    /// The encoded JWT string
    pub token: String,

    /// The claims (decoded)
    pub claims: IdTokenClaims,
}

impl IdToken {
    /// Create and sign a new ID token
    ///
    /// Note: In production, this should use Dilithium signatures for PQ security.
    /// For OIDC compatibility, we also support Ed25519/RS256 for JWT signing.
    pub fn create(claims: IdTokenClaims, signing_key: &[u8]) -> Result<Self, TokenError> {
        let header = Header::new(Algorithm::HS256); // Simplified for demo

        let encoding_key = EncodingKey::from_secret(signing_key);

        let token = encode(&header, &claims, &encoding_key)
            .map_err(|e| TokenError::EncodingFailed(e.to_string()))?;

        Ok(Self { token, claims })
    }

    /// Get the token string
    pub fn as_str(&self) -> &str {
        &self.token
    }
}

/// Token response for the token endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// Access token
    pub access_token: String,

    /// Token type (always "Bearer")
    pub token_type: String,

    /// Expires in (seconds)
    pub expires_in: u64,

    /// ID token
    pub id_token: String,

    /// Refresh token (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl TokenResponse {
    /// Create a new token response
    pub fn new(access_token: String, id_token: String, expires_in: u64) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in,
            id_token,
            refresh_token: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_token_creation() {
        let claims = IdTokenClaims::new("https://fantasma.example", "zkid:123", "client_abc", 3600)
            .with_nonce("nonce123");

        let signing_key = b"test_signing_key_32_bytes_long!";
        let token = IdToken::create(claims.clone(), signing_key).unwrap();

        assert!(!token.token.is_empty());
        assert_eq!(token.claims.iss, "https://fantasma.example");
        assert_eq!(token.claims.nonce, Some("nonce123".to_string()));
    }
}
