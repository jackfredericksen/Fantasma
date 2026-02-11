//! Database models for Fantasma

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// OAuth2 Client registration
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Client {
    pub id: Uuid,
    pub client_id: String,
    pub client_secret_hash: Option<Vec<u8>>,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub client_type: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// New client for insertion
#[derive(Debug, Clone)]
pub struct NewClient {
    pub client_id: String,
    pub client_secret_hash: Option<Vec<u8>>,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub client_type: String,
}

/// Authorization code for OAuth2 flow
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AuthCode {
    pub id: Uuid,
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub zk_claims: Option<serde_json::Value>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

/// New auth code for insertion
#[derive(Debug, Clone)]
pub struct NewAuthCode {
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub zk_claims: Option<serde_json::Value>,
    pub expires_at: DateTime<Utc>,
}

/// Refresh token
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: Uuid,
    pub token_hash: Vec<u8>,
    pub client_id: String,
    pub user_id: String,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// New refresh token for insertion
#[derive(Debug, Clone)]
pub struct NewRefreshToken {
    pub token_hash: Vec<u8>,
    pub client_id: String,
    pub user_id: String,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

/// Stored STARK proof
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct StoredProof {
    pub id: Uuid,
    pub proof_id: String,
    pub proof_hash: Vec<u8>,
    pub proof_data: Vec<u8>,
    pub circuit_type: String,
    pub public_inputs: serde_json::Value,
    pub verified: bool,
    pub user_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// New proof for insertion
#[derive(Debug, Clone)]
pub struct NewProof {
    pub proof_id: String,
    pub proof_hash: Vec<u8>,
    pub proof_data: Vec<u8>,
    pub circuit_type: String,
    pub public_inputs: serde_json::Value,
    pub verified: bool,
    pub user_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Nullifier for replay prevention
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Nullifier {
    pub id: Uuid,
    pub nullifier_hash: Vec<u8>,
    pub domain: String,
    pub circuit_type: String,
    pub used_at: DateTime<Utc>,
}

/// New nullifier for insertion
#[derive(Debug, Clone)]
pub struct NewNullifier {
    pub nullifier_hash: Vec<u8>,
    pub domain: String,
    pub circuit_type: String,
}

/// Encrypted credential storage
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct StoredCredential {
    pub id: Uuid,
    pub credential_id: Vec<u8>,
    pub user_id: String,
    pub issuer_id: String,
    pub schema_id: String,
    pub credential_type: String,
    pub encrypted_data: Vec<u8>,
    pub encryption_nonce: Vec<u8>,
    pub commitment: Vec<u8>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// New credential for insertion
#[derive(Debug, Clone)]
pub struct NewCredential {
    pub credential_id: Vec<u8>,
    pub user_id: String,
    pub issuer_id: String,
    pub schema_id: String,
    pub credential_type: String,
    pub encrypted_data: Vec<u8>,
    pub encryption_nonce: Vec<u8>,
    pub commitment: Vec<u8>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Trusted issuer
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Issuer {
    pub id: Uuid,
    pub issuer_id: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub public_key_algorithm: String,
    pub verification_url: Option<String>,
    pub trusted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// New issuer for insertion
#[derive(Debug, Clone)]
pub struct NewIssuer {
    pub issuer_id: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub public_key_algorithm: String,
    pub verification_url: Option<String>,
    pub trusted: bool,
}

/// Audit log entry
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub event_type: String,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// New audit log entry
#[derive(Debug, Clone)]
pub struct NewAuditLogEntry {
    pub event_type: String,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}
