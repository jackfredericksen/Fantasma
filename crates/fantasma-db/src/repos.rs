//! Repository implementations for database operations

use sqlx::PgPool;

use crate::models::*;
use crate::{DbError, Result};

/// Repository for OAuth2 clients
pub struct ClientRepo {
    pool: PgPool,
}

impl ClientRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, client: NewClient) -> Result<Client> {
        let result = sqlx::query_as::<_, Client>(
            r#"
            INSERT INTO clients (client_id, client_secret_hash, client_name, redirect_uris, allowed_scopes, client_type)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(&client.client_id)
        .bind(&client.client_secret_hash)
        .bind(&client.client_name)
        .bind(&client.redirect_uris)
        .bind(&client.allowed_scopes)
        .bind(&client.client_type)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn find_by_client_id(&self, client_id: &str) -> Result<Option<Client>> {
        let result = sqlx::query_as::<_, Client>(
            "SELECT * FROM clients WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn list(&self) -> Result<Vec<Client>> {
        let results = sqlx::query_as::<_, Client>("SELECT * FROM clients ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?;

        Ok(results)
    }
}

/// Repository for authorization codes
pub struct AuthCodeRepo {
    pool: PgPool,
}

impl AuthCodeRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, auth_code: NewAuthCode) -> Result<AuthCode> {
        let result = sqlx::query_as::<_, AuthCode>(
            r#"
            INSERT INTO auth_codes (code, client_id, user_id, redirect_uri, scopes, nonce, state,
                                   code_challenge, code_challenge_method, zk_claims, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
        )
        .bind(&auth_code.code)
        .bind(&auth_code.client_id)
        .bind(&auth_code.user_id)
        .bind(&auth_code.redirect_uri)
        .bind(&auth_code.scopes)
        .bind(&auth_code.nonce)
        .bind(&auth_code.state)
        .bind(&auth_code.code_challenge)
        .bind(&auth_code.code_challenge_method)
        .bind(&auth_code.zk_claims)
        .bind(&auth_code.expires_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn find_by_code(&self, code: &str) -> Result<Option<AuthCode>> {
        let result = sqlx::query_as::<_, AuthCode>(
            "SELECT * FROM auth_codes WHERE code = $1 AND used_at IS NULL AND expires_at > NOW()",
        )
        .bind(code)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn mark_used(&self, code: &str) -> Result<()> {
        sqlx::query("UPDATE auth_codes SET used_at = NOW() WHERE code = $1")
            .bind(code)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn cleanup_expired(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM auth_codes WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}

/// Repository for STARK proofs
pub struct ProofRepo {
    pool: PgPool,
}

impl ProofRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, proof: NewProof) -> Result<StoredProof> {
        let result = sqlx::query_as::<_, StoredProof>(
            r#"
            INSERT INTO proofs (proof_id, proof_hash, proof_data, circuit_type, public_inputs, verified, user_id, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(&proof.proof_id)
        .bind(&proof.proof_hash)
        .bind(&proof.proof_data)
        .bind(&proof.circuit_type)
        .bind(&proof.public_inputs)
        .bind(proof.verified)
        .bind(&proof.user_id)
        .bind(&proof.expires_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn find_by_proof_id(&self, proof_id: &str) -> Result<Option<StoredProof>> {
        let result = sqlx::query_as::<_, StoredProof>(
            "SELECT * FROM proofs WHERE proof_id = $1",
        )
        .bind(proof_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn find_by_hash(&self, proof_hash: &[u8]) -> Result<Option<StoredProof>> {
        let result = sqlx::query_as::<_, StoredProof>(
            "SELECT * FROM proofs WHERE proof_hash = $1",
        )
        .bind(proof_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn mark_verified(&self, proof_id: &str) -> Result<()> {
        sqlx::query("UPDATE proofs SET verified = true WHERE proof_id = $1")
            .bind(proof_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn list_by_user(&self, user_id: &str) -> Result<Vec<StoredProof>> {
        let results = sqlx::query_as::<_, StoredProof>(
            "SELECT * FROM proofs WHERE user_id = $1 ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    pub async fn cleanup_expired(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM proofs WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}

/// Repository for nullifiers (replay prevention)
pub struct NullifierRepo {
    pool: PgPool,
}

impl NullifierRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, nullifier: NewNullifier) -> Result<Nullifier> {
        let result = sqlx::query_as::<_, Nullifier>(
            r#"
            INSERT INTO nullifiers (nullifier_hash, domain, circuit_type)
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
        )
        .bind(&nullifier.nullifier_hash)
        .bind(&nullifier.domain)
        .bind(&nullifier.circuit_type)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("nullifiers_nullifier_hash_key") {
                    return DbError::Duplicate("Nullifier already used".into());
                }
            }
            DbError::Query(e)
        })?;

        Ok(result)
    }

    pub async fn exists(&self, nullifier_hash: &[u8]) -> Result<bool> {
        let result = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM nullifiers WHERE nullifier_hash = $1",
        )
        .bind(nullifier_hash)
        .fetch_one(&self.pool)
        .await?;

        Ok(result > 0)
    }

    pub async fn exists_for_domain(&self, nullifier_hash: &[u8], domain: &str) -> Result<bool> {
        let result = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM nullifiers WHERE nullifier_hash = $1 AND domain = $2",
        )
        .bind(nullifier_hash)
        .bind(domain)
        .fetch_one(&self.pool)
        .await?;

        Ok(result > 0)
    }
}

/// Repository for credentials
pub struct CredentialRepo {
    pool: PgPool,
}

impl CredentialRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, credential: NewCredential) -> Result<StoredCredential> {
        let result = sqlx::query_as::<_, StoredCredential>(
            r#"
            INSERT INTO credentials (credential_id, user_id, issuer_id, schema_id, credential_type,
                                    encrypted_data, encryption_nonce, commitment, issued_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
        )
        .bind(&credential.credential_id)
        .bind(&credential.user_id)
        .bind(&credential.issuer_id)
        .bind(&credential.schema_id)
        .bind(&credential.credential_type)
        .bind(&credential.encrypted_data)
        .bind(&credential.encryption_nonce)
        .bind(&credential.commitment)
        .bind(&credential.issued_at)
        .bind(&credential.expires_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<StoredCredential>> {
        let result = sqlx::query_as::<_, StoredCredential>(
            "SELECT * FROM credentials WHERE credential_id = $1 AND revoked_at IS NULL",
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn list_by_user(&self, user_id: &str) -> Result<Vec<StoredCredential>> {
        let results = sqlx::query_as::<_, StoredCredential>(
            "SELECT * FROM credentials WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    pub async fn revoke(&self, credential_id: &[u8]) -> Result<()> {
        sqlx::query("UPDATE credentials SET revoked_at = NOW() WHERE credential_id = $1")
            .bind(credential_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

/// Repository for issuers
pub struct IssuerRepo {
    pool: PgPool,
}

impl IssuerRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, issuer: NewIssuer) -> Result<Issuer> {
        let result = sqlx::query_as::<_, Issuer>(
            r#"
            INSERT INTO issuers (issuer_id, name, public_key, public_key_algorithm, verification_url, trusted)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(&issuer.issuer_id)
        .bind(&issuer.name)
        .bind(&issuer.public_key)
        .bind(&issuer.public_key_algorithm)
        .bind(&issuer.verification_url)
        .bind(issuer.trusted)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn find_by_issuer_id(&self, issuer_id: &str) -> Result<Option<Issuer>> {
        let result = sqlx::query_as::<_, Issuer>(
            "SELECT * FROM issuers WHERE issuer_id = $1",
        )
        .bind(issuer_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn list_trusted(&self) -> Result<Vec<Issuer>> {
        let results = sqlx::query_as::<_, Issuer>(
            "SELECT * FROM issuers WHERE trusted = true ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    pub async fn set_trusted(&self, issuer_id: &str, trusted: bool) -> Result<()> {
        sqlx::query("UPDATE issuers SET trusted = $2 WHERE issuer_id = $1")
            .bind(issuer_id)
            .bind(trusted)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

/// Repository for audit logs
pub struct AuditLogRepo {
    pool: PgPool,
}

impl AuditLogRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn log(&self, entry: NewAuditLogEntry) -> Result<AuditLogEntry> {
        let result = sqlx::query_as::<_, AuditLogEntry>(
            r#"
            INSERT INTO audit_log (event_type, user_id, client_id, details, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5::inet, $6)
            RETURNING *
            "#,
        )
        .bind(&entry.event_type)
        .bind(&entry.user_id)
        .bind(&entry.client_id)
        .bind(&entry.details)
        .bind(&entry.ip_address)
        .bind(&entry.user_agent)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn list_by_user(&self, user_id: &str, limit: i64) -> Result<Vec<AuditLogEntry>> {
        let results = sqlx::query_as::<_, AuditLogEntry>(
            "SELECT * FROM audit_log WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }
}

/// Refresh token repository
pub struct RefreshTokenRepo {
    pool: PgPool,
}

impl RefreshTokenRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, token: NewRefreshToken) -> Result<RefreshToken> {
        let result = sqlx::query_as::<_, RefreshToken>(
            r#"
            INSERT INTO refresh_tokens (token_hash, client_id, user_id, scopes, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(&token.token_hash)
        .bind(&token.client_id)
        .bind(&token.user_id)
        .bind(&token.scopes)
        .bind(&token.expires_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn find_by_hash(&self, token_hash: &[u8]) -> Result<Option<RefreshToken>> {
        let result = sqlx::query_as::<_, RefreshToken>(
            "SELECT * FROM refresh_tokens WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn revoke(&self, token_hash: &[u8]) -> Result<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn revoke_all_for_user(&self, user_id: &str) -> Result<u64> {
        let result = sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    pub async fn cleanup_expired(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}
