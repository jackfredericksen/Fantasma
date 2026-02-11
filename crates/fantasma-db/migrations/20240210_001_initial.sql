-- Fantasma Database Schema
-- Initial migration for PostgreSQL

-- OAuth2 Clients
CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret_hash BYTEA,  -- Argon2 hash of client secret (NULL for public clients)
    client_name VARCHAR(255) NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    allowed_scopes TEXT[] NOT NULL DEFAULT '{}',
    client_type VARCHAR(50) NOT NULL DEFAULT 'confidential',  -- 'public' or 'confidential'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_clients_client_id ON clients(client_id);

-- Authorization Codes
CREATE TABLE IF NOT EXISTS auth_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(255) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL REFERENCES clients(client_id),
    user_id VARCHAR(255) NOT NULL,  -- zkid (pseudonymous)
    redirect_uri TEXT NOT NULL,
    scopes TEXT[] NOT NULL,
    nonce VARCHAR(255),
    state VARCHAR(255),
    code_challenge VARCHAR(255),  -- PKCE
    code_challenge_method VARCHAR(10),  -- 'S256' or 'plain'
    zk_claims JSONB,  -- Verified ZK claims
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at TIMESTAMPTZ  -- NULL until used
);

CREATE INDEX idx_auth_codes_code ON auth_codes(code);
CREATE INDEX idx_auth_codes_expires ON auth_codes(expires_at);

-- Refresh Tokens
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash BYTEA UNIQUE NOT NULL,  -- SHA256 hash of token
    client_id VARCHAR(255) NOT NULL REFERENCES clients(client_id),
    user_id VARCHAR(255) NOT NULL,
    scopes TEXT[] NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);

-- Stored STARK Proofs
CREATE TABLE IF NOT EXISTS proofs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id VARCHAR(255) UNIQUE NOT NULL,  -- Public identifier (prf_...)
    proof_hash BYTEA NOT NULL,  -- SHA256 hash of proof bytes
    proof_data BYTEA NOT NULL,  -- The actual STARK proof (~100KB)
    circuit_type VARCHAR(100) NOT NULL,  -- 'age_verification', 'kyc_verification', etc.
    public_inputs JSONB NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT false,
    user_id VARCHAR(255),  -- Optional: associate with user
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_proofs_proof_id ON proofs(proof_id);
CREATE INDEX idx_proofs_hash ON proofs(proof_hash);
CREATE INDEX idx_proofs_user ON proofs(user_id);
CREATE INDEX idx_proofs_expires ON proofs(expires_at);

-- Nullifiers (Replay Prevention)
CREATE TABLE IF NOT EXISTS nullifiers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nullifier_hash BYTEA UNIQUE NOT NULL,  -- Hash of nullifier
    domain VARCHAR(255) NOT NULL,  -- Service domain for domain-bound nullifiers
    circuit_type VARCHAR(100) NOT NULL,
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_nullifiers_hash ON nullifiers(nullifier_hash);
CREATE INDEX idx_nullifiers_domain ON nullifiers(domain);

-- User Credentials (Encrypted)
CREATE TABLE IF NOT EXISTS credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id BYTEA UNIQUE NOT NULL,  -- 32-byte credential ID
    user_id VARCHAR(255) NOT NULL,
    issuer_id VARCHAR(255) NOT NULL,
    schema_id VARCHAR(255) NOT NULL,
    credential_type VARCHAR(100) NOT NULL,
    encrypted_data BYTEA NOT NULL,  -- AES-256-GCM encrypted credential
    encryption_nonce BYTEA NOT NULL,  -- 12-byte nonce
    commitment BYTEA NOT NULL,  -- Pedersen/Poseidon commitment
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_credentials_user ON credentials(user_id);
CREATE INDEX idx_credentials_issuer ON credentials(issuer_id);
CREATE INDEX idx_credentials_commitment ON credentials(commitment);

-- Issuers (Trusted credential issuers)
CREATE TABLE IF NOT EXISTS issuers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    public_key BYTEA NOT NULL,  -- Dilithium public key (~2KB)
    public_key_algorithm VARCHAR(50) NOT NULL DEFAULT 'dilithium3',
    verification_url TEXT,
    trusted BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_issuers_issuer_id ON issuers(issuer_id);

-- Audit Log
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL,
    user_id VARCHAR(255),
    client_id VARCHAR(255),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_user ON audit_log(user_id);
CREATE INDEX idx_audit_log_type ON audit_log(event_type);
CREATE INDEX idx_audit_log_created ON audit_log(created_at);

-- Helper function to update timestamps
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply timestamp triggers
CREATE TRIGGER clients_updated_at
    BEFORE UPDATE ON clients
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER issuers_updated_at
    BEFORE UPDATE ON issuers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();
