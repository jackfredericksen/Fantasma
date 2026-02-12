//! Application state

use fantasma_db::{
    models::{NewAuthCode, NewClient},
    pool::{DatabasePool, Repositories},
};
use fantasma_oidc::config::OidcConfig;
use fantasma_proof_store::InMemoryProofStore;
use fantasma_stark::circuit::CircuitType;
use fantasma_stark::verifier::Verifier;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Stored authorization code (in-memory version)
#[derive(Debug, Clone)]
pub struct AuthCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub subject_id: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Registered client information
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    pub name: String,
}

/// Storage backend abstraction
#[derive(Clone)]
pub enum StorageBackend {
    /// In-memory storage (for development)
    InMemory {
        auth_codes: Arc<RwLock<HashMap<String, AuthCode>>>,
    },
    /// PostgreSQL storage (for production)
    Database { pool: DatabasePool },
}

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    /// OIDC configuration
    pub config: Arc<OidcConfig>,

    /// Signing key (in production, use proper key management)
    pub signing_key: Arc<[u8; 32]>,

    /// Proof verifier
    pub verifier: Arc<Verifier>,

    /// Proof storage
    pub proof_store: Arc<InMemoryProofStore>,

    /// Storage backend
    storage: StorageBackend,

    /// Demo clients (always available for testing)
    pub clients: Arc<HashMap<String, ClientInfo>>,
}

impl AppState {
    /// Create new state with in-memory storage
    pub fn new(config: OidcConfig) -> Self {
        Self::with_storage(config, None)
    }

    /// Create new state with optional database
    pub fn with_storage(config: OidcConfig, db: Option<DatabasePool>) -> Self {
        // Generate a random signing key (in production, load from secure storage)
        use rand::RngCore;
        let mut signing_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut signing_key);

        // Create verifier and load circuit verification keys
        let mut verifier = Verifier::new();
        let _ = verifier.load_verification_key(CircuitType::AgeVerification);
        let _ = verifier.load_verification_key(CircuitType::CredentialVerification);
        let _ = verifier.load_verification_key(CircuitType::KycVerification);

        // Register demo clients
        let demo_clients = create_demo_clients();

        let storage = match db {
            Some(pool) => {
                tracing::info!("Using PostgreSQL storage backend");
                StorageBackend::Database { pool }
            }
            None => {
                tracing::info!("Using in-memory storage backend");
                StorageBackend::InMemory {
                    auth_codes: Arc::new(RwLock::new(HashMap::new())),
                }
            }
        };

        Self {
            config: Arc::new(config),
            signing_key: Arc::new(signing_key),
            verifier: Arc::new(verifier),
            proof_store: Arc::new(InMemoryProofStore::default()),
            storage,
            clients: Arc::new(demo_clients),
        }
    }

    /// Check if using database storage
    pub fn is_using_database(&self) -> bool {
        matches!(self.storage, StorageBackend::Database { .. })
    }

    /// Get database repositories (if using database)
    pub fn repos(&self) -> Option<Repositories> {
        match &self.storage {
            StorageBackend::Database { pool } => Some(Repositories::new(pool)),
            StorageBackend::InMemory { .. } => None,
        }
    }

    /// Validate a redirect URI for a client
    pub async fn validate_redirect_uri(&self, client_id: &str, redirect_uri: &str) -> bool {
        let normalized_input = redirect_uri.trim_end_matches('/');

        // First check demo clients (always available)
        if let Some(client) = self.clients.get(client_id) {
            if client
                .redirect_uris
                .iter()
                .any(|uri| uri.trim_end_matches('/') == normalized_input)
            {
                return true;
            }
        }

        // Then check database if available
        if let Some(repos) = self.repos() {
            if let Ok(Some(client)) = repos.clients().find_by_client_id(client_id).await {
                return client
                    .redirect_uris
                    .iter()
                    .any(|uri| uri.trim_end_matches('/') == normalized_input);
            }
        }

        tracing::warn!("Unknown client_id: {}", client_id);
        false
    }

    /// Get client info
    pub async fn get_client(&self, client_id: &str) -> Option<ClientInfo> {
        // Check demo clients first
        if let Some(client) = self.clients.get(client_id) {
            return Some(client.clone());
        }

        // Check database
        if let Some(repos) = self.repos() {
            if let Ok(Some(client)) = repos.clients().find_by_client_id(client_id).await {
                return Some(ClientInfo {
                    client_id: client.client_id,
                    client_secret: None, // Don't expose hash
                    redirect_uris: client.redirect_uris,
                    name: client.client_name,
                });
            }
        }

        None
    }

    /// Generate a new authorization code
    pub async fn create_auth_code(
        &self,
        client_id: String,
        redirect_uri: String,
        scopes: Vec<String>,
        nonce: Option<String>,
    ) -> String {
        use rand::distributions::Alphanumeric;
        use rand::Rng;

        let code: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let subject_id = format!("zkid:{}", uuid::Uuid::new_v4().simple());
        let expires_at = chrono::Utc::now()
            + chrono::Duration::seconds(self.config.auth_code_expiration_seconds as i64);

        match &self.storage {
            StorageBackend::InMemory { auth_codes } => {
                let auth_code = AuthCode {
                    code: code.clone(),
                    client_id,
                    redirect_uri,
                    scopes,
                    nonce,
                    subject_id,
                    expires_at,
                };

                let mut codes = auth_codes.write().await;
                codes.insert(code.clone(), auth_code);
            }
            StorageBackend::Database { pool } => {
                let repos = Repositories::new(pool);
                let new_code = NewAuthCode {
                    code: code.clone(),
                    client_id,
                    user_id: subject_id,
                    redirect_uri,
                    scopes,
                    nonce,
                    state: None,
                    code_challenge: None,
                    code_challenge_method: None,
                    zk_claims: None,
                    expires_at,
                };

                if let Err(e) = repos.auth_codes().create(new_code).await {
                    tracing::error!("Failed to store auth code: {}", e);
                }
            }
        }

        code
    }

    /// Exchange an authorization code for tokens
    pub async fn exchange_code(&self, code: &str) -> Option<AuthCode> {
        match &self.storage {
            StorageBackend::InMemory { auth_codes } => {
                let mut codes = auth_codes.write().await;
                codes
                    .remove(code)
                    .filter(|c| c.expires_at > chrono::Utc::now())
            }
            StorageBackend::Database { pool } => {
                let repos = Repositories::new(pool);

                // Find and mark as used
                if let Ok(Some(db_code)) = repos.auth_codes().find_by_code(code).await {
                    let _ = repos.auth_codes().mark_used(code).await;

                    return Some(AuthCode {
                        code: db_code.code,
                        client_id: db_code.client_id,
                        redirect_uri: db_code.redirect_uri,
                        scopes: db_code.scopes,
                        nonce: db_code.nonce,
                        subject_id: db_code.user_id,
                        expires_at: db_code.expires_at,
                    });
                }
                None
            }
        }
    }

    /// Register a new client (database only)
    pub async fn register_client(&self, client: NewClient) -> Result<(), String> {
        match &self.storage {
            StorageBackend::InMemory { .. } => {
                Err("Cannot register clients in in-memory mode".to_string())
            }
            StorageBackend::Database { pool } => {
                let repos = Repositories::new(pool);
                repos
                    .clients()
                    .create(client)
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
        }
    }
}

/// Create demo clients for testing
fn create_demo_clients() -> HashMap<String, ClientInfo> {
    let mut clients = HashMap::new();

    // Generic demo client
    clients.insert(
        "demo-client".to_string(),
        ClientInfo {
            client_id: "demo-client".to_string(),
            client_secret: Some("demo-secret".to_string()),
            redirect_uris: vec![
                "http://localhost:8080/callback".to_string(),
                "https://oauth.pstmn.io/v1/callback".to_string(),
            ],
            name: "Demo Client".to_string(),
        },
    );

    // Demo relying party (examples/relying-party)
    clients.insert(
        "demo-rp".to_string(),
        ClientInfo {
            client_id: "demo-rp".to_string(),
            client_secret: Some("demo-secret".to_string()),
            redirect_uris: vec!["http://localhost:8080/callback".to_string()],
            name: "Demo Relying Party".to_string(),
        },
    );

    // Wallet extension
    clients.insert(
        "fantasma-wallet".to_string(),
        ClientInfo {
            client_id: "fantasma-wallet".to_string(),
            client_secret: None, // Public client
            redirect_uris: vec![
                "chrome-extension://*/callback".to_string(),
                "moz-extension://*/callback".to_string(),
            ],
            name: "Fantasma Wallet".to_string(),
        },
    );

    clients
}
