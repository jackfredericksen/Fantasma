//! Application state

use fantasma_oidc::config::OidcConfig;
use fantasma_proof_store::InMemoryProofStore;
use fantasma_stark::circuit::CircuitType;
use fantasma_stark::verifier::Verifier;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Stored authorization code
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

    /// Authorization codes (in production, use Redis/database)
    pub auth_codes: Arc<RwLock<HashMap<String, AuthCode>>>,

    /// Registered clients (in production, use database)
    pub clients: Arc<HashMap<String, ClientInfo>>,
}

/// Registered client information
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    pub name: String,
}

impl AppState {
    pub fn new(config: OidcConfig) -> Self {
        // Generate a random signing key (in production, load from secure storage)
        use rand::RngCore;
        let mut signing_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut signing_key);

        // Create verifier and load circuit verification keys
        let mut verifier = Verifier::new();
        let _ = verifier.load_verification_key(CircuitType::AgeVerification);
        let _ = verifier.load_verification_key(CircuitType::CredentialVerification);
        let _ = verifier.load_verification_key(CircuitType::KycVerification);

        // Register a demo client
        let mut clients = HashMap::new();
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

        Self {
            config: Arc::new(config),
            signing_key: Arc::new(signing_key),
            verifier: Arc::new(verifier),
            proof_store: Arc::new(InMemoryProofStore::default()),
            auth_codes: Arc::new(RwLock::new(HashMap::new())),
            clients: Arc::new(clients),
        }
    }

    /// Validate a redirect URI for a client
    pub fn validate_redirect_uri(&self, client_id: &str, redirect_uri: &str) -> bool {
        if let Some(client) = self.clients.get(client_id) {
            client.redirect_uris.iter().any(|uri| uri == redirect_uri)
        } else {
            false
        }
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

        let auth_code = AuthCode {
            code: code.clone(),
            client_id,
            redirect_uri,
            scopes,
            nonce,
            subject_id,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(
                self.config.auth_code_expiration_seconds as i64,
            ),
        };

        let mut codes = self.auth_codes.write().await;
        codes.insert(code.clone(), auth_code);

        code
    }

    /// Exchange an authorization code for tokens
    pub async fn exchange_code(&self, code: &str) -> Option<AuthCode> {
        let mut codes = self.auth_codes.write().await;
        codes.remove(code).filter(|c| c.expires_at > chrono::Utc::now())
    }
}
