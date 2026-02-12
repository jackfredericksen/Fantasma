//! Test utilities for integration tests

use axum::Router;
use fantasma_oidc::config::OidcConfig;

/// Test application wrapper
pub struct TestApp {
    router: Router,
}

impl TestApp {
    /// Create a new test application with in-memory storage
    pub async fn new() -> Self {
        let config = OidcConfig::with_issuer("http://localhost:8080".to_string());

        // Create state with in-memory storage (no database)
        let state = fantasma_server::state::AppState::with_storage(config, None);

        // Build router using the library function
        let router = fantasma_server::create_router(state);

        Self { router }
    }

    /// Get the router for making requests
    pub fn router(&self) -> Router {
        self.router.clone()
    }
}
