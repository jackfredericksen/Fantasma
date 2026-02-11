//! Fantasma Server
//!
//! HTTP server for the Fantasma OIDC provider.

use axum::{routing::{get, post}, Router};
use fantasma_oidc::config::OidcConfig;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod routes;
mod state;

use state::AppState;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "fantasma_server=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = OidcConfig::with_issuer(
        std::env::var("FANTASMA_ISSUER").unwrap_or_else(|_| "http://localhost:3000".to_string()),
    );

    // Create application state
    let state = AppState::new(config);

    // Build router
    let app = Router::new()
        // OIDC Discovery
        .route("/.well-known/openid-configuration", get(routes::discovery))
        .route("/.well-known/jwks.json", get(routes::jwks))
        // OIDC Core
        .route("/authorize", get(routes::authorize))
        .route("/authorize/consent", get(routes::authorize_consent))
        .route("/token", post(routes::token))
        .route("/userinfo", get(routes::userinfo))
        // ZK Proof endpoints
        .route("/proofs", post(routes::submit_proof))
        .route("/proofs/:id", get(routes::get_proof))
        // Health check
        .route("/health", get(routes::health))
        .with_state(state)
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
        .layer(TraceLayer::new_for_http());

    // Start server
    let addr = std::env::var("FANTASMA_BIND")
        .unwrap_or_else(|_| "0.0.0.0:3000".to_string());

    tracing::info!("Starting Fantasma server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
