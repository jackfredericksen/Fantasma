//! Fantasma Server Library
//!
//! This crate provides the HTTP server implementation for the Fantasma OIDC provider.
//! The library exposes modules for integration testing while the binary handles startup.

pub mod middleware;
pub mod routes;
pub mod seeds;
pub mod state;

use axum::{
    middleware as axum_middleware,
    routing::{get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use state::AppState;

/// Create the main router with all routes configured
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // OIDC Discovery
        .route("/.well-known/openid-configuration", get(routes::discovery))
        .route("/.well-known/jwks.json", get(routes::jwks))
        // OIDC Core
        .route("/authorize", get(routes::authorize))
        .route("/authorize/consent", post(routes::authorize_consent))
        .route("/token", post(routes::token))
        .route("/userinfo", get(routes::userinfo))
        // ZK Proof endpoints
        .route("/proofs", post(routes::submit_proof))
        .route("/proofs/:id", get(routes::get_proof))
        // Health check
        .route("/health", get(routes::health))
        // Demo/seed data endpoints
        .route("/demo/users", get(routes::demo_users))
        .route("/demo/seeds", get(routes::seeds))
        .with_state(state)
        // Security middleware
        .layer(axum_middleware::from_fn(middleware::security_headers_middleware))
        // CORS
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        // Tracing
        .layer(TraceLayer::new_for_http())
}

/// Create router with all security features enabled (production mode)
pub fn create_secure_router(state: AppState) -> Router {
    Router::new()
        // OIDC Discovery
        .route("/.well-known/openid-configuration", get(routes::discovery))
        .route("/.well-known/jwks.json", get(routes::jwks))
        // OIDC Core
        .route("/authorize", get(routes::authorize))
        .route("/authorize/consent", post(routes::authorize_consent))
        .route("/token", post(routes::token))
        .route("/userinfo", get(routes::userinfo))
        // ZK Proof endpoints
        .route("/proofs", post(routes::submit_proof))
        .route("/proofs/:id", get(routes::get_proof))
        // Health check
        .route("/health", get(routes::health))
        // Demo/seed data endpoints
        .route("/demo/users", get(routes::demo_users))
        .route("/demo/seeds", get(routes::seeds))
        .with_state(state)
        // Security middleware stack (order matters - applied bottom to top)
        .layer(axum_middleware::from_fn(middleware::security_headers_middleware))
        // CORS (stricter in production)
        .layer(
            CorsLayer::new()
                .allow_origin(Any) // In production, restrict this
                .allow_methods(Any)
                .allow_headers(Any),
        )
        // Tracing
        .layer(TraceLayer::new_for_http())
}
