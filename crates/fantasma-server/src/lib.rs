//! Fantasma Server Library
//!
//! This crate provides the HTTP server implementation for the Fantasma OIDC provider.
//! The library exposes modules for integration testing while the binary handles startup.

pub mod admin;
pub mod middleware;
pub mod routes;
pub mod seeds;
pub mod state;

use axum::{
    middleware as axum_middleware,
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use state::AppState;

/// Create the admin sub-router (behind auth middleware)
fn admin_router() -> Router<AppState> {
    Router::new()
        .route("/stats", get(admin::stats))
        .route(
            "/clients",
            get(admin::list_clients).post(admin::create_client),
        )
        .route("/clients/:id", delete(admin::delete_client))
        .route("/proofs", get(admin::list_proofs))
        .route(
            "/issuers",
            get(admin::list_issuers).post(admin::create_issuer),
        )
        .route("/issuers/:id", delete(admin::delete_issuer))
        .route("/audit", get(admin::list_audit))
        .route("/health/detailed", get(admin::detailed_health))
        .layer(axum_middleware::from_fn(admin::admin_auth_middleware))
}

/// Build CORS layer based on environment.
///
/// - `FANTASMA_CORS_ORIGINS` — comma-separated allowed origins (default: `*`).
/// - When set to `*`, all origins are allowed (development mode).
/// - When set to specific origins, only those are allowed (production mode).
fn cors_layer() -> CorsLayer {
    let origins = std::env::var("FANTASMA_CORS_ORIGINS").unwrap_or_else(|_| "*".into());

    let allow_origin = if origins.trim() == "*" {
        AllowOrigin::any()
    } else {
        let parsed: Vec<_> = origins
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        AllowOrigin::list(parsed)
    };

    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods(AllowMethods::mirror_request())
        .allow_headers(AllowHeaders::mirror_request())
        .max_age(std::time::Duration::from_secs(3600))
}

/// Core routes shared between dev and production routers.
fn core_routes() -> Router<AppState> {
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
        // Admin API
        .nest("/admin", admin_router())
}

/// Create the main router with all routes configured
pub fn create_router(state: AppState) -> Router {
    core_routes()
        .with_state(state)
        .layer(axum_middleware::from_fn(
            middleware::security_headers_middleware,
        ))
        .layer(cors_layer())
        .layer(TraceLayer::new_for_http())
}

/// Create router with all security features enabled (production mode)
pub fn create_secure_router(state: AppState) -> Router {
    core_routes()
        .with_state(state)
        .layer(axum_middleware::from_fn(
            middleware::security_headers_middleware,
        ))
        .layer(cors_layer())
        .layer(TraceLayer::new_for_http())
}
