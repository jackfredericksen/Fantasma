//! Fantasma Server
//!
//! HTTP server for the Fantasma OIDC provider.

use fantasma_db::pool::DatabasePool;
use fantasma_oidc::config::OidcConfig;
use fantasma_server::{create_router, state::AppState};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "fantasma_server=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = OidcConfig::with_issuer(
        std::env::var("FANTASMA_ISSUER").unwrap_or_else(|_| "http://localhost:3000".to_string()),
    );

    // Try to connect to database if DATABASE_URL is set
    let db = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => {
            tracing::info!("DATABASE_URL set, connecting to PostgreSQL...");
            match DatabasePool::from_env().await {
                Ok(pool) => {
                    tracing::info!("Database connection established");

                    // Run migrations
                    if let Err(e) = pool.run_migrations().await {
                        tracing::warn!("Failed to run migrations: {}. Continuing anyway.", e);
                    }

                    Some(pool)
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to connect to database: {}. Falling back to in-memory storage.",
                        e
                    );
                    None
                }
            }
        }
        _ => {
            tracing::info!("DATABASE_URL not set, using in-memory storage");
            None
        }
    };

    // Create application state
    let state = AppState::with_storage(config, db);

    // Log storage mode
    if state.is_using_database() {
        tracing::info!("Running with PostgreSQL persistence");
    } else {
        tracing::info!("Running with in-memory storage (data will be lost on restart)");
    }

    // Build router using the library function
    let app = create_router(state);

    // Start server
    let addr = std::env::var("FANTASMA_BIND").unwrap_or_else(|_| "0.0.0.0:3000".to_string());

    tracing::info!("Starting Fantasma server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
