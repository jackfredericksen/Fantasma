//! Database connection pool management

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;
use tracing::info;

use crate::{DbError, Result};

/// Database pool configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// PostgreSQL connection URL
    pub url: String,
    /// Maximum number of connections
    pub max_connections: u32,
    /// Minimum number of idle connections
    pub min_connections: u32,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Idle timeout
    pub idle_timeout: Duration,
    /// Max lifetime of a connection
    pub max_lifetime: Duration,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost/fantasma".to_string()),
            max_connections: 10,
            min_connections: 2,
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            max_lifetime: Duration::from_secs(3600),
        }
    }
}

impl DatabaseConfig {
    pub fn from_env() -> Self {
        let default = Self::default();

        Self {
            url: std::env::var("DATABASE_URL").unwrap_or(default.url),
            max_connections: std::env::var("DB_MAX_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.max_connections),
            min_connections: std::env::var("DB_MIN_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.min_connections),
            connect_timeout: default.connect_timeout,
            idle_timeout: default.idle_timeout,
            max_lifetime: default.max_lifetime,
        }
    }
}

/// Database pool wrapper
#[derive(Clone)]
pub struct DatabasePool {
    pool: PgPool,
}

impl DatabasePool {
    /// Create a new database pool with the given configuration
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        info!(
            "Connecting to database with max_connections={}, min_connections={}",
            config.max_connections, config.min_connections
        );

        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(config.connect_timeout)
            .idle_timeout(Some(config.idle_timeout))
            .max_lifetime(Some(config.max_lifetime))
            .connect(&config.url)
            .await
            .map_err(|e| DbError::Connection(e.to_string()))?;

        info!("Database connection pool established");

        Ok(Self { pool })
    }

    /// Create a pool from environment variables
    pub async fn from_env() -> Result<Self> {
        Self::new(&DatabaseConfig::from_env()).await
    }

    /// Get the underlying PgPool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get a cloned PgPool
    pub fn get_pool(&self) -> PgPool {
        self.pool.clone()
    }

    /// Run database migrations
    pub async fn run_migrations(&self) -> Result<()> {
        info!("Running database migrations...");

        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|e| DbError::Query(e.into()))?;

        info!("Database migrations completed");
        Ok(())
    }

    /// Check database health
    pub async fn health_check(&self) -> Result<bool> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| true)
            .map_err(|e| DbError::Query(e))
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            size: self.pool.size(),
            idle: self.pool.num_idle(),
        }
    }

    /// Close the pool gracefully
    pub async fn close(&self) {
        info!("Closing database connection pool...");
        self.pool.close().await;
        info!("Database connection pool closed");
    }
}

/// Pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Total connections in the pool
    pub size: u32,
    /// Idle connections
    pub idle: usize,
}

/// Repository factory for creating repository instances
pub struct Repositories {
    pool: PgPool,
}

impl Repositories {
    pub fn new(db: &DatabasePool) -> Self {
        Self {
            pool: db.get_pool(),
        }
    }

    pub fn clients(&self) -> crate::repos::ClientRepo {
        crate::repos::ClientRepo::new(self.pool.clone())
    }

    pub fn auth_codes(&self) -> crate::repos::AuthCodeRepo {
        crate::repos::AuthCodeRepo::new(self.pool.clone())
    }

    pub fn proofs(&self) -> crate::repos::ProofRepo {
        crate::repos::ProofRepo::new(self.pool.clone())
    }

    pub fn nullifiers(&self) -> crate::repos::NullifierRepo {
        crate::repos::NullifierRepo::new(self.pool.clone())
    }

    pub fn credentials(&self) -> crate::repos::CredentialRepo {
        crate::repos::CredentialRepo::new(self.pool.clone())
    }

    pub fn issuers(&self) -> crate::repos::IssuerRepo {
        crate::repos::IssuerRepo::new(self.pool.clone())
    }

    pub fn audit_log(&self) -> crate::repos::AuditLogRepo {
        crate::repos::AuditLogRepo::new(self.pool.clone())
    }

    pub fn refresh_tokens(&self) -> crate::repos::RefreshTokenRepo {
        crate::repos::RefreshTokenRepo::new(self.pool.clone())
    }
}
