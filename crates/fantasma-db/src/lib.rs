//! Fantasma Database
//!
//! PostgreSQL persistence layer for Fantasma OIDC provider.
//!
//! This crate provides:
//! - Database models for clients, auth codes, tokens, proofs, and credentials
//! - Repository traits and implementations
//! - Migration support via SQLx

pub mod models;
pub mod repos;
pub mod pool;

pub use models::*;
pub use repos::*;
pub use pool::DatabasePool;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("Database connection error: {0}")]
    Connection(String),

    #[error("Query error: {0}")]
    Query(#[from] sqlx::Error),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Duplicate entry: {0}")]
    Duplicate(String),

    #[error("Constraint violation: {0}")]
    Constraint(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, DbError>;
