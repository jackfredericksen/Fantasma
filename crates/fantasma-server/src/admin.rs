//! Admin API routes for Fantasma dashboard
//!
//! All admin endpoints require the `X-Admin-Key` header to match
//! the `FANTASMA_ADMIN_KEY` environment variable.

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

// ── Auth middleware ──────────────────────────────────────────────

/// Admin API key authentication middleware.
/// Checks `X-Admin-Key` header against `FANTASMA_ADMIN_KEY` env var.
pub async fn admin_auth_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let admin_key = std::env::var("FANTASMA_ADMIN_KEY").unwrap_or_default();

    if admin_key.is_empty() {
        // No admin key configured — reject all admin requests
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let provided = request
        .headers()
        .get("X-Admin-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if provided != admin_key {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}

// ── Shared types ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub data: Vec<T>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

// ── Stats ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AdminStats {
    pub clients: i64,
    pub proofs: i64,
    pub issuers: i64,
    pub audit_entries: i64,
    pub using_database: bool,
}

/// `GET /admin/stats`
pub async fn stats(State(state): State<AppState>) -> Result<Json<AdminStats>, StatusCode> {
    let repos = state.repos().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let (clients, proofs, issuers, audit_entries) = tokio::try_join!(
        async { repos.clients().count().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR) },
        async { repos.proofs().count().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR) },
        async { repos.issuers().count().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR) },
        async { repos.audit_log().count().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR) },
    )?;

    Ok(Json(AdminStats {
        clients,
        proofs,
        issuers,
        audit_entries,
        using_database: true,
    }))
}

// ── Clients ─────────────────────────────────────────────────────

/// `GET /admin/clients`
pub async fn list_clients(
    State(state): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<fantasma_db::Client>>, StatusCode> {
    let repos = state.repos().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = params.offset.unwrap_or(0);

    let (data, total) = tokio::try_join!(
        async {
            repos
                .clients()
                .list_paginated(limit, offset)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        },
        async {
            repos
                .clients()
                .count()
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        },
    )?;

    Ok(Json(PaginatedResponse {
        data,
        total,
        limit,
        offset,
    }))
}

#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub client_type: Option<String>,
}

/// `POST /admin/clients`
pub async fn create_client(
    State(state): State<AppState>,
    Json(body): Json<CreateClientRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let new_client = fantasma_db::NewClient {
        client_id: body.client_id,
        client_secret_hash: None,
        client_name: body.client_name,
        redirect_uris: body.redirect_uris,
        allowed_scopes: body.allowed_scopes,
        client_type: body.client_type.unwrap_or_else(|| "confidential".into()),
    };

    state
        .register_client(new_client)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::CREATED)
}

/// `DELETE /admin/clients/:id`
pub async fn delete_client(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let repos = state.repos().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    repos
        .clients()
        .delete(&client_id)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(StatusCode::NO_CONTENT)
}

// ── Proofs ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ProofListParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub circuit_type: Option<String>,
}

/// `GET /admin/proofs`
pub async fn list_proofs(
    State(state): State<AppState>,
    Query(params): Query<ProofListParams>,
) -> Result<Json<PaginatedResponse<fantasma_db::StoredProof>>, StatusCode> {
    let repos = state.repos().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = params.offset.unwrap_or(0);

    let (data, total) = tokio::try_join!(
        async {
            repos
                .proofs()
                .list_paginated(limit, offset, params.circuit_type.as_deref())
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        },
        async {
            repos
                .proofs()
                .count()
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        },
    )?;

    Ok(Json(PaginatedResponse {
        data,
        total,
        limit,
        offset,
    }))
}

// ── Issuers ─────────────────────────────────────────────────────

/// `GET /admin/issuers`
pub async fn list_issuers(
    State(state): State<AppState>,
) -> Result<Json<Vec<fantasma_db::Issuer>>, StatusCode> {
    let repos = state.repos().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    repos
        .issuers()
        .list_all()
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Debug, Deserialize)]
pub struct CreateIssuerRequest {
    pub issuer_id: String,
    pub name: String,
    pub public_key: String,       // hex-encoded
    pub public_key_algorithm: String,
    pub verification_url: Option<String>,
    pub trusted: Option<bool>,
}

/// `POST /admin/issuers`
pub async fn create_issuer(
    State(state): State<AppState>,
    Json(body): Json<CreateIssuerRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let repos = state.repos().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let pk_bytes = hex::decode(&body.public_key).map_err(|_| StatusCode::BAD_REQUEST)?;

    let issuer = fantasma_db::NewIssuer {
        issuer_id: body.issuer_id,
        name: body.name,
        public_key: pk_bytes,
        public_key_algorithm: body.public_key_algorithm,
        verification_url: body.verification_url,
        trusted: body.trusted.unwrap_or(false),
    };

    repos
        .issuers()
        .create(issuer)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::CREATED)
}

/// `DELETE /admin/issuers/:id`
pub async fn delete_issuer(
    State(state): State<AppState>,
    Path(issuer_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let repos = state.repos().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    repos
        .issuers()
        .delete(&issuer_id)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(StatusCode::NO_CONTENT)
}

// ── Audit log ───────────────────────────────────────────────────

/// `GET /admin/audit`
pub async fn list_audit(
    State(state): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<fantasma_db::AuditLogEntry>>, StatusCode> {
    let repos = state.repos().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let limit = params.limit.unwrap_or(50).min(200);
    let offset = params.offset.unwrap_or(0);

    let (data, total) = tokio::try_join!(
        async {
            repos
                .audit_log()
                .list_recent(limit, offset)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        },
        async {
            repos
                .audit_log()
                .count()
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        },
    )?;

    Ok(Json(PaginatedResponse {
        data,
        total,
        limit,
        offset,
    }))
}

// ── Health (detailed) ───────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DetailedHealth {
    pub status: String,
    pub database: DatabaseHealth,
    pub uptime_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct DatabaseHealth {
    pub connected: bool,
    pub pool_size: u32,
    pub pool_idle: usize,
}

/// `GET /admin/health/detailed`
pub async fn detailed_health(
    State(state): State<AppState>,
) -> Json<DetailedHealth> {
    let (connected, pool_size, pool_idle) = match &state.repos() {
        Some(repos) => {
            // Repos exist means we have a DB pool — try a lightweight check
            let _ = repos; // repos don't expose health_check directly; use pool stats via state
            (true, 0u32, 0usize) // placeholder — real stats require pool access
        }
        None => (false, 0, 0),
    };

    // We don't track start time in state, so use a fixed placeholder.
    // In a real deployment this would come from state.started_at.
    Json(DetailedHealth {
        status: if connected { "healthy" } else { "degraded" }.into(),
        database: DatabaseHealth {
            connected,
            pool_size,
            pool_idle,
        },
        uptime_seconds: 0,
    })
}
