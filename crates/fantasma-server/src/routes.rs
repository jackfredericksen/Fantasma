//! HTTP route handlers

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Json, Redirect},
};
use fantasma_core::proof::ProofId;
use fantasma_oidc::{
    claims::ZkClaims,
    discovery::DiscoveryDocument,
    scopes::{parse_scopes, ZkScope},
    token::{IdToken, IdTokenClaims, TokenResponse},
};
use fantasma_proof_store::{ProofStore, StoredProof};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

/// HTML template for authorization consent page
const AUTHORIZE_TEMPLATE: &str = include_str!("../templates/authorize.html");

/// Discovery endpoint
pub async fn discovery(State(state): State<AppState>) -> Json<DiscoveryDocument> {
    Json(DiscoveryDocument::from_config(&state.config))
}

/// JWKS endpoint (placeholder)
pub async fn jwks() -> Json<serde_json::Value> {
    // In production, this would return actual public keys
    Json(serde_json::json!({
        "keys": []
    }))
}

/// Authorization request parameters
#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// Authorization endpoint - shows consent page
pub async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeParams>,
) -> impl IntoResponse {
    // Validate response type
    if params.response_type != "code" {
        return Html(format!(
            "<h1>Error</h1><p>Unsupported response type: {}</p>",
            params.response_type
        ))
        .into_response();
    }

    // Validate client and redirect URI
    if !state.validate_redirect_uri(&params.client_id, &params.redirect_uri) {
        return Html("<h1>Error</h1><p>Invalid client or redirect URI</p>".to_string())
            .into_response();
    }

    // Get client name
    let client_name = state
        .clients
        .get(&params.client_id)
        .map(|c| c.name.clone())
        .unwrap_or_else(|| params.client_id.clone());

    // Parse scopes and build permissions HTML
    let scopes = parse_scopes(&params.scope);
    let permissions_html = build_permissions_html(&scopes);

    // Build allow/deny URLs
    let query_string = build_query_string(&params);
    let allow_url = format!("/authorize/consent?action=allow&{}", query_string);
    let deny_url = format!(
        "{}?error=access_denied&error_description=User%20denied%20access{}",
        params.redirect_uri,
        params.state.as_ref().map(|s| format!("&state={}", s)).unwrap_or_default()
    );

    // Render the template
    let html = AUTHORIZE_TEMPLATE
        .replace("{{CLIENT_NAME}}", &client_name)
        .replace("{{PERMISSIONS}}", &permissions_html)
        .replace("{{ALLOW_URL}}", &allow_url)
        .replace("{{DENY_URL}}", &deny_url);

    Html(html).into_response()
}

/// Build permissions HTML from scopes
fn build_permissions_html(scopes: &[ZkScope]) -> String {
    let mut html = String::new();

    for scope in scopes {
        let (icon_class, icon, title, description, has_zk): (&str, &str, String, &str, bool) = match scope {
            ZkScope::OpenId => (
                "identity",
                "&#128100;",
                "Basic Identity".to_string(),
                "A pseudonymous identifier for this service",
                false,
            ),
            ZkScope::Age { threshold } => (
                "age",
                "&#127874;",
                format!("Age {} or older", threshold),
                "Proves you meet the age requirement without revealing your birthdate",
                true,
            ),
            ZkScope::Credential { credential_type } => {
                let cred_name = credential_type.clone().unwrap_or_else(|| "credential".to_string());
                (
                    "credential",
                    "&#128196;",
                    format!("{} verification", cred_name),
                    "Proves you hold this credential without revealing details",
                    true,
                )
            }
            ZkScope::Kyc { level } => (
                "kyc",
                "&#9989;",
                format!("KYC {} status", level.as_str()),
                "Proves your identity verification status without personal data",
                true,
            ),
        };

        let zk_badge = if has_zk {
            r#"<span class="zk-badge">Zero-Knowledge Proof</span>"#
        } else {
            ""
        };

        html.push_str(&format!(
            r#"<li class="permission-item">
                <div class="permission-icon {}">{}</div>
                <div class="permission-details">
                    <h3>{}</h3>
                    <p>{}</p>
                    {}
                </div>
            </li>"#,
            icon_class, icon, title, description, zk_badge
        ));
    }

    html
}

/// Build query string from params
fn build_query_string(params: &AuthorizeParams) -> String {
    let mut parts = vec![
        format!("response_type={}", urlencoding::encode(&params.response_type)),
        format!("client_id={}", urlencoding::encode(&params.client_id)),
        format!("redirect_uri={}", urlencoding::encode(&params.redirect_uri)),
        format!("scope={}", urlencoding::encode(&params.scope)),
    ];

    if let Some(ref state) = params.state {
        parts.push(format!("state={}", urlencoding::encode(state)));
    }
    if let Some(ref nonce) = params.nonce {
        parts.push(format!("nonce={}", urlencoding::encode(nonce)));
    }
    if let Some(ref challenge) = params.code_challenge {
        parts.push(format!("code_challenge={}", urlencoding::encode(challenge)));
    }
    if let Some(ref method) = params.code_challenge_method {
        parts.push(format!("code_challenge_method={}", urlencoding::encode(method)));
    }

    parts.join("&")
}

/// URL encoding helper
mod urlencoding {
    pub fn encode(s: &str) -> String {
        url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
    }
}

/// Consent confirmation parameters
#[derive(Debug, Deserialize)]
pub struct ConsentParams {
    pub action: String,
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// Consent confirmation endpoint
pub async fn authorize_consent(
    State(state): State<AppState>,
    Query(params): Query<ConsentParams>,
) -> impl IntoResponse {
    if params.action != "allow" {
        let mut redirect_url = format!(
            "{}?error=access_denied&error_description=User%20denied%20access",
            params.redirect_uri
        );
        if let Some(s) = params.state {
            redirect_url.push_str(&format!("&state={}", s));
        }
        return Redirect::temporary(&redirect_url);
    }

    // Parse scopes
    let scopes = parse_scopes(&params.scope);
    let scope_strings: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();

    // Create authorization code
    let code = state
        .create_auth_code(
            params.client_id,
            params.redirect_uri.clone(),
            scope_strings,
            params.nonce,
        )
        .await;

    let mut redirect_url = format!("{}?code={}", params.redirect_uri, code);
    if let Some(s) = params.state {
        redirect_url.push_str(&format!("&state={}", s));
    }

    Redirect::temporary(&redirect_url)
}

/// Token request parameters
#[derive(Debug, Deserialize)]
pub struct TokenParams {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
}

/// Token endpoint
pub async fn token(
    State(state): State<AppState>,
    axum::Form(params): axum::Form<TokenParams>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Validate grant type
    if params.grant_type != "authorization_code" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "unsupported_grant_type"
            })),
        ));
    }

    // Get the authorization code
    let code = params.code.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "code is required"
            })),
        )
    })?;

    // Exchange the code
    let auth_code = state.exchange_code(&code).await.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "invalid or expired code"
            })),
        )
    })?;

    // Build ZK claims based on scopes
    let mut zk_claims = ZkClaims::new();

    for scope in &auth_code.scopes {
        if scope.starts_with("zk:age:") {
            let threshold: u8 = scope
                .strip_prefix("zk:age:")
                .and_then(|s| s.trim_end_matches('+').parse().ok())
                .unwrap_or(18);
            zk_claims = zk_claims.with_age_claim(threshold, None);
        } else if scope.starts_with("zk:kyc:") {
            let level = match scope.as_str() {
                "zk:kyc:basic" => fantasma_core::claim::KycLevel::Basic,
                "zk:kyc:enhanced" => fantasma_core::claim::KycLevel::Enhanced,
                "zk:kyc:accredited" => fantasma_core::claim::KycLevel::Accredited,
                _ => fantasma_core::claim::KycLevel::Basic,
            };
            zk_claims = zk_claims.with_kyc_claim(level, None, None);
        } else if scope.starts_with("zk:credential") {
            let cred_type = scope
                .strip_prefix("zk:credential:")
                .unwrap_or("*")
                .to_string();
            zk_claims = zk_claims.with_credential_claim(cred_type, None);
        }
    }

    // Create ID token
    let claims = IdTokenClaims::new(
        &state.config.issuer,
        &auth_code.subject_id,
        &auth_code.client_id,
        state.config.token_expiration_seconds,
    )
    .with_zk_claims(zk_claims);

    let claims = if let Some(nonce) = auth_code.nonce {
        claims.with_nonce(nonce)
    } else {
        claims
    };

    let id_token = IdToken::create(claims, state.signing_key.as_ref()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": e.to_string()
            })),
        )
    })?;

    // Generate access token
    let access_token = uuid::Uuid::new_v4().to_string();

    Ok(Json(TokenResponse::new(
        access_token,
        id_token.token,
        state.config.token_expiration_seconds,
    )))
}

/// UserInfo endpoint (minimal implementation)
pub async fn userinfo() -> Json<serde_json::Value> {
    // In production, validate the access token and return user info
    Json(serde_json::json!({
        "sub": "zkid:anonymous"
    }))
}

/// Submit proof request
#[derive(Debug, Deserialize)]
pub struct SubmitProofRequest {
    pub proof_bytes: String, // Base64 encoded
    pub circuit_type: String,
}

/// Submit proof response
#[derive(Debug, Serialize)]
pub struct SubmitProofResponse {
    pub proof_id: String,
    pub hash: String,
}

/// Submit a proof for storage
pub async fn submit_proof(
    State(state): State<AppState>,
    Json(request): Json<SubmitProofRequest>,
) -> Result<Json<SubmitProofResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Decode proof bytes
    let proof_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &request.proof_bytes,
    )
    .map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_proof",
                "error_description": "invalid base64 encoding"
            })),
        )
    })?;

    // Store the proof
    let stored = StoredProof::new(proof_bytes, request.circuit_type, 3600);
    let hash = hex::encode(stored.hash);
    let id = state.proof_store.store(stored).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "storage_error",
                "error_description": e.to_string()
            })),
        )
    })?;

    Ok(Json(SubmitProofResponse {
        proof_id: id.0,
        hash,
    }))
}

/// Get a stored proof
pub async fn get_proof(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Vec<u8>, (StatusCode, Json<serde_json::Value>)> {
    let proof_id = ProofId::new(id);
    let proof = state.proof_store.get(&proof_id).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "not_found",
                "error_description": e.to_string()
            })),
        )
    })?;

    Ok(proof.proof_bytes)
}

/// Health check
pub async fn health() -> &'static str {
    "OK"
}

use base64::Engine;
