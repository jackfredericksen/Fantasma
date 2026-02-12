//! HTTP route handlers

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
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

/// Demo user data for authorization flow
struct DemoUser {
    id: &'static str,
    name: &'static str,
    dob: &'static str,
    age_18: bool,
    age_21: bool,
    kyc_basic: bool,
    kyc_enhanced: bool,
    has_degree: bool,
}

const DEMO_USERS: &[DemoUser] = &[
    DemoUser {
        id: "alice",
        name: "Alice",
        dob: "1990",
        age_18: true,
        age_21: true,
        kyc_basic: true,
        kyc_enhanced: true,
        has_degree: true,
    },
    DemoUser {
        id: "bob",
        name: "Bob",
        dob: "2005",
        age_18: true,
        age_21: false,
        kyc_basic: true,
        kyc_enhanced: false,
        has_degree: false,
    },
    DemoUser {
        id: "carol",
        name: "Carol",
        dob: "2010",
        age_18: false,
        age_21: false,
        kyc_basic: false,
        kyc_enhanced: false,
        has_degree: false,
    },
    DemoUser {
        id: "dave",
        name: "Dave",
        dob: "1975",
        age_18: true,
        age_21: true,
        kyc_basic: true,
        kyc_enhanced: true,
        has_degree: false,
    },
];

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
    if !state.validate_redirect_uri(&params.client_id, &params.redirect_uri).await {
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

    // Build user options HTML
    let user_options_html = build_user_options_html(&scopes);

    // Build hidden fields for form
    let hidden_fields_html = build_hidden_fields(&params);

    // Build deny URL
    let deny_url = format!(
        "{}?error=access_denied&error_description=User%20denied%20access{}",
        params.redirect_uri,
        params.state.as_ref().map(|s| format!("&state={}", s)).unwrap_or_default()
    );

    // Render the template
    let html = AUTHORIZE_TEMPLATE
        .replace("{{CLIENT_NAME}}", &client_name)
        .replace("{{PERMISSIONS}}", &permissions_html)
        .replace("{{USER_OPTIONS}}", &user_options_html)
        .replace("{{HIDDEN_FIELDS}}", &hidden_fields_html)
        .replace("{{DENY_URL}}", &deny_url);

    Html(html).into_response()
}

/// Build hidden fields for the authorization form
fn build_hidden_fields(params: &AuthorizeParams) -> String {
    let mut html = String::new();

    html.push_str(&format!(
        r#"<input type="hidden" name="response_type" value="{}">"#,
        html_escape(&params.response_type)
    ));
    html.push_str(&format!(
        r#"<input type="hidden" name="client_id" value="{}">"#,
        html_escape(&params.client_id)
    ));
    html.push_str(&format!(
        r#"<input type="hidden" name="redirect_uri" value="{}">"#,
        html_escape(&params.redirect_uri)
    ));
    html.push_str(&format!(
        r#"<input type="hidden" name="scope" value="{}">"#,
        html_escape(&params.scope)
    ));

    if let Some(ref state) = params.state {
        html.push_str(&format!(
            r#"<input type="hidden" name="state" value="{}">"#,
            html_escape(state)
        ));
    }
    if let Some(ref nonce) = params.nonce {
        html.push_str(&format!(
            r#"<input type="hidden" name="nonce" value="{}">"#,
            html_escape(nonce)
        ));
    }
    if let Some(ref challenge) = params.code_challenge {
        html.push_str(&format!(
            r#"<input type="hidden" name="code_challenge" value="{}">"#,
            html_escape(challenge)
        ));
    }
    if let Some(ref method) = params.code_challenge_method {
        html.push_str(&format!(
            r#"<input type="hidden" name="code_challenge_method" value="{}">"#,
            html_escape(method)
        ));
    }

    html
}

/// Build user options HTML with pass/fail badges based on requested scopes
fn build_user_options_html(scopes: &[ZkScope]) -> String {
    let mut html = String::new();

    for (i, user) in DEMO_USERS.iter().enumerate() {
        let checked = if i == 0 { "checked" } else { "" };

        // Determine which badges to show based on requested scopes
        let mut badges = Vec::new();

        for scope in scopes {
            match scope {
                ZkScope::Age { threshold } => {
                    let passes = if *threshold <= 18 {
                        user.age_18
                    } else if *threshold <= 21 {
                        user.age_21
                    } else {
                        user.age_21 // assume 21+ for higher thresholds in demo
                    };
                    badges.push((format!("{}+", threshold), passes));
                }
                ZkScope::Kyc { level } => {
                    let passes = match level {
                        fantasma_core::claim::KycLevel::Basic => user.kyc_basic,
                        fantasma_core::claim::KycLevel::Enhanced => user.kyc_enhanced,
                        fantasma_core::claim::KycLevel::Accredited => user.kyc_enhanced, // treat as enhanced for demo
                    };
                    badges.push((format!("KYC {}", level.as_str()), passes));
                }
                ZkScope::Credential { credential_type } => {
                    let cred = credential_type.as_deref().unwrap_or("credential");
                    let passes = if cred.contains("degree") {
                        user.has_degree
                    } else {
                        true // assume other credentials pass
                    };
                    badges.push((cred.to_string(), passes));
                }
                ZkScope::OpenId => {} // No badge for openid
            }
        }

        let badges_html: String = badges
            .iter()
            .map(|(label, passes)| {
                let class = if *passes { "badge-pass" } else { "badge-fail" };
                let icon = if *passes { "✓" } else { "✗" };
                format!(r#"<span class="user-badge {}">{} {}</span>"#, class, icon, label)
            })
            .collect::<Vec<_>>()
            .join("");

        html.push_str(&format!(
            r#"<label class="user-option">
                <input type="radio" name="demo_user" value="{}" {}>
                <div class="user-card">
                    <div class="user-name">{}</div>
                    <div class="user-dob">Born {}</div>
                    <div class="user-badges">{}</div>
                </div>
            </label>"#,
            user.id, checked, user.name, user.dob, badges_html
        ));
    }

    html
}

/// Simple HTML escape
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
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
    /// Selected demo user for testing
    pub demo_user: Option<String>,
}

/// Consent confirmation endpoint (accepts form data via POST)
pub async fn authorize_consent(
    State(state): State<AppState>,
    axum::Form(params): axum::Form<ConsentParams>,
) -> impl IntoResponse {
    if params.action != "approve" && params.action != "allow" {
        let mut redirect_url = format!(
            "{}?error=access_denied&error_description=User%20denied%20access",
            params.redirect_uri
        );
        if let Some(s) = params.state {
            redirect_url.push_str(&format!("&state={}", s));
        }
        return Redirect::temporary(&redirect_url);
    }

    // Get demo user (default to alice)
    let demo_user_id = params.demo_user.as_deref().unwrap_or("alice");
    let demo_user = DEMO_USERS
        .iter()
        .find(|u| u.id == demo_user_id)
        .unwrap_or(&DEMO_USERS[0]);

    // Parse scopes and add demo_user prefix to track which user was selected
    let scopes = parse_scopes(&params.scope);
    let mut scope_strings: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();

    // Add demo user marker (will be used in token generation)
    scope_strings.push(format!("demo_user:{}", demo_user.id));

    // Create authorization code
    let code = state
        .create_auth_code(
            params.client_id,
            params.redirect_uri.clone(),
            scope_strings,
            params.nonce,
        )
        .await;

    tracing::info!(
        "Authorization granted for demo user '{}' with scopes: {:?}",
        demo_user.name,
        params.scope
    );

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

    // Find demo user from scopes
    let demo_user_id = auth_code
        .scopes
        .iter()
        .find(|s| s.starts_with("demo_user:"))
        .and_then(|s| s.strip_prefix("demo_user:"))
        .unwrap_or("alice");

    let demo_user = DEMO_USERS
        .iter()
        .find(|u| u.id == demo_user_id)
        .unwrap_or(&DEMO_USERS[0]);

    tracing::info!(
        "Generating token for demo user '{}' (born {})",
        demo_user.name,
        demo_user.dob
    );

    // Build ZK claims based on scopes and demo user's actual credentials
    let mut zk_claims = ZkClaims::new();

    for scope in &auth_code.scopes {
        if scope.starts_with("zk:age:") {
            let threshold: u8 = scope
                .strip_prefix("zk:age:")
                .and_then(|s| s.trim_end_matches('+').parse().ok())
                .unwrap_or(18);

            // Check if demo user passes the age requirement
            let verified = if threshold <= 18 {
                demo_user.age_18
            } else if threshold <= 21 {
                demo_user.age_21
            } else {
                demo_user.age_21 // Assume 21+ covers higher thresholds
            };

            zk_claims = zk_claims.with_age_claim_verified(threshold, verified, None);
        } else if scope.starts_with("zk:kyc:") {
            let level = match scope.as_str() {
                "zk:kyc:basic" => fantasma_core::claim::KycLevel::Basic,
                "zk:kyc:enhanced" => fantasma_core::claim::KycLevel::Enhanced,
                "zk:kyc:accredited" => fantasma_core::claim::KycLevel::Accredited,
                _ => fantasma_core::claim::KycLevel::Basic,
            };

            // Check if demo user passes the KYC requirement
            let verified = match level {
                fantasma_core::claim::KycLevel::Basic => demo_user.kyc_basic,
                fantasma_core::claim::KycLevel::Enhanced => demo_user.kyc_enhanced,
                fantasma_core::claim::KycLevel::Accredited => demo_user.kyc_enhanced,
            };

            zk_claims = zk_claims.with_kyc_claim_verified(level, verified, None, None);
        } else if scope.starts_with("zk:credential:") {
            let cred_type = scope
                .strip_prefix("zk:credential:")
                .unwrap_or("*")
                .to_string();

            // Check if demo user has the credential
            let verified = if cred_type.contains("degree") {
                demo_user.has_degree
            } else {
                true // Assume other credentials pass
            };

            zk_claims = zk_claims.with_credential_claim_verified(cred_type, verified, None);
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

/// Seed data endpoint - returns demo users and credentials
pub async fn seeds() -> Json<serde_json::Value> {
    let data = crate::seeds::SeedData::generate();
    Json(serde_json::to_value(data).unwrap())
}

/// Demo user selection - returns available demo users
pub async fn demo_users() -> Json<serde_json::Value> {
    let data = crate::seeds::SeedData::generate();
    let users: Vec<serde_json::Value> = data
        .users
        .iter()
        .map(|u| {
            let cred_summary: Vec<String> = u
                .credentials
                .iter()
                .map(|c| match &c.credential_type {
                    fantasma_core::credential::CredentialType::Identity { birthdate, .. } => {
                        format!("Identity (DOB: {})", birthdate)
                    }
                    fantasma_core::credential::CredentialType::Kyc { level, .. } => {
                        format!("KYC ({})", level.as_str())
                    }
                    fantasma_core::credential::CredentialType::Degree { degree_type, field_of_study, .. } => {
                        format!("{} in {}", degree_type, field_of_study)
                    }
                    fantasma_core::credential::CredentialType::License { license_type, .. } => {
                        format!("License: {}", license_type)
                    }
                    fantasma_core::credential::CredentialType::Membership { organization, .. } => {
                        format!("Member: {}", organization)
                    }
                })
                .collect();

            serde_json::json!({
                "id": u.id,
                "name": u.name,
                "email": u.email,
                "credentials": cred_summary
            })
        })
        .collect();

    Json(serde_json::json!({ "users": users }))
}
