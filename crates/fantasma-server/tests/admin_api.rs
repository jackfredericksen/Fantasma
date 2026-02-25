//! Integration tests for the admin API
//!
//! Admin auth middleware reads `FANTASMA_ADMIN_KEY` from the environment.
//! Because env vars are process-wide and tests run in parallel, we combine
//! all admin auth tests into a single test function to avoid races.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;

mod common;
use common::TestApp;

const ADMIN_KEY: &str = "test-admin-key-for-admin-tests";

fn admin_get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("X-Admin-Key", ADMIN_KEY)
        .body(Body::empty())
        .unwrap()
}

fn admin_post(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("X-Admin-Key", ADMIN_KEY)
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// All admin API tests run sequentially in a single function to avoid
/// env-var race conditions between parallel tests.
#[tokio::test]
async fn test_admin_api() {
    // Set the admin key for all sub-tests
    std::env::set_var("FANTASMA_ADMIN_KEY", ADMIN_KEY);
    let app = TestApp::new().await;

    // ── Auth: no header → 401 ───────────────────────────────
    let res = app
        .router()
        .oneshot(
            Request::builder()
                .uri("/admin/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "no header should be 401"
    );

    // ── Auth: wrong key → 401 ───────────────────────────────
    let res = app
        .router()
        .oneshot(
            Request::builder()
                .uri("/admin/stats")
                .header("X-Admin-Key", "wrong-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "wrong key should be 401"
    );

    // ── Stats: no DB → 503 ──────────────────────────────────
    let res = app
        .router()
        .oneshot(admin_get("/admin/stats"))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "stats without DB"
    );

    // ── Clients: list → 503 ─────────────────────────────────
    let res = app
        .router()
        .oneshot(admin_get("/admin/clients"))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "list clients without DB"
    );

    // ── Clients: create → 500 (in-memory rejects registration)
    let body = serde_json::json!({
        "client_id": "test-new-client",
        "client_name": "Test Client",
        "redirect_uris": ["http://localhost:9999/callback"],
        "allowed_scopes": ["openid"]
    })
    .to_string();
    let res = app
        .router()
        .oneshot(admin_post("/admin/clients", &body))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "create client without DB"
    );

    // ── Proofs: list → 503 ──────────────────────────────────
    let res = app
        .router()
        .oneshot(admin_get("/admin/proofs"))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "list proofs without DB"
    );

    // ── Issuers: list → 503 ─────────────────────────────────
    let res = app
        .router()
        .oneshot(admin_get("/admin/issuers"))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "list issuers without DB"
    );

    // ── Audit: list → 503 ───────────────────────────────────
    let res = app
        .router()
        .oneshot(admin_get("/admin/audit"))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "list audit without DB"
    );

    // ── Health: detailed → 200 (always works) ───────────────
    let res = app
        .router()
        .oneshot(admin_get("/admin/health/detailed"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "detailed health");

    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(json["status"].as_str().is_some());
    assert!(json["database"].is_object());

    // ── No admin key configured → 503 ───────────────────────
    std::env::remove_var("FANTASMA_ADMIN_KEY");
    let app2 = TestApp::new().await;
    let res = app2
        .router()
        .oneshot(admin_get("/admin/stats"))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "no key configured"
    );

    // Restore for other test files that may run after us
    std::env::set_var("FANTASMA_ADMIN_KEY", ADMIN_KEY);
}
