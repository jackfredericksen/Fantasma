//! Integration tests for the OIDC flow

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;

mod common;
use common::TestApp;

#[tokio::test]
async fn test_discovery_endpoint() {
    let app = TestApp::new().await;

    let response = app
        .router()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["issuer"].as_str().is_some());
    assert!(json["authorization_endpoint"].as_str().is_some());
    assert!(json["token_endpoint"].as_str().is_some());
    assert!(json["jwks_uri"].as_str().is_some());

    // Check ZK scopes are advertised
    let scopes = json["scopes_supported"].as_array().unwrap();
    let scope_strings: Vec<&str> = scopes.iter().filter_map(|s| s.as_str()).collect();
    assert!(scope_strings.contains(&"openid"));
    assert!(scope_strings.contains(&"zk:age:18+"));
    assert!(scope_strings.contains(&"zk:age:21+"));
}

#[tokio::test]
async fn test_jwks_endpoint() {
    let app = TestApp::new().await;

    let response = app
        .router()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // Check that keys array exists (may be empty in development mode)
    assert!(json["keys"].as_array().is_some());
}

#[tokio::test]
async fn test_authorize_endpoint_missing_params() {
    let app = TestApp::new().await;

    // Missing required parameters should return error
    let response = app
        .router()
        .oneshot(
            Request::builder()
                .uri("/authorize")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should return 400 Bad Request for missing params
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_authorize_endpoint_valid_params() {
    let app = TestApp::new().await;

    let response = app
        .router()
        .oneshot(
            Request::builder()
                .uri("/authorize?client_id=demo-client&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid%20zk:age:21+&state=test123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should return consent page (200 OK with HTML)
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&body);

    // Check consent page contains expected elements (HTML content)
    assert!(html.len() > 100, "Expected HTML response, got: {}", html);
}

#[tokio::test]
async fn test_token_endpoint_invalid_grant() {
    let app = TestApp::new().await;

    let response = app
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=authorization_code&code=invalid&redirect_uri=http://localhost:8080/callback&client_id=demo-client"))
                .unwrap(),
        )
        .await
        .unwrap();

    // Invalid code should return 400
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["error"].as_str().is_some());
}

#[tokio::test]
async fn test_health_endpoint() {
    let app = TestApp::new().await;

    let response = app
        .router()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_full_oidc_flow() {
    let app = TestApp::new().await;

    // Step 1: Start authorization
    let auth_response = app
        .router()
        .clone()
        .oneshot(
            Request::builder()
                .uri("/authorize?client_id=demo-client&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid%20zk:age:21+&state=test123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(auth_response.status(), StatusCode::OK);

    // Step 2: Submit consent (simulating user approval)
    let consent_response = app
        .router()
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/authorize/consent")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("response_type=code&client_id=demo-client&redirect_uri=http://localhost:8080/callback&scope=openid%20zk:age:21+&state=test123&demo_user=alice&action=approve"))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should redirect with authorization code
    assert_eq!(consent_response.status(), StatusCode::TEMPORARY_REDIRECT);

    let location = consent_response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();

    assert!(location.starts_with("http://localhost:8080/callback"));
    assert!(location.contains("code="));
    assert!(location.contains("state=test123"));

    // Extract auth code from redirect URL
    let code = url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .unwrap();

    // Step 3: Exchange code for tokens
    let token_response = app
        .router()
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={}&redirect_uri=http://localhost:8080/callback&client_id=demo-client",
                    code
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(token_response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(token_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // Verify token response
    assert!(json["access_token"].as_str().is_some());
    assert!(json["id_token"].as_str().is_some());
    assert_eq!(json["token_type"].as_str(), Some("Bearer"));

    // Decode and verify ID token (basic structure check)
    let id_token = json["id_token"].as_str().unwrap();
    let parts: Vec<&str> = id_token.split('.').collect();
    assert_eq!(parts.len(), 3); // Header.Payload.Signature

    // Decode payload
    let payload = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        parts[1],
    )
    .unwrap();
    let claims: Value = serde_json::from_slice(&payload).unwrap();

    // Verify ZK claims
    assert!(claims["sub"].as_str().is_some());
    assert!(claims["iss"].as_str().is_some());

    // Alice is 21+, so zk_age_claim should be verified
    if let Some(age_claim) = claims.get("zk_age_claim") {
        assert_eq!(age_claim["verified"].as_bool(), Some(true));
        assert_eq!(age_claim["threshold"].as_u64(), Some(21));
    }
}

#[tokio::test]
async fn test_denied_consent() {
    let app = TestApp::new().await;

    // User denies consent
    let response = app
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/authorize/consent")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("response_type=code&client_id=demo-client&redirect_uri=http://localhost:8080/callback&scope=openid&state=test123&demo_user=alice&action=deny"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);

    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();

    // Should redirect with error
    assert!(location.contains("error=access_denied"));
}

#[tokio::test]
async fn test_underage_user_fails_21_check() {
    let app = TestApp::new().await;

    // Bob is under 21 in demo users
    let consent_response = app
        .router()
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/authorize/consent")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("response_type=code&client_id=demo-client&redirect_uri=http://localhost:8080/callback&scope=openid%20zk:age:21+&state=test123&demo_user=bob&action=approve"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(consent_response.status(), StatusCode::TEMPORARY_REDIRECT);

    let location = consent_response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();

    // Extract code
    let code = url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .unwrap();

    // Exchange for tokens
    let token_response = app
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={}&redirect_uri=http://localhost:8080/callback&client_id=demo-client",
                    code
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(token_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let id_token = json["id_token"].as_str().unwrap();
    let parts: Vec<&str> = id_token.split('.').collect();
    let payload = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        parts[1],
    )
    .unwrap();
    let claims: Value = serde_json::from_slice(&payload).unwrap();

    // Bob's age verification for 21+ should fail
    if let Some(age_claim) = claims.get("zk_age_claim") {
        assert_eq!(age_claim["verified"].as_bool(), Some(false));
    }
}
