//! Example: Relying Party Integration
//!
//! This example shows how a relying party (service provider) can integrate
//! with Fantasma for privacy-preserving identity verification.
//!
//! Run with: cargo run --example relying_party

use fantasma_client_sdk::{AuthorizationUrlBuilder, FantasmaClient};
use serde::Deserialize;

const FANTASMA_ISSUER: &str = "http://localhost:3000";
const CLIENT_ID: &str = "demo-client";
const REDIRECT_URI: &str = "http://localhost:8080/callback";

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: u64,
    iat: u64,
    nonce: Option<String>,
    zk_age_claim: Option<fantasma_oidc::claims::ZkAgeClaim>,
    zk_kyc_claim: Option<fantasma_oidc::claims::ZkKycClaim>,
    zk_credential_claim: Option<fantasma_oidc::claims::ZkCredentialClaim>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔════════════════════════════════════════╗");
    println!("║   Fantasma Relying Party Example       ║");
    println!("╚════════════════════════════════════════╝");
    println!();

    // Step 1: Initialize the client and fetch discovery document
    println!("1. Initializing Fantasma client...");
    let client = FantasmaClient::new(FANTASMA_ISSUER);

    let discovery = match client.discover().await {
        Ok(doc) => {
            println!("   ✓ Discovery document fetched");
            println!("     Issuer: {}", doc.issuer);
            doc
        }
        Err(e) => {
            println!("   ✗ Failed to fetch discovery: {}", e);
            println!("   Make sure the Fantasma server is running on {}", FANTASMA_ISSUER);
            return Ok(());
        }
    };

    println!();

    // Step 2: Build authorization URL
    println!("2. Building authorization URL...");

    let state = uuid::Uuid::new_v4().to_string();
    let nonce = uuid::Uuid::new_v4().to_string();

    let auth_url = AuthorizationUrlBuilder::new(
        &discovery.authorization_endpoint,
        CLIENT_ID,
        REDIRECT_URI,
    )
    .require_age(21) // Require user to be 21+
    .require_kyc("basic") // Require basic KYC
    .state(&state)
    .nonce(&nonce)
    .build();

    println!("   Authorization URL:");
    println!("   {}", auth_url);
    println!();

    // Step 3: Handle callback (simulated)
    println!("3. In a real application, you would:");
    println!("   a) Redirect the user to the authorization URL");
    println!("   b) User authenticates with Fantasma wallet");
    println!("   c) Fantasma redirects back to your callback with a code");
    println!("   d) Exchange the code for tokens");
    println!();

    // Step 4: Verify claims from ID token
    println!("4. Example: Verifying claims from an ID token");
    println!();

    // Simulated ID token claims
    let example_claims = serde_json::json!({
        "sub": "zkid:abc123",
        "iss": FANTASMA_ISSUER,
        "aud": CLIENT_ID,
        "exp": 9999999999u64,
        "iat": 1700000000u64,
        "nonce": nonce,
        "zk_age_claim": {
            "verified": true,
            "threshold": 21,
            "proof_ref": null,
            "circuit_version": "age_v1"
        },
        "zk_kyc_claim": {
            "verified": true,
            "level": "basic",
            "proof_ref": null,
            "max_age": 31536000
        }
    });

    println!("   Example claims: {}", serde_json::to_string_pretty(&example_claims)?);
    println!();

    // Verify age claim
    if let Some(age_claim) = example_claims.get("zk_age_claim") {
        let verified = age_claim["verified"].as_bool().unwrap_or(false);
        let threshold = age_claim["threshold"].as_u64().unwrap_or(0) as u8;

        if verified && threshold >= 21 {
            println!("   ✓ Age verification PASSED (21+)");
        } else {
            println!("   ✗ Age verification FAILED");
        }
    }

    // Verify KYC claim
    if let Some(kyc_claim) = example_claims.get("zk_kyc_claim") {
        let verified = kyc_claim["verified"].as_bool().unwrap_or(false);
        let level = kyc_claim["level"].as_str().unwrap_or("");

        if verified && (level == "basic" || level == "enhanced" || level == "accredited") {
            println!("   ✓ KYC verification PASSED ({})", level);
        } else {
            println!("   ✗ KYC verification FAILED");
        }
    }

    println!();
    println!("5. Key Benefits:");
    println!("   • No personal data (birthdate, address) was revealed");
    println!("   • Cryptographic proof verifies the claims");
    println!("   • User maintains privacy while proving eligibility");
    println!("   • STARK proofs are post-quantum secure");

    Ok(())
}
