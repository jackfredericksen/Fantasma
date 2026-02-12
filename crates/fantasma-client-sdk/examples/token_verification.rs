//! Example: ID Token Verification
//!
//! This example shows how to verify ID tokens with ZK claims
//! returned from the Fantasma OIDC provider.
//!
//! Run with: cargo run --example token_verification

use base64::Engine;
use serde::{Deserialize, Serialize};

/// ID Token Claims structure
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    // Standard OIDC claims
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    nonce: Option<String>,

    // Fantasma ZK claims
    zk_age_claim: Option<ZkAgeClaim>,
    zk_kyc_claim: Option<ZkKycClaim>,
    zk_credential_claim: Option<ZkCredentialClaim>,
}

#[derive(Debug, Deserialize)]
struct ZkAgeClaim {
    verified: bool,
    threshold: u8,
    proof_ref: Option<ProofRef>,
    circuit_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ZkKycClaim {
    verified: bool,
    level: String,
    proof_ref: Option<ProofRef>,
    max_age: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ZkCredentialClaim {
    verified: bool,
    credential_type: String,
    proof_ref: Option<ProofRef>,
}

#[derive(Debug, Deserialize)]
struct ProofRef {
    id: String,
    hash: String,
    url: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔════════════════════════════════════════╗");
    println!("║   Fantasma Token Verification Example  ║");
    println!("╚════════════════════════════════════════╝");
    println!();

    // Simulated ID token (in practice, this comes from the token endpoint)
    let id_token = create_example_token();

    println!("1. Received ID Token (truncated):");
    println!("   {}...{}", &id_token[..50], &id_token[id_token.len()-20..]);
    println!();

    // Decode the token (without signature verification for this example)
    let claims = decode_token(&id_token)?;

    println!("2. Decoded Claims:");
    println!("   Issuer:  {}", claims.iss);
    println!("   Subject: {}", claims.sub);
    println!("   Audience: {}", claims.aud);
    println!();

    // Verify ZK claims
    println!("3. Verifying ZK Claims:");
    println!();

    // Age claim
    if let Some(ref age_claim) = claims.zk_age_claim {
        println!("   Age Claim:");
        println!("     Threshold: {}+", age_claim.threshold);
        println!("     Verified:  {}", if age_claim.verified { "✓ YES" } else { "✗ NO" });

        if age_claim.verified {
            println!("     → User is verified to be {} years or older", age_claim.threshold);
        } else {
            println!("     → User did NOT meet the age requirement");
        }

        if let Some(ref proof) = age_claim.proof_ref {
            println!("     Proof ID: {}", proof.id);
            println!("     Proof Hash: {}", proof.hash);
        }
        println!();
    }

    // KYC claim
    if let Some(ref kyc_claim) = claims.zk_kyc_claim {
        println!("   KYC Claim:");
        println!("     Level:    {}", kyc_claim.level);
        println!("     Verified: {}", if kyc_claim.verified { "✓ YES" } else { "✗ NO" });

        if kyc_claim.verified {
            println!("     → User has {} KYC verification", kyc_claim.level);
        } else {
            println!("     → User did NOT meet the KYC requirement");
        }

        if let Some(max_age) = kyc_claim.max_age {
            println!("     Max Age: {} seconds ({} days)", max_age, max_age / 86400);
        }
        println!();
    }

    // Credential claim
    if let Some(ref cred_claim) = claims.zk_credential_claim {
        println!("   Credential Claim:");
        println!("     Type:     {}", cred_claim.credential_type);
        println!("     Verified: {}", if cred_claim.verified { "✓ YES" } else { "✗ NO" });

        if cred_claim.verified {
            println!("     → User holds a valid '{}' credential", cred_claim.credential_type);
        } else {
            println!("     → User does NOT hold the required credential");
        }
        println!();
    }

    // Access control decision
    println!("4. Access Control Decision:");
    println!();

    let age_ok = claims.zk_age_claim.as_ref().map(|c| c.verified).unwrap_or(false);
    let kyc_ok = claims.zk_kyc_claim.as_ref().map(|c| c.verified).unwrap_or(false);

    if age_ok && kyc_ok {
        println!("   ✓ ACCESS GRANTED");
        println!("     User meets all requirements:");
        println!("     • Age: 21+");
        println!("     • KYC: Basic or higher");
    } else {
        println!("   ✗ ACCESS DENIED");
        if !age_ok {
            println!("     • Failed age verification");
        }
        if !kyc_ok {
            println!("     • Failed KYC verification");
        }
    }

    println!();
    println!("5. Privacy Preservation:");
    println!("   The service ONLY knows:");
    println!("   • User is 21+ (not their actual age)");
    println!("   • User has KYC (not their personal data)");
    println!("   • User's pseudonymous ID (not their real identity)");
    println!();
    println!("   The service does NOT know:");
    println!("   • User's birthdate");
    println!("   • User's name or address");
    println!("   • User's SSN or government ID");

    Ok(())
}

fn create_example_token() -> String {
    // Create a mock ID token for demonstration
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        r#"{"alg":"RS256","typ":"JWT"}"#
    );

    let claims = serde_json::json!({
        "iss": "http://localhost:3000",
        "sub": "zkid:abc123def456",
        "aud": "demo-client",
        "exp": 1999999999u64,
        "iat": 1700000000u64,
        "nonce": "random_nonce_value",
        "zk_age_claim": {
            "verified": true,
            "threshold": 21,
            "proof_ref": {
                "id": "prf_age_12345",
                "hash": "0xabcdef123456789...",
                "url": "http://localhost:3000/proofs/prf_age_12345"
            },
            "circuit_version": "age_v1"
        },
        "zk_kyc_claim": {
            "verified": true,
            "level": "basic",
            "proof_ref": {
                "id": "prf_kyc_67890",
                "hash": "0x987654321fedcba...",
                "url": "http://localhost:3000/proofs/prf_kyc_67890"
            },
            "max_age": 31536000
        }
    });

    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&claims).unwrap()
    );

    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        "mock_signature_for_demonstration"
    );

    format!("{}.{}.{}", header, payload, signature)
}

fn decode_token(token: &str) -> Result<IdTokenClaims, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid token format".into());
    }

    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?;
    let claims: IdTokenClaims = serde_json::from_slice(&payload)?;

    // In production, you would also:
    // 1. Verify the signature using JWKS
    // 2. Check exp > now
    // 3. Check iss matches expected issuer
    // 4. Check aud matches your client_id
    // 5. Check nonce matches your stored nonce

    Ok(claims)
}
