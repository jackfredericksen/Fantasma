//! Example: ZK Proof Generation
//!
//! This example demonstrates how to generate zero-knowledge proofs
//! for various claim types using Fantasma.
//!
//! Run with: cargo run --example proof_generation

use fantasma_stark::{MockBackend, ProverBackendTrait, ProverConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔════════════════════════════════════════╗");
    println!("║   Fantasma Proof Generation Example    ║");
    println!("╚════════════════════════════════════════╝");
    println!();

    // Initialize the prover backend
    // In production, you would use StoneBackend for real STARK proofs
    let prover = MockBackend::new();

    println!("Prover backend: {}", prover.name());
    println!();

    // Example 1: Age Verification Proof
    println!("═══════════════════════════════════════");
    println!("Example 1: Age Verification Proof");
    println!("═══════════════════════════════════════");
    println!();
    println!("Scenario: Prove user is 21+ without revealing birthdate");
    println!();

    // Private inputs (witness) - never revealed
    let private_inputs = vec![
        "19900115".to_string(), // birthdate: Jan 15, 1990
        "salt_12345".to_string(), // random salt
    ];

    // Public inputs - verifier sees these
    let public_inputs = vec![
        "21".to_string(),        // threshold age
        "20260212".to_string(),  // verification date
        "commitment_hash".to_string(), // credential commitment
    ];

    let result = prover.prove("age_verification", &private_inputs, &public_inputs)?;

    println!("Proof generated!");
    println!("  Proof size: {} bytes (~{} KB)", result.size_bytes, result.size_bytes / 1024);
    println!("  Proving time: {} ms", result.proving_time_ms);
    println!("  Public inputs: {:?}", result.public_inputs);
    println!();
    println!("Note: The actual birthdate (Jan 15, 1990) is NOT in the proof!");
    println!("The verifier only learns that the user is at least 21 years old.");
    println!();

    // Verify the proof
    let verify_result = prover.verify("age_verification", &result.proof_bytes, &public_inputs)?;
    println!(
        "Verification: {}",
        if verify_result.valid { "✓ VALID" } else { "✗ INVALID" }
    );
    println!();

    // Example 2: KYC Verification Proof
    println!("═══════════════════════════════════════");
    println!("Example 2: KYC Verification Proof");
    println!("═══════════════════════════════════════");
    println!();
    println!("Scenario: Prove KYC Enhanced status without revealing personal data");
    println!();

    let kyc_private = vec![
        "user_id_hash".to_string(),
        "kyc_provider_id".to_string(),
        "2".to_string(), // KYC level: Enhanced
        "1700000000".to_string(), // verification timestamp
        "kyc_data_hash".to_string(),
    ];

    let kyc_public = vec![
        "2".to_string(),        // expected level (Enhanced)
        "31536000".to_string(), // max age: 1 year
        "1705000000".to_string(), // current timestamp
        "provider_pubkey_hash".to_string(),
    ];

    let kyc_result = prover.prove("kyc_verification", &kyc_private, &kyc_public)?;

    println!("Proof generated!");
    println!("  Proof size: {} bytes", kyc_result.size_bytes);
    println!("  Proving time: {} ms", kyc_result.proving_time_ms);
    println!();
    println!("The verifier learns:");
    println!("  • User has KYC Enhanced status");
    println!("  • KYC was done within the last year");
    println!("  • KYC was done by a trusted provider");
    println!();
    println!("The verifier does NOT learn:");
    println!("  • User's real identity");
    println!("  • User's address, SSN, etc.");
    println!("  • Which specific KYC checks were performed");
    println!();

    // Example 3: Credential Verification Proof
    println!("═══════════════════════════════════════");
    println!("Example 3: Credential Verification Proof");
    println!("═══════════════════════════════════════");
    println!();
    println!("Scenario: Prove possession of a degree without revealing details");
    println!();

    let cred_private = vec![
        "credential_id".to_string(),
        "degree_type".to_string(),
        "university".to_string(),
        "graduation_year".to_string(),
    ];

    let cred_public = vec![
        "merkle_root".to_string(),
        "credential_type_hash".to_string(),
    ];

    let cred_result = prover.prove("credential_verification", &cred_private, &cred_public)?;

    println!("Proof generated!");
    println!("  Proof size: {} bytes", cred_result.size_bytes);
    println!();
    println!("The verifier learns:");
    println!("  • User holds a valid credential");
    println!("  • Credential is in the issuer's Merkle tree");
    println!();
    println!("The verifier does NOT learn:");
    println!("  • Which specific degree");
    println!("  • Which university");
    println!("  • Graduation year or GPA");
    println!();

    // Summary
    println!("═══════════════════════════════════════");
    println!("Summary: Post-Quantum ZK Proofs");
    println!("═══════════════════════════════════════");
    println!();
    println!("Fantasma uses STARK proofs which are:");
    println!("  • Post-quantum secure (hash-based, not ECC)");
    println!("  • Transparent (no trusted setup required)");
    println!("  • Efficient verification (~10-50ms)");
    println!();
    println!("Trade-offs:");
    println!("  • Larger proof size (~50-200 KB vs ~200 bytes for SNARKs)");
    println!("  • Longer proving time (~10-30 seconds vs ~1-5 seconds)");
    println!();
    println!("For identity verification, the privacy and quantum");
    println!("resistance benefits outweigh the size/time costs.");

    Ok(())
}
