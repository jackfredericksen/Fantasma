//! Proof generation and verification commands

use anyhow::Result;
use console::style;
use fantasma_stark::{MockBackend, ProverBackendTrait};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::time::Duration;

/// Generate a ZK proof
pub async fn generate(circuit: &str, input_file: &str, output_file: &str) -> Result<()> {
    println!("\n{}", style("Generating ZK Proof").bold().underlined());
    println!();

    // Read input file
    let input_content = fs::read_to_string(input_file)?;
    let input: serde_json::Value = serde_json::from_str(&input_content)?;

    println!("  Circuit:       {}", style(circuit).cyan());
    println!("  Input:         {}", input_file);
    println!("  Output:        {}", output_file);
    println!();

    // Create progress bar
    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}% {msg}")?
            .progress_chars("#>-"),
    );

    // Simulate proof generation stages
    pb.set_message("Loading circuit...");
    pb.set_position(10);
    tokio::time::sleep(Duration::from_millis(200)).await;

    pb.set_message("Parsing witness...");
    pb.set_position(20);
    tokio::time::sleep(Duration::from_millis(200)).await;

    pb.set_message("Computing execution trace...");
    pb.set_position(40);
    tokio::time::sleep(Duration::from_millis(300)).await;

    pb.set_message("Generating STARK proof...");
    pb.set_position(70);

    // Actually generate proof using mock backend
    let backend = MockBackend::new();
    let private_inputs: Vec<String> = input
        .get("private")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let public_inputs: Vec<String> = input
        .get("public")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let result = backend.prove(circuit, &private_inputs, &public_inputs)?;

    pb.set_position(90);
    pb.set_message("Writing proof...");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Write proof to file
    let proof_json = serde_json::json!({
        "circuit_type": circuit,
        "proof_bytes": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &result.proof_bytes),
        "public_inputs": result.public_inputs,
        "size_bytes": result.size_bytes,
        "proving_time_ms": result.proving_time_ms,
        "generated_at": chrono::Utc::now().to_rfc3339(),
    });

    fs::write(output_file, serde_json::to_string_pretty(&proof_json)?)?;

    pb.set_position(100);
    pb.finish_with_message("Done!");
    println!();

    println!(
        "{}",
        style("✓ Proof generated successfully!").green().bold()
    );
    println!();
    println!("  Proof size:    {} bytes", style(result.size_bytes).cyan());
    println!(
        "  Proving time:  {} ms",
        style(result.proving_time_ms).cyan()
    );
    println!("  Output file:   {}", style(output_file).yellow());

    Ok(())
}

/// Verify a ZK proof
pub async fn verify(proof_file: &str, public_inputs_file: &str) -> Result<()> {
    println!("\n{}", style("Verifying ZK Proof").bold().underlined());
    println!();

    // Read proof file
    let proof_content = fs::read_to_string(proof_file)?;
    let proof: serde_json::Value = serde_json::from_str(&proof_content)?;

    // Read public inputs
    let inputs_content = fs::read_to_string(public_inputs_file)?;
    let inputs: serde_json::Value = serde_json::from_str(&inputs_content)?;

    let circuit_type = proof["circuit_type"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing circuit_type in proof"))?;

    println!("  Circuit:       {}", style(circuit_type).cyan());
    println!("  Proof file:    {}", proof_file);
    println!("  Inputs file:   {}", public_inputs_file);
    println!();

    // Create progress bar
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
    pb.set_message("Verifying proof...");

    // Decode proof bytes
    let proof_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        proof["proof_bytes"].as_str().unwrap_or(""),
    )?;

    let public_inputs: Vec<String> = inputs
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Verify using mock backend
    let backend = MockBackend::new();
    let result = backend.verify(circuit_type, &proof_bytes, &public_inputs)?;

    pb.finish_and_clear();

    if result.valid {
        println!("{}", style("✓ Proof is VALID").green().bold());
        println!();
        println!(
            "  Verification time: {} ms",
            style(result.verify_time_ms).cyan()
        );
    } else {
        println!("{}", style("✗ Proof is INVALID").red().bold());
        if let Some(error) = result.error {
            println!("  Error: {}", style(error).red());
        }
    }

    Ok(())
}

/// Show proof info
pub async fn info(proof_file: &str) -> Result<()> {
    println!("\n{}", style("Proof Information").bold().underlined());
    println!();

    let proof_content = fs::read_to_string(proof_file)?;
    let proof: serde_json::Value = serde_json::from_str(&proof_content)?;

    println!("  File:          {}", proof_file);
    println!(
        "  Circuit:       {}",
        style(proof["circuit_type"].as_str().unwrap_or("unknown")).cyan()
    );
    println!(
        "  Size:          {} bytes",
        style(proof["size_bytes"].as_u64().unwrap_or(0)).yellow()
    );
    println!(
        "  Proving time:  {} ms",
        proof["proving_time_ms"].as_u64().unwrap_or(0)
    );
    println!(
        "  Generated:     {}",
        proof["generated_at"].as_str().unwrap_or("unknown")
    );

    println!();
    println!("{}", style("Public Inputs:").bold());
    if let Some(inputs) = proof["public_inputs"].as_array() {
        for (i, input) in inputs.iter().enumerate() {
            println!("  [{}] {}", i, input);
        }
    }

    Ok(())
}
