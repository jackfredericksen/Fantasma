//! Status command - show configuration and status

use anyhow::Result;
use console::style;

pub async fn show() -> Result<()> {
    println!(
        "\n{}",
        style("╔════════════════════════════════════════╗").cyan()
    );
    println!(
        "{}",
        style("║   🔮 Fantasma Status                  ║").cyan()
    );
    println!(
        "{}",
        style("╚════════════════════════════════════════╝").cyan()
    );
    println!();

    // Version info
    println!("{}", style("Version").bold().underlined());
    println!("  fantasma-cli:    {}", env!("CARGO_PKG_VERSION"));
    println!();

    // Environment
    println!("{}", style("Environment").bold().underlined());
    println!(
        "  DATABASE_URL:    {}",
        if std::env::var("DATABASE_URL").is_ok() {
            style("Set").green()
        } else {
            style("Not set (using in-memory)").yellow()
        }
    );
    println!(
        "  FANTASMA_BIND:   {}",
        std::env::var("FANTASMA_BIND").unwrap_or_else(|_| "0.0.0.0:3000 (default)".to_string())
    );
    println!(
        "  FANTASMA_ISSUER: {}",
        std::env::var("FANTASMA_ISSUER")
            .unwrap_or_else(|_| "http://localhost:3000 (default)".to_string())
    );
    println!();

    // Prover backend
    println!("{}", style("Prover Backend").bold().underlined());
    let backend = std::env::var("FANTASMA_PROVER_BACKEND").unwrap_or_else(|_| "mock".to_string());
    println!(
        "  Backend:         {}",
        match backend.as_str() {
            "mock" => style("Mock (development)").yellow(),
            "stone" => style("Stone Prover").green(),
            "stwo" => style("Stwo (experimental)").cyan(),
            other => style(other).dim(),
        }
    );

    if backend == "stone" {
        println!(
            "  STONE_PROVER_PATH: {}",
            std::env::var("STONE_PROVER_PATH").unwrap_or_else(|_| "Not set".to_string())
        );
    }
    println!();

    // Supported circuits
    println!("{}", style("Supported Circuits").bold().underlined());
    println!("  • age_verification      - Prove age >= threshold");
    println!("  • credential_verification - Prove credential ownership");
    println!("  • kyc_verification      - Prove KYC status");
    println!();

    // Cryptography
    println!("{}", style("Cryptography").bold().underlined());
    println!("  Signatures:      Dilithium3 (NIST ML-DSA)");
    println!("  Hash:            Poseidon (STARK-friendly)");
    println!("  Proofs:          STARK (post-quantum secure)");
    println!();

    // Quick help
    println!("{}", style("Quick Start").bold().underlined());
    println!("  Start server:    fantasma server");
    println!("  List clients:    fantasma client list");
    println!("  Generate proof:  fantasma proof generate -c age -i input.json -o proof.json");
    println!("  Show help:       fantasma --help");

    Ok(())
}
