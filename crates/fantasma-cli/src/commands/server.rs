//! Server command - starts the Fantasma OIDC server

use anyhow::Result;
use console::style;

pub async fn run(bind: String, _database_url: Option<String>) -> Result<()> {
    println!(
        "\n{}",
        style("╔════════════════════════════════════════╗").cyan()
    );
    println!(
        "{}",
        style("║   🔮 Fantasma Identity Provider       ║").cyan()
    );
    println!(
        "{}",
        style("║   Post-Quantum ZK Identity Layer      ║").cyan()
    );
    println!(
        "{}",
        style("╚════════════════════════════════════════╝").cyan()
    );
    println!();

    println!(
        "{}",
        style("Use 'cargo run -p fantasma-server' to start the full server.").yellow()
    );
    println!();
    println!("Server would bind to: {}", style(&bind).green());

    // Note: The actual server implementation is in fantasma-server crate
    // This command provides a convenience wrapper

    println!();
    println!("{}", style("Endpoints:").bold());
    println!(
        "  Discovery:     {}/.well-known/openid-configuration",
        format!("http://{}", bind)
    );
    println!("  Authorization: {}/authorize", format!("http://{}", bind));
    println!("  Token:         {}/token", format!("http://{}", bind));
    println!(
        "  JWKS:          {}/.well-known/jwks.json",
        format!("http://{}", bind)
    );
    println!();
    println!("{}", style("ZK Scopes:").bold());
    println!("  zk:age:18+      - Prove age >= 18");
    println!("  zk:age:21+      - Prove age >= 21");
    println!("  zk:kyc:basic    - Prove KYC Basic status");
    println!("  zk:kyc:enhanced - Prove KYC Enhanced status");
    println!("  zk:credential:* - Prove credential ownership");

    Ok(())
}
