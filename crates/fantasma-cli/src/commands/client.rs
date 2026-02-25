//! Client management commands

use anyhow::Result;
use console::style;

/// List registered clients
pub async fn list() -> Result<()> {
    println!("\n{}", style("Registered OIDC Clients").bold().underlined());
    println!();

    // Demo clients (always available)
    let demo_clients = vec![
        (
            "demo-client",
            "Demo Client",
            vec!["http://localhost:8080/callback"],
        ),
        (
            "demo-rp",
            "Demo Relying Party",
            vec!["http://localhost:8080/callback"],
        ),
        (
            "fantasma-wallet",
            "Fantasma Wallet",
            vec!["chrome-extension://*/callback"],
        ),
    ];

    for (id, name, uris) in demo_clients {
        println!("  {} {}", style("●").green(), style(name).bold());
        println!("    ID: {}", style(id).cyan());
        println!(
            "    Redirect URIs: {}",
            uris.iter()
                .map(|u| u.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!();
    }

    println!(
        "{}",
        style("Note: Additional clients can be registered with --database-url").dim()
    );

    Ok(())
}

/// Register a new client
pub async fn register(name: String, redirect_uris: String, public: bool) -> Result<()> {
    let client_id = format!("client_{}", uuid::Uuid::new_v4().simple());
    let client_secret = if public {
        None
    } else {
        Some(uuid::Uuid::new_v4().to_string())
    };

    let uris: Vec<&str> = redirect_uris.split(',').map(|s| s.trim()).collect();

    println!("\n{}", style("Client Registered").bold().green());
    println!();
    println!("  Name:          {}", style(&name).cyan());
    println!("  Client ID:     {}", style(&client_id).yellow());
    if let Some(ref secret) = client_secret {
        println!("  Client Secret: {}", style(secret).red());
        println!(
            "  {}",
            style("⚠️  Store this secret securely - it won't be shown again!").red()
        );
    } else {
        println!("  Type:          {}", style("Public Client").dim());
    }
    println!("  Redirect URIs:");
    for uri in uris {
        println!("    - {}", uri);
    }

    println!();
    println!(
        "{}",
        style("Note: Without --database-url, registration is not persisted.").yellow()
    );

    Ok(())
}

/// Show client details
pub async fn show(client_id: &str) -> Result<()> {
    println!("\n{}", style("Client Details").bold().underlined());
    println!();

    // Check demo clients
    match client_id {
        "demo-client" => {
            println!("  Name:          Demo Client");
            println!("  Client ID:     {}", style("demo-client").cyan());
            println!("  Type:          Confidential");
            println!("  Redirect URIs:");
            println!("    - http://localhost:8080/callback");
            println!("    - https://oauth.pstmn.io/v1/callback");
        }
        "demo-rp" => {
            println!("  Name:          Demo Relying Party");
            println!("  Client ID:     {}", style("demo-rp").cyan());
            println!("  Type:          Confidential");
            println!("  Redirect URIs:");
            println!("    - http://localhost:8080/callback");
        }
        "fantasma-wallet" => {
            println!("  Name:          Fantasma Wallet");
            println!("  Client ID:     {}", style("fantasma-wallet").cyan());
            println!("  Type:          Public");
            println!("  Redirect URIs:");
            println!("    - chrome-extension://*/callback");
            println!("    - moz-extension://*/callback");
        }
        _ => {
            println!(
                "  {}",
                style(format!("Client '{}' not found", client_id)).red()
            );
        }
    }

    Ok(())
}
