//! Database management commands

use anyhow::Result;
use fantasma_db::pool::{DatabaseConfig, DatabasePool};

/// Run database migrations
pub async fn migrate(database_url: Option<String>) -> Result<()> {
    let config = match database_url {
        Some(url) => DatabaseConfig {
            url,
            ..DatabaseConfig::default()
        },
        None => DatabaseConfig::from_env(),
    };

    println!("Connecting to database...");
    let pool = DatabasePool::new(&config)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    println!("Running migrations...");
    pool.run_migrations()
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    println!("Migrations completed successfully.");
    pool.close().await;

    Ok(())
}

/// Show database status
pub async fn status(database_url: Option<String>) -> Result<()> {
    let config = match database_url {
        Some(url) => DatabaseConfig {
            url,
            ..DatabaseConfig::default()
        },
        None => DatabaseConfig::from_env(),
    };

    println!("Connecting to database...");
    let pool = match DatabasePool::new(&config).await {
        Ok(pool) => pool,
        Err(e) => {
            println!("Failed to connect: {}", e);
            return Ok(());
        }
    };

    match pool.health_check().await {
        Ok(true) => println!("Database: connected"),
        Ok(false) => println!("Database: unhealthy"),
        Err(e) => println!("Database: error - {}", e),
    }

    let stats = pool.stats();
    println!("Pool size: {}", stats.size);
    println!("Idle connections: {}", stats.idle);

    // Count records in each table
    let pg_pool = pool.pool();
    let tables = [
        "clients",
        "auth_codes",
        "refresh_tokens",
        "proofs",
        "nullifiers",
        "credentials",
        "issuers",
        "audit_log",
    ];

    println!("\nTable counts:");
    for table in &tables {
        match sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {}", table))
            .fetch_one(pg_pool)
            .await
        {
            Ok(count) => println!("  {}: {}", table, count),
            Err(_) => println!("  {}: (table not found)", table),
        }
    }

    pool.close().await;
    Ok(())
}

/// Seed the database with demo data
pub async fn seed(database_url: Option<String>) -> Result<()> {
    let config = match database_url {
        Some(url) => DatabaseConfig {
            url,
            ..DatabaseConfig::default()
        },
        None => DatabaseConfig::from_env(),
    };

    println!("Connecting to database...");
    let pool = DatabasePool::new(&config)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let repos = fantasma_db::pool::Repositories::new(&pool);

    // Seed demo clients
    let demo_clients = vec![
        fantasma_db::models::NewClient {
            client_id: "demo-client".to_string(),
            client_secret_hash: None,
            client_name: "Demo Client".to_string(),
            redirect_uris: vec![
                "http://localhost:8080/callback".to_string(),
                "https://oauth.pstmn.io/v1/callback".to_string(),
            ],
            allowed_scopes: vec![
                "openid".to_string(),
                "zk:age:18+".to_string(),
                "zk:age:21+".to_string(),
                "zk:kyc:basic".to_string(),
            ],
            client_type: "confidential".to_string(),
        },
        fantasma_db::models::NewClient {
            client_id: "demo-rp".to_string(),
            client_secret_hash: None,
            client_name: "Demo Relying Party".to_string(),
            redirect_uris: vec!["http://localhost:8080/callback".to_string()],
            allowed_scopes: vec!["openid".to_string(), "zk:age:21+".to_string()],
            client_type: "confidential".to_string(),
        },
    ];

    println!("Seeding clients...");
    for client in demo_clients {
        match repos.clients().create(client).await {
            Ok(c) => println!("  Created client: {}", c.client_id),
            Err(e) => println!("  Skipped (already exists?): {}", e),
        }
    }

    // Seed demo issuers
    let demo_issuers = vec![fantasma_db::models::NewIssuer {
        issuer_id: "demo-issuer".to_string(),
        name: "Demo Identity Issuer".to_string(),
        public_key: vec![0u8; 32], // Placeholder
        public_key_algorithm: "dilithium3".to_string(),
        verification_url: Some("http://localhost:3000".to_string()),
        trusted: true,
    }];

    println!("Seeding issuers...");
    for issuer in demo_issuers {
        match repos.issuers().create(issuer).await {
            Ok(i) => println!("  Created issuer: {}", i.issuer_id),
            Err(e) => println!("  Skipped (already exists?): {}", e),
        }
    }

    println!("Seeding complete.");
    pool.close().await;
    Ok(())
}
