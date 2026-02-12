//! Fantasma CLI
//!
//! Command-line interface for the Fantasma zero-knowledge identity provider.

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod commands;

#[derive(Parser)]
#[command(name = "fantasma")]
#[command(author, version, about = "Fantasma: Post-quantum ZK identity layer", long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Fantasma server
    Server {
        /// Address to bind to
        #[arg(short, long, default_value = "0.0.0.0:3000", env = "FANTASMA_BIND")]
        bind: String,

        /// Database URL (optional, uses in-memory storage if not set)
        #[arg(long, env = "DATABASE_URL")]
        database_url: Option<String>,
    },

    /// Manage OIDC clients
    Client {
        #[command(subcommand)]
        action: ClientAction,
    },

    /// Generate and verify ZK proofs
    Proof {
        #[command(subcommand)]
        action: ProofAction,
    },

    /// Credential operations
    Credential {
        #[command(subcommand)]
        action: CredentialAction,
    },

    /// Show configuration and status
    Status,
}

#[derive(Subcommand)]
enum ClientAction {
    /// List registered clients
    List,

    /// Register a new client
    Register {
        /// Client name
        #[arg(short, long)]
        name: String,

        /// Redirect URIs (comma-separated)
        #[arg(short, long)]
        redirect_uris: String,

        /// Client is public (no secret required)
        #[arg(long)]
        public: bool,
    },

    /// Show client details
    Show {
        /// Client ID
        client_id: String,
    },
}

#[derive(Subcommand)]
enum ProofAction {
    /// Generate a ZK proof
    Generate {
        /// Circuit type (age, kyc, credential)
        #[arg(short, long)]
        circuit: String,

        /// Private input file (JSON)
        #[arg(short, long)]
        input: String,

        /// Output proof file
        #[arg(short, long)]
        output: String,
    },

    /// Verify a ZK proof
    Verify {
        /// Proof file
        #[arg(short, long)]
        proof: String,

        /// Public inputs file (JSON)
        #[arg(short, long)]
        public_inputs: String,
    },

    /// Show proof details
    Info {
        /// Proof file
        proof: String,
    },
}

#[derive(Subcommand)]
enum CredentialAction {
    /// Generate a sample credential
    Generate {
        /// Credential type (identity, kyc, degree)
        #[arg(short = 't', long)]
        credential_type: String,

        /// Output file
        #[arg(short, long)]
        output: String,
    },

    /// Verify a credential signature
    Verify {
        /// Credential file
        credential: String,
    },

    /// Import a credential
    Import {
        /// Credential file
        file: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| format!("fantasma={}", log_level)),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    match cli.command {
        Commands::Server { bind, database_url } => {
            commands::server::run(bind, database_url).await?;
        }
        Commands::Client { action } => match action {
            ClientAction::List => commands::client::list().await?,
            ClientAction::Register {
                name,
                redirect_uris,
                public,
            } => {
                commands::client::register(name, redirect_uris, public).await?;
            }
            ClientAction::Show { client_id } => {
                commands::client::show(&client_id).await?;
            }
        },
        Commands::Proof { action } => match action {
            ProofAction::Generate {
                circuit,
                input,
                output,
            } => {
                commands::proof::generate(&circuit, &input, &output).await?;
            }
            ProofAction::Verify {
                proof,
                public_inputs,
            } => {
                commands::proof::verify(&proof, &public_inputs).await?;
            }
            ProofAction::Info { proof } => {
                commands::proof::info(&proof).await?;
            }
        },
        Commands::Credential { action } => match action {
            CredentialAction::Generate {
                credential_type,
                output,
            } => {
                commands::credential::generate(&credential_type, &output).await?;
            }
            CredentialAction::Verify { credential } => {
                commands::credential::verify(&credential).await?;
            }
            CredentialAction::Import { file } => {
                commands::credential::import(&file).await?;
            }
        },
        Commands::Status => {
            commands::status::show().await?;
        }
    }

    Ok(())
}
