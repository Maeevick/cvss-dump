use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cvss-dump")]
#[command(
    about = "CLI/TUI tool for logging structured security findings and exporting client-ready markdown reports"
)]
#[command(version = "0.1.0")]
/// Top-level CLI entry point that dispatches to subcommands.
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
/// Available subcommands for managing and exporting pentest sessions.
enum Commands {
    /// Create a new session
    New,
    /// Open session in TUI
    Open { session: String },
    /// List all sessions
    List,
    /// Export session to markdown
    Report { session: String },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::New => {
            println!("Creating new session...");
            // TODO: Implement interactive session creation
        }
        Commands::Open { session } => {
            println!("Opening session: {}", session);
            // TODO: Implement TUI session opening
        }
        Commands::List => {
            println!("Listing sessions...");
            // TODO: Implement session listing
        }
        Commands::Report { session } => {
            println!("Generating report for session: {}", session);
            // TODO: Implement markdown report generation
        }
    }
}
