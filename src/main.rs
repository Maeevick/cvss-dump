mod commands;
mod cvss;
mod domain;
mod storage;

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
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

/// Parses CLI arguments and dispatches to the appropriate command handler.
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::New => commands::cmd_new(),
        Commands::Open { session } => commands::cmd_open(&session),
        Commands::List => commands::cmd_list(),
        Commands::Report { session } => commands::cmd_report(&session),
    }
}
