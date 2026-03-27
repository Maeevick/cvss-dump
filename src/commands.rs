use std::fs;
use std::io::{Write, stdin, stdout};

use chrono::Utc;

use crate::domain::Session;
use crate::report;
use crate::storage;
use crate::tui;

/// Returns `true` when `name` is a valid session slug: non-empty and
/// composed exclusively of ASCII alphanumeric characters or hyphens (`-`).
pub fn is_valid_slug(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Prompts the user for a session name on stdout and reads a line from stdin.
fn prompt_line(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    print!("{prompt}");
    stdout().flush()?;
    let mut buf = String::new();
    stdin().read_line(&mut buf)?;
    Ok(buf
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string())
}

/// Handles the `new` subcommand — creates a new pentest session.
///
/// Interactively prompts for a session name (slug-safe, non-duplicate) and
/// one or more scope entries, then persists the session via `storage::save_session`.
pub fn cmd_new() -> Result<(), Box<dyn std::error::Error>> {
    let name = loop {
        let raw = prompt_line("Session name: ")?;

        if !is_valid_slug(&raw) {
            eprintln!("Invalid session name. Use alphanumeric characters and hyphens only.");
            continue;
        }

        match storage::session_path(&raw) {
            Ok(path) if path.exists() => {
                eprintln!("Session '{raw}' already exists. Choose a different name.");
                continue;
            }
            Err(e) => return Err(Box::new(e)),
            _ => break raw,
        }
    };

    let scope = loop {
        let mut entries: Vec<String> = Vec::new();

        loop {
            let raw = prompt_line("Scope entry (empty line to finish): ")?;
            if raw.is_empty() {
                break;
            }
            entries.push(raw);
        }

        if entries.is_empty() {
            eprintln!("At least one scope entry is required.");
            continue;
        }

        break entries;
    };

    let now = Utc::now();
    let session = Session {
        name: name.clone(),
        scope,
        findings: vec![],
        created_at: now,
        updated_at: now,
    };

    storage::save_session(&session).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    println!("Session '{name}' created.");
    Ok(())
}

/// Handles the `open` subcommand — loads the named session and launches the TUI.
///
/// Returns `Err` with a user-facing message when the session does not exist or
/// is corrupted. Any other storage or TUI error is propagated to the caller.
pub fn cmd_open(session_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let dir = storage::storage_dir().map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    cmd_open_from(session_name, &dir)
}

/// Testable variant of `cmd_open` that loads from `base_dir` instead of the default storage dir.
pub fn cmd_open_from(
    session_name: &str,
    base_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let session = storage::load_session_from(session_name, base_dir).map_err(|e| {
        match &e {
            storage::StorageError::SessionNotFound(_) => Box::from(format!(
                "Session '{session_name}' not found. Run 'cvss-dump list' to see available sessions."
            )),
            storage::StorageError::CorruptedJson(_) => {
                let path = base_dir
                    .join(format!("{session_name}.json"))
                    .display()
                    .to_string();
                Box::from(format!(
                    "Session '{session_name}' is corrupted ({path}). Run 'cvss-dump repair {session_name}' to attempt recovery."
                ))
            }
            _ => Box::new(e) as Box<dyn std::error::Error>,
        }
    })?;

    tui::run_tui(session)
}

/// A single row of data collected for the session list table.
struct SessionRow {
    name: String,
    findings: String,
    created: String,
}

/// Handles the `list` subcommand — lists all recorded sessions.
///
/// Prints a left-aligned table of sessions sorted alphabetically.
/// Columns: Name | Findings | Created.
/// If a session file cannot be loaded, its row shows `<corrupted>` and `unknown`
/// rather than aborting the entire listing.
pub fn cmd_list() -> Result<(), Box<dyn std::error::Error>> {
    let names = storage::list_sessions().map_err(|e| {
        eprintln!("Error listing sessions: {e}");
        Box::new(e) as Box<dyn std::error::Error>
    })?;

    if names.is_empty() {
        println!("No sessions found.");
        return Ok(());
    }

    let rows: Vec<SessionRow> = names
        .iter()
        .map(|name| match storage::load_session(name) {
            Ok(session) => SessionRow {
                name: name.clone(),
                findings: session.findings.len().to_string(),
                created: session.created_at.format("%Y-%m-%d").to_string(),
            },
            Err(_) => SessionRow {
                name: name.clone(),
                findings: "<corrupted>".to_string(),
                created: "unknown".to_string(),
            },
        })
        .collect();

    let col_name = "Name";
    let col_findings = "Findings";
    let col_created = "Created";

    let name_width = rows
        .iter()
        .map(|r| r.name.len())
        .max()
        .unwrap_or(0)
        .max(col_name.len());
    let findings_width = rows
        .iter()
        .map(|r| r.findings.len())
        .max()
        .unwrap_or(0)
        .max(col_findings.len());
    let created_width = rows
        .iter()
        .map(|r| r.created.len())
        .max()
        .unwrap_or(0)
        .max(col_created.len());

    println!(
        "{:<name_width$}  {:<findings_width$}  {:<created_width$}",
        col_name, col_findings, col_created
    );
    println!(
        "{:<name_width$}  {:<findings_width$}  {:<created_width$}",
        "-".repeat(name_width),
        "-".repeat(findings_width),
        "-".repeat(created_width)
    );

    for row in &rows {
        println!(
            "{:<name_width$}  {:<findings_width$}  {:<created_width$}",
            row.name, row.findings, row.created
        );
    }

    Ok(())
}

/// Handles the `report` subcommand — exports a session to a markdown report.
///
/// Loads the named session, guards against zero findings, generates the
/// markdown content, and writes it atomically to `<session>-report.md` in the
/// current working directory.
pub fn cmd_report(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !is_valid_slug(name) {
        return Err(Box::from(format!(
            "Invalid session name '{}'. Session names must be alphanumeric and hyphens only.",
            name
        )));
    }

    let dir = storage::storage_dir().map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    cmd_report_from(name, &dir)
}

/// Testable variant of `cmd_report` that loads from `base_dir` and writes the report
/// to the current working directory.
pub fn cmd_report_from(
    name: &str,
    base_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let session = match storage::load_session_from(name, base_dir) {
        Ok(session) => session,
        Err(storage::StorageError::SessionNotFound(_)) => {
            return Err(Box::from(format!(
                "Session '{name}' not found. Run 'cvss-dump list' to see available sessions."
            )));
        }
        Err(storage::StorageError::CorruptedJson(_)) => {
            let path = base_dir
                .join(format!("{name}.json"))
                .display()
                .to_string();
            return Err(Box::from(format!(
                "Session '{name}' is corrupted ({path}). Run 'cvss-dump repair {name}' to attempt recovery."
            )));
        }
        Err(e) => return Err(Box::new(e)),
    };

    if session.findings.is_empty() {
        return Err(Box::from(format!(
            "Session '{name}' has no findings. Add findings before exporting."
        )));
    }

    let markdown = report::generate_report(&session);
    let filename = format!("{name}-report.md");
    let tmp_filename = format!("{filename}.tmp");

    fs::write(&tmp_filename, &markdown).map_err(|_| {
        Box::<dyn std::error::Error>::from("Cannot write to current directory. Check permissions.")
    })?;

    fs::rename(&tmp_filename, &filename).map_err(|_| {
        let _ = fs::remove_file(&tmp_filename);
        Box::<dyn std::error::Error>::from("Cannot write to current directory. Check permissions.")
    })?;

    println!("Report written to {filename}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_is_invalid_slug() {
        assert!(!is_valid_slug(""));
    }

    #[test]
    fn lowercase_alphanumeric_is_valid_slug() {
        assert!(is_valid_slug("myproject"));
    }

    #[test]
    fn uppercase_alphanumeric_is_valid_slug() {
        assert!(is_valid_slug("MyProject"));
    }

    #[test]
    fn mixed_case_with_hyphens_is_valid_slug() {
        assert!(is_valid_slug("pentest-2024-ClientA"));
    }

    #[test]
    fn digits_only_is_valid_slug() {
        assert!(is_valid_slug("12345"));
    }

    #[test]
    fn single_hyphen_is_valid_slug() {
        assert!(is_valid_slug("-"));
    }

    #[test]
    fn slug_with_space_is_invalid() {
        assert!(!is_valid_slug("my project"));
    }

    #[test]
    fn slug_with_slash_is_invalid() {
        assert!(!is_valid_slug("my/project"));
    }

    #[test]
    fn slug_with_dot_is_invalid() {
        assert!(!is_valid_slug("my.project"));
    }

    #[test]
    fn slug_with_underscore_is_invalid() {
        assert!(!is_valid_slug("my_project"));
    }

    #[test]
    fn path_traversal_is_invalid_slug() {
        assert!(!is_valid_slug("../evil"));
    }

    #[test]
    fn slug_with_at_sign_is_invalid() {
        assert!(!is_valid_slug("user@host"));
    }
}
