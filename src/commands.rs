use std::io::{Write, stdin, stdout};

use chrono::Utc;

use crate::domain::Session;
use crate::storage;

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
    Ok(buf.trim_end_matches('\n').trim_end_matches('\r').to_string())
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

/// Handles the `open` subcommand — opens an existing session in the TUI.
pub fn cmd_open(session: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Not yet implemented: open (session: {session})");
    Err(Box::from("not yet implemented"))
}

/// Handles the `list` subcommand — lists all recorded sessions.
pub fn cmd_list() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Not yet implemented: list");
    Err(Box::from("not yet implemented"))
}

/// Handles the `report` subcommand — exports a session to a markdown report.
pub fn cmd_report(session: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Not yet implemented: report (session: {session})");
    Err(Box::from("not yet implemented"))
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
