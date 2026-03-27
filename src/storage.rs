use std::fs;
use std::path::{Path, PathBuf};

use crate::domain::Session;

/// Errors that can occur during session persistence operations.
#[derive(Debug)]
pub enum StorageError {
    /// The sessions directory could not be created.
    DirectoryCreationFailed(std::io::Error),
    /// No session file was found for the requested name.
    SessionNotFound(String),
    /// The session file exists but contains invalid JSON.
    CorruptedJson(serde_json::Error),
    /// Writing the session file failed.
    WriteFailed(std::io::Error),
    /// Reading the session file failed.
    ReadFailed(std::io::Error),
    /// The `HOME` environment variable is not set.
    HomeDirNotFound,
    /// The session name contains characters outside `[a-zA-Z0-9-]`.
    InvalidSessionName(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::DirectoryCreationFailed(e) => {
                write!(f, "failed to create sessions directory: {e}")
            }
            StorageError::SessionNotFound(name) => write!(f, "session not found: {name}"),
            StorageError::CorruptedJson(e) => write!(f, "corrupted session JSON: {e}"),
            StorageError::WriteFailed(e) => write!(f, "failed to write session file: {e}"),
            StorageError::ReadFailed(e) => write!(f, "failed to read session file: {e}"),
            StorageError::HomeDirNotFound => {
                write!(f, "HOME environment variable is not set")
            }
            StorageError::InvalidSessionName(name) => {
                write!(
                    f,
                    "invalid session name (alphanumeric and hyphens only): {name}"
                )
            }
        }
    }
}

impl std::error::Error for StorageError {}

/// Returns `~/.cvss-dump/sessions/`, creating it if it does not already exist.
pub fn storage_dir() -> Result<PathBuf, StorageError> {
    let home = std::env::var("HOME").map_err(|_| StorageError::HomeDirNotFound)?;
    let path = PathBuf::from(home).join(".cvss-dump").join("sessions");
    ensure_dir_exists(&path)?;
    Ok(path)
}

/// Returns the full filesystem path for a named session file.
pub fn session_path(name: &str) -> Result<PathBuf, StorageError> {
    let dir = storage_dir()?;
    session_path_in(&dir, name)
}

/// Serialises `session` to JSON and writes it atomically to `storage_dir()`.
///
/// Atomic write: data is written to a `.tmp` sibling file first, then renamed
/// into place. The final path is never partially written.
pub fn save_session(session: &Session) -> Result<(), StorageError> {
    let dir = storage_dir()?;
    save_session_to(session, &dir)
}

/// Deserialises and returns the named session from `storage_dir()`.
///
/// Returns `StorageError::SessionNotFound` when no file exists for `name`.
/// Returns `StorageError::CorruptedJson` when the file cannot be parsed.
pub fn load_session(name: &str) -> Result<Session, StorageError> {
    let dir = storage_dir()?;
    load_session_from(name, &dir)
}

/// Returns a sorted list of session names in `storage_dir()`.
///
/// Each entry is the filename without its `.json` extension.
pub fn list_sessions() -> Result<Vec<String>, StorageError> {
    let dir = storage_dir()?;
    list_sessions_in(&dir)
}

// --- path helpers -----------------------------------------------------------

fn is_valid_session_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn session_path_in(base: &Path, name: &str) -> Result<PathBuf, StorageError> {
    if !is_valid_session_name(name) {
        return Err(StorageError::InvalidSessionName(name.to_string()));
    }
    Ok(base.join(format!("{name}.json")))
}

fn tmp_path_for(final_path: &Path) -> Result<PathBuf, StorageError> {
    let mut file_name = final_path
        .file_name()
        .ok_or_else(|| StorageError::WriteFailed(std::io::Error::other("path has no file name")))?
        .to_os_string();
    file_name.push(".tmp");
    let mut tmp = final_path.to_path_buf();
    tmp.set_file_name(file_name);
    Ok(tmp)
}

fn ensure_dir_exists(path: &Path) -> Result<(), StorageError> {
    fs::create_dir_all(path).map_err(StorageError::DirectoryCreationFailed)
}

/// Returns a display string for the file path of a session, used in error messages.
///
/// Does not check whether the file exists. Safe to call for missing or corrupted sessions.
pub fn session_file_path_display(name: &str) -> String {
    match session_path(name) {
        Ok(path) => path.display().to_string(),
        Err(_) => format!("~/.cvss-dump/sessions/{name}.json"),
    }
}

// --- testable core ----------------------------------------------------------

/// Serialises `session` to JSON and writes it atomically into `base_dir`.
///
/// Intended for testing. Production code calls `save_session`.
pub fn save_session_to(session: &Session, base_dir: &Path) -> Result<(), StorageError> {
    ensure_dir_exists(base_dir)?;
    let final_path = session_path_in(base_dir, &session.name)?;
    let tmp_path = tmp_path_for(&final_path)?;

    let json = serde_json::to_string_pretty(session)
        .map_err(|e| StorageError::WriteFailed(std::io::Error::other(e)))?;

    fs::write(&tmp_path, json).map_err(StorageError::WriteFailed)?;
    fs::rename(&tmp_path, &final_path).map_err(StorageError::WriteFailed)?;

    Ok(())
}

/// Deserialises and returns the named session from `base_dir`.
///
/// Intended for testing. Production code calls `load_session`.
pub fn load_session_from(name: &str, base_dir: &Path) -> Result<Session, StorageError> {
    let path = session_path_in(base_dir, name)?;

    if !path.exists() {
        return Err(StorageError::SessionNotFound(name.to_string()));
    }

    let contents = fs::read_to_string(&path).map_err(StorageError::ReadFailed)?;
    serde_json::from_str(&contents).map_err(StorageError::CorruptedJson)
}

/// Returns a sorted list of session names found in `base_dir`.
///
/// Intended for testing. Production code calls `list_sessions`.
pub fn list_sessions_in(base_dir: &Path) -> Result<Vec<String>, StorageError> {
    ensure_dir_exists(base_dir)?;

    let mut names: Vec<String> = fs::read_dir(base_dir)
        .map_err(StorageError::ReadFailed)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let file_name = entry.file_name();
            let name = file_name.to_str()?;
            name.strip_suffix(".json")
                .filter(|stem| is_valid_session_name(stem))
                .map(|stem| stem.to_string())
        })
        .collect();

    names.sort();
    Ok(names)
}

// --- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Session;
    use chrono::Utc;

    fn temp_session(name: &str) -> Session {
        Session {
            name: name.to_string(),
            scope: vec!["10.0.0.1".to_string()],
            findings: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn unique_temp_dir() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("cvss-dump-test-{}", uuid::Uuid::new_v4()));
        path
    }

    #[test]
    fn save_then_load_round_trip() {
        let dir = unique_temp_dir();
        let session = temp_session("alpha");

        save_session_to(&session, &dir).expect("save must succeed");
        let loaded = load_session_from("alpha", &dir).expect("load must succeed");

        assert_eq!(loaded.name, session.name);
        assert_eq!(loaded.scope, session.scope);
    }

    #[test]
    fn list_sessions_returns_sorted_names() {
        let dir = unique_temp_dir();

        save_session_to(&temp_session("zebra"), &dir).unwrap();
        save_session_to(&temp_session("alpha"), &dir).unwrap();
        save_session_to(&temp_session("mango"), &dir).unwrap();

        let names = list_sessions_in(&dir).expect("list must succeed");

        assert_eq!(names, vec!["alpha", "mango", "zebra"]);
    }

    #[test]
    fn list_sessions_skips_files_with_invalid_stems() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();

        fs::write(dir.join("invalid name.json"), b"{}").unwrap();
        fs::write(dir.join("evil\x1b[31m.json"), b"{}").unwrap();
        save_session_to(&temp_session("valid"), &dir).unwrap();

        let names = list_sessions_in(&dir).expect("list must succeed");

        assert_eq!(names, vec!["valid"]);
    }

    #[test]
    fn load_non_existent_session_returns_not_found() {
        let dir = unique_temp_dir();

        let result = load_session_from("ghost", &dir);

        assert!(
            matches!(result, Err(StorageError::SessionNotFound(ref n)) if n == "ghost"),
            "expected SessionNotFound, got {result:?}"
        );
    }

    #[test]
    fn load_corrupted_json_returns_corrupted_error() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("broken.json"), b"this is not json").unwrap();

        let result = load_session_from("broken", &dir);

        assert!(
            matches!(result, Err(StorageError::CorruptedJson(_))),
            "expected CorruptedJson, got {result:?}"
        );
    }

    #[test]
    fn save_uses_atomic_rename_no_tmp_file_left() {
        let dir = unique_temp_dir();
        let session = temp_session("clean");

        save_session_to(&session, &dir).expect("save must succeed");

        let tmp_path = dir.join("clean.json.tmp");
        assert!(
            !tmp_path.exists(),
            "tmp file must not remain after successful save"
        );
    }

    // --- StorageError::Display ---

    #[test]
    fn display_directory_creation_failed() {
        let io_err = std::io::Error::other("test");
        let msg = StorageError::DirectoryCreationFailed(io_err).to_string();
        assert!(
            msg.starts_with("failed to create sessions directory:"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn display_session_not_found() {
        let msg = StorageError::SessionNotFound("foo".to_string()).to_string();
        assert_eq!(msg, "session not found: foo");
    }

    #[test]
    fn display_corrupted_json() {
        let serde_err = serde_json::from_str::<crate::domain::Session>("invalid").unwrap_err();
        let msg = StorageError::CorruptedJson(serde_err).to_string();
        assert!(
            msg.starts_with("corrupted session JSON:"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn display_write_failed() {
        let io_err = std::io::Error::other("test");
        let msg = StorageError::WriteFailed(io_err).to_string();
        assert!(
            msg.starts_with("failed to write session file:"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn display_read_failed() {
        let io_err = std::io::Error::other("test");
        let msg = StorageError::ReadFailed(io_err).to_string();
        assert!(
            msg.starts_with("failed to read session file:"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn display_home_dir_not_found() {
        let msg = StorageError::HomeDirNotFound.to_string();
        assert_eq!(msg, "HOME environment variable is not set");
    }

    #[test]
    fn display_invalid_session_name() {
        let msg = StorageError::InvalidSessionName("../evil".to_string()).to_string();
        assert!(
            msg.contains("invalid session name"),
            "unexpected message: {msg}"
        );
        assert!(
            msg.contains("../evil"),
            "message must include the bad name: {msg}"
        );
    }

    // --- session_path_in slug validation ---

    #[test]
    fn session_path_in_rejects_path_traversal() {
        let dir = unique_temp_dir();
        let result = session_path_in(&dir, "../traversal");
        assert!(
            matches!(result, Err(StorageError::InvalidSessionName(ref n)) if n == "../traversal"),
            "expected InvalidSessionName, got {result:?}"
        );
    }

    #[test]
    fn session_path_in_accepts_valid_slug() {
        let dir = unique_temp_dir();
        let result = session_path_in(&dir, "valid-name");
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        assert!(
            result.unwrap().ends_with("valid-name.json"),
            "expected path ending with valid-name.json"
        );
    }

    // --- storage_dir() ---

    #[test]
    fn storage_dir_returns_ok_and_ends_with_expected_suffix() {
        let dir = storage_dir().expect("storage_dir must succeed when HOME is set");
        assert!(
            dir.ends_with(".cvss-dump/sessions"),
            "expected path ending with .cvss-dump/sessions, got: {dir:?}"
        );
    }

    // --- session_path() ---

    #[test]
    fn session_path_ends_with_json_filename() {
        let path = session_path("my-session").expect("session_path must succeed");
        assert!(
            path.ends_with("my-session.json"),
            "expected path ending with my-session.json, got: {path:?}"
        );
    }

    // --- save_session / load_session / list_sessions ---

    #[test]
    fn save_load_list_sessions_via_default_storage_dir() {
        let name = format!("test-{}", uuid::Uuid::new_v4().simple());
        let session = temp_session(&name);

        save_session(&session).expect("save_session must succeed");

        let loaded = load_session(&name).expect("load_session must succeed");
        assert_eq!(loaded.name, name);
        assert_eq!(loaded.scope, session.scope);

        let names = list_sessions().expect("list_sessions must succeed");
        assert!(
            names.contains(&name),
            "list_sessions must include the saved session name"
        );

        let dir = storage_dir().expect("storage_dir must succeed");
        fs::remove_file(dir.join(format!("{name}.json")))
            .expect("cleanup of test session file must succeed");
    }
}
