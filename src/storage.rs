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
    Ok(session_path_in(&dir, name))
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

fn session_path_in(base: &Path, name: &str) -> PathBuf {
    base.join(format!("{name}.json"))
}

fn tmp_path_for(final_path: &Path) -> PathBuf {
    let mut tmp = final_path.to_path_buf();
    let mut name = final_path
        .file_name()
        .expect("session path always has a file name")
        .to_os_string();
    name.push(".tmp");
    tmp.set_file_name(name);
    tmp
}

fn ensure_dir_exists(path: &Path) -> Result<(), StorageError> {
    fs::create_dir_all(path).map_err(StorageError::DirectoryCreationFailed)
}

// --- testable core ----------------------------------------------------------

/// Serialises `session` to JSON and writes it atomically into `base_dir`.
///
/// Intended for testing. Production code calls `save_session`.
pub fn save_session_to(session: &Session, base_dir: &Path) -> Result<(), StorageError> {
    ensure_dir_exists(base_dir)?;
    let final_path = session_path_in(base_dir, &session.name);
    let tmp_path = tmp_path_for(&final_path);

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
    let path = session_path_in(base_dir, name);

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
            name.strip_suffix(".json").map(|stem| stem.to_string())
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
        path.push(format!(
            "cvss-dump-test-{}",
            uuid::Uuid::new_v4().to_string()
        ));
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
}
