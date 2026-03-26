use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Severity level derived exclusively from the CVSS score.
/// Never set manually — always computed via `Severity::from_score`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    /// Score 9.0–10.0
    Critical,
    /// Score 7.0–8.9
    High,
    /// Score 4.0–6.9
    Medium,
    /// Score 0.1–3.9
    Low,
    /// Score exactly 0.0
    Informational,
}

impl Severity {
    /// Derives a `Severity` level from a numeric CVSS score.
    ///
    /// Scale:
    /// - 9.0–10.0 → Critical
    /// - 7.0–8.9  → High
    /// - 4.0–6.9  → Medium
    /// - 0.1–3.9  → Low
    /// - 0.0      → Informational
    pub fn from_score(score: f64) -> Severity {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s > 0.0 => Severity::Low,
            _ => Severity::Informational,
        }
    }
}

/// A single security finding within a pentest session.
///
/// `cvss_score` and `severity` are auto-derived from `cvss_vector`
/// and must be computed by the caller — never set independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding.
    pub id: Uuid,
    /// Short descriptive title of the vulnerability.
    pub title: String,
    /// Raw CVSS vector string (e.g. `CVSS:3.1/AV:N/AC:L/...`).
    pub cvss_vector: String,
    /// Numeric CVSS base score derived from `cvss_vector`.
    pub cvss_score: f64,
    /// Severity band derived from `cvss_score` — see `Severity::from_score`.
    pub severity: Severity,
    /// Affected asset or component (host, endpoint, service).
    pub affected: String,
    /// Detailed description of the vulnerability.
    pub description: String,
    /// Supporting evidence (screenshots, payloads, logs).
    pub evidence: String,
    /// Recommended remediation steps.
    pub remediation: String,
    /// Optional external references (CVEs, advisories, write-ups).
    #[serde(default)]
    pub references: Vec<String>,
}

/// A pentest engagement session grouping scope and findings.
///
/// `name` must be slug-safe (alphanumeric + hyphens) — validation is
/// the caller's responsibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Slug-safe identifier for this session (alphanumeric + hyphens).
    pub name: String,
    /// In-scope targets for this engagement.
    pub scope: Vec<String>,
    /// All findings recorded during this session.
    pub findings: Vec<Finding>,
    /// Timestamp when the session was first created.
    pub created_at: DateTime<Utc>,
    /// Timestamp of the most recent modification.
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_zero_is_informational() {
        assert_eq!(Severity::from_score(0.0), Severity::Informational);
    }

    #[test]
    fn score_point_one_is_low() {
        assert_eq!(Severity::from_score(0.1), Severity::Low);
    }

    #[test]
    fn score_three_point_nine_is_low() {
        assert_eq!(Severity::from_score(3.9), Severity::Low);
    }

    #[test]
    fn score_four_point_zero_is_medium() {
        assert_eq!(Severity::from_score(4.0), Severity::Medium);
    }

    #[test]
    fn score_six_point_nine_is_medium() {
        assert_eq!(Severity::from_score(6.9), Severity::Medium);
    }

    #[test]
    fn score_seven_point_zero_is_high() {
        assert_eq!(Severity::from_score(7.0), Severity::High);
    }

    #[test]
    fn score_eight_point_nine_is_high() {
        assert_eq!(Severity::from_score(8.9), Severity::High);
    }

    #[test]
    fn score_nine_point_zero_is_critical() {
        assert_eq!(Severity::from_score(9.0), Severity::Critical);
    }

    #[test]
    fn score_ten_is_critical() {
        assert_eq!(Severity::from_score(10.0), Severity::Critical);
    }
}
