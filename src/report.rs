use chrono::Utc;

use crate::domain::{Finding, Session, Severity};

/// Formats a `Severity` value as the label used in report output.
fn severity_label(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Informational => "INFO",
    }
}

/// Returns a sort key for a finding so that findings are ordered by CVSS score
/// descending, with Informational always last, and alphabetical title as the
/// tiebreaker within the same score.
fn finding_sort_key(finding: &Finding) -> (u8, ordered_float::NotNan<f64>, String) {
    let informational_last: u8 = if matches!(finding.severity, Severity::Informational) {
        1
    } else {
        0
    };
    // Negate the score so that higher scores sort first (ascending order on negated value).
    let descending_score =
        ordered_float::NotNan::new(-finding.cvss_score).unwrap_or(ordered_float::NotNan::new(0.0).unwrap());
    (informational_last, descending_score, finding.title.clone())
}

/// Sorts a slice of findings according to the report ordering rules:
/// - CVSS score descending (higher score first)
/// - Informational findings always last regardless of score
/// - Alphabetical title ascending as the tiebreaker within the same score
fn sorted_findings(findings: &[Finding]) -> Vec<&Finding> {
    let mut refs: Vec<&Finding> = findings.iter().collect();
    refs.sort_by_key(|f| finding_sort_key(f));
    refs
}

/// Generates the full markdown report string for a session.
///
/// The caller is responsible for ensuring the session has at least one finding
/// before calling this function.
pub fn generate_report(session: &Session) -> String {
    let now = Utc::now();
    let generated = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let mut out = String::new();

    // Header
    out.push_str(&format!("# Pentest Report: {}\n\n", session.name));
    out.push_str(&format!("**Generated:** {}\n\n", generated));

    // Scope
    out.push_str("## Scope\n\n");
    for entry in &session.scope {
        out.push_str(&format!("- {}\n", entry));
    }
    out.push('\n');

    // Findings summary table
    out.push_str("## Findings Summary\n\n");
    out.push_str("| # | Title | Severity | CVSS Score | Affected |\n");
    out.push_str("|---|-------|----------|------------|----------|\n");

    let ordered = sorted_findings(&session.findings);

    for (idx, finding) in ordered.iter().enumerate() {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            idx + 1,
            finding.title,
            severity_label(&finding.severity),
            finding.cvss_score,
            finding.affected,
        ));
    }
    out.push('\n');

    // Detailed findings
    out.push_str("## Findings\n\n");

    for (idx, finding) in ordered.iter().enumerate() {
        let refs_text = if finding.references.is_empty() {
            "None".to_string()
        } else {
            finding.references.join(", ")
        };

        out.push_str(&format!("### {}. {}\n\n", idx + 1, finding.title));
        out.push_str(&format!(
            "**Severity:** {}\n",
            severity_label(&finding.severity)
        ));
        out.push_str(&format!("**CVSS Vector:** `{}`\n", finding.cvss_vector));
        out.push_str(&format!("**CVSS Score:** {}\n", finding.cvss_score));
        out.push_str(&format!("**Affected:** {}\n\n", finding.affected));
        out.push_str("**Description:**\n");
        out.push_str(&format!("{}\n\n", finding.description));
        out.push_str("**Evidence:**\n");
        out.push_str(&format!("{}\n\n", finding.evidence));
        out.push_str("**Remediation:**\n");
        out.push_str(&format!("{}\n\n", finding.remediation));
        out.push_str("**References:**\n");
        out.push_str(&format!("{}\n\n", refs_text));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Finding, Session, Severity};
    use chrono::Utc;
    use uuid::Uuid;

    fn make_finding(title: &str, score: f64, affected: &str, references: Vec<String>) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            title: title.to_string(),
            cvss_vector: format!("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            cvss_score: score,
            severity: Severity::from_score(score),
            affected: affected.to_string(),
            description: format!("Description of {title}"),
            evidence: format!("Evidence for {title}"),
            remediation: format!("Fix {title}"),
            references,
        }
    }

    fn make_session(name: &str, scope: Vec<&str>, findings: Vec<Finding>) -> Session {
        Session {
            name: name.to_string(),
            scope: scope.into_iter().map(|s| s.to_string()).collect(),
            findings,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn critical_before_high_before_medium_informational_last() {
        let findings = vec![
            make_finding("Medium Finding", 5.0, "host-a", vec![]),
            make_finding("Info Finding", 0.0, "host-b", vec![]),
            make_finding("Critical Finding", 9.8, "host-c", vec![]),
            make_finding("High Finding", 7.5, "host-d", vec![]),
        ];
        let session = make_session("test-session", vec!["10.0.0.1"], findings);

        let report = generate_report(&session);

        let critical_pos = report.find("Critical Finding").unwrap();
        let high_pos = report.find("High Finding").unwrap();
        let medium_pos = report.find("Medium Finding").unwrap();
        let info_pos = report.find("Info Finding").unwrap();

        assert!(critical_pos < high_pos, "Critical must appear before High");
        assert!(high_pos < medium_pos, "High must appear before Medium");
        assert!(medium_pos < info_pos, "Medium must appear before Informational");
    }

    #[test]
    fn tied_scores_ordered_alphabetically_by_title() {
        let findings = vec![
            make_finding("Zebra Bug", 7.0, "host-a", vec![]),
            make_finding("Alpha Bug", 7.0, "host-b", vec![]),
            make_finding("Mango Bug", 7.0, "host-c", vec![]),
        ];
        let session = make_session("tie-session", vec!["10.0.0.1"], findings);

        let report = generate_report(&session);

        let alpha_pos = report.find("Alpha Bug").unwrap();
        let mango_pos = report.find("Mango Bug").unwrap();
        let zebra_pos = report.find("Zebra Bug").unwrap();

        assert!(alpha_pos < mango_pos, "Alpha must appear before Mango");
        assert!(mango_pos < zebra_pos, "Mango must appear before Zebra");
    }

    #[test]
    fn scope_section_lists_all_scope_entries() {
        let session = make_session(
            "scope-session",
            vec!["192.168.1.0/24", "api.example.com", "10.0.0.1"],
            vec![make_finding("Some Finding", 5.0, "host", vec![])],
        );

        let report = generate_report(&session);

        assert!(report.contains("- 192.168.1.0/24\n"));
        assert!(report.contains("- api.example.com\n"));
        assert!(report.contains("- 10.0.0.1\n"));
    }

    #[test]
    fn references_shows_none_when_empty() {
        let session = make_session(
            "ref-session",
            vec!["10.0.0.1"],
            vec![make_finding("No Refs Finding", 6.0, "host", vec![])],
        );

        let report = generate_report(&session);

        assert!(
            report.contains("**References:**\nNone\n"),
            "Expected 'None' for empty references, report was:\n{report}"
        );
    }

    #[test]
    fn references_joined_by_comma_when_present() {
        let refs = vec!["CVE-2021-44228".to_string(), "https://example.com".to_string()];
        let session = make_session(
            "ref-session",
            vec!["10.0.0.1"],
            vec![make_finding("Log4Shell", 10.0, "server", refs)],
        );

        let report = generate_report(&session);

        assert!(
            report.contains("CVE-2021-44228, https://example.com"),
            "Expected joined references, report was:\n{report}"
        );
    }

    #[test]
    fn informational_findings_with_same_score_zero_ordered_alphabetically() {
        let findings = vec![
            make_finding("Zebra Info", 0.0, "host-a", vec![]),
            make_finding("Alpha Info", 0.0, "host-b", vec![]),
        ];
        let session = make_session("info-session", vec!["10.0.0.1"], findings);

        let report = generate_report(&session);

        let alpha_pos = report.find("Alpha Info").unwrap();
        let zebra_pos = report.find("Zebra Info").unwrap();

        assert!(alpha_pos < zebra_pos, "Alpha Info must appear before Zebra Info");
    }

    #[test]
    fn report_header_contains_session_name() {
        let session = make_session(
            "my-engagement",
            vec!["10.0.0.1"],
            vec![make_finding("Some Finding", 5.0, "host", vec![])],
        );

        let report = generate_report(&session);

        assert!(report.starts_with("# Pentest Report: my-engagement\n"));
    }

    #[test]
    fn summary_table_has_correct_headers() {
        let session = make_session(
            "header-check",
            vec!["10.0.0.1"],
            vec![make_finding("Some Finding", 5.0, "host", vec![])],
        );

        let report = generate_report(&session);

        assert!(report.contains("| # | Title | Severity | CVSS Score | Affected |"));
    }
}

// Bring in `ordered_float` via a local re-export so the sort key compiles
// without adding a new crate dependency — we use only `NotNan` on f64 values
// that are guaranteed to come from valid CVSS scores.
mod ordered_float {
    /// A thin wrapper around `f64` that implements `Ord` + `Eq` by treating NaN
    /// as equal to NaN and less than all other values (NaN should never appear in
    /// valid CVSS scores, so this degenerate ordering is acceptable).
    #[derive(Clone, Copy, PartialEq)]
    pub struct NotNan(f64);

    impl NotNan {
        pub fn new(v: f64) -> Result<Self, ()> {
            if v.is_nan() { Err(()) } else { Ok(Self(v)) }
        }
    }

    impl Eq for NotNan {}

    impl PartialOrd for NotNan {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for NotNan {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.0.partial_cmp(&other.0).unwrap_or(std::cmp::Ordering::Equal)
        }
    }
}
