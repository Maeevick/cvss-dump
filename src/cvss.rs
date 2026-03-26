/// Pure-Rust CVSS v3.1 base score calculator.
///
/// Implements the CVSS v3.1 specification for base metrics only.
/// Temporal and environmental metrics are out of scope.
///
/// Reference: https://www.first.org/cvss/v3.1/specification-document
use std::collections::HashMap;

/// Error type for CVSS vector parsing failures.
#[derive(Debug, PartialEq)]
pub enum CvssError {
    /// The vector string does not start with the required `CVSS:3.1/` prefix.
    MissingPrefix,
    /// A required base metric is absent from the vector string.
    MissingMetric(String),
    /// A metric value is not valid for the given metric key.
    InvalidMetricValue { metric: String, value: String },
}

impl std::fmt::Display for CvssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CvssError::MissingPrefix => write!(f, "vector must start with 'CVSS:3.1/'"),
            CvssError::MissingMetric(m) => write!(f, "missing required metric: {m}"),
            CvssError::InvalidMetricValue { metric, value } => {
                write!(f, "invalid value '{value}' for metric '{metric}'")
            }
        }
    }
}

/// Parsed and validated CVSS v3.1 base metric values as numeric weights.
#[derive(Debug)]
struct BaseMetrics {
    attack_vector: f64,
    attack_complexity: f64,
    privileges_required: f64,
    user_interaction: f64,
    scope_changed: bool,
    confidentiality: f64,
    integrity: f64,
    availability: f64,
}

fn parse_attack_vector(value: &str) -> Result<f64, CvssError> {
    match value {
        "N" => Ok(0.85),
        "A" => Ok(0.62),
        "L" => Ok(0.55),
        "P" => Ok(0.2),
        _ => Err(CvssError::InvalidMetricValue {
            metric: "AV".to_string(),
            value: value.to_string(),
        }),
    }
}

fn parse_attack_complexity(value: &str) -> Result<f64, CvssError> {
    match value {
        "L" => Ok(0.77),
        "H" => Ok(0.44),
        _ => Err(CvssError::InvalidMetricValue {
            metric: "AC".to_string(),
            value: value.to_string(),
        }),
    }
}

fn parse_privileges_required(value: &str, scope_changed: bool) -> Result<f64, CvssError> {
    match (value, scope_changed) {
        ("N", _) => Ok(0.85),
        ("L", false) => Ok(0.62),
        ("L", true) => Ok(0.68),
        ("H", false) => Ok(0.27),
        ("H", true) => Ok(0.50),
        _ => Err(CvssError::InvalidMetricValue {
            metric: "PR".to_string(),
            value: value.to_string(),
        }),
    }
}

fn parse_user_interaction(value: &str) -> Result<f64, CvssError> {
    match value {
        "N" => Ok(0.85),
        "R" => Ok(0.62),
        _ => Err(CvssError::InvalidMetricValue {
            metric: "UI".to_string(),
            value: value.to_string(),
        }),
    }
}

fn parse_scope(value: &str) -> Result<bool, CvssError> {
    match value {
        "U" => Ok(false),
        "C" => Ok(true),
        _ => Err(CvssError::InvalidMetricValue {
            metric: "S".to_string(),
            value: value.to_string(),
        }),
    }
}

fn parse_impact(metric: &str, value: &str) -> Result<f64, CvssError> {
    match value {
        "N" => Ok(0.0),
        "L" => Ok(0.22),
        "H" => Ok(0.56),
        _ => Err(CvssError::InvalidMetricValue {
            metric: metric.to_string(),
            value: value.to_string(),
        }),
    }
}

fn require_metric<'a>(metrics: &'a HashMap<&str, &str>, key: &str) -> Result<&'a str, CvssError> {
    metrics
        .get(key)
        .copied()
        .ok_or_else(|| CvssError::MissingMetric(key.to_string()))
}

fn parse_base_metrics(vector: &str) -> Result<BaseMetrics, CvssError> {
    let without_prefix = vector
        .strip_prefix("CVSS:3.1/")
        .ok_or(CvssError::MissingPrefix)?;

    let metrics: HashMap<&str, &str> = without_prefix
        .split('/')
        .filter_map(|part| part.split_once(':'))
        .collect();

    let av_raw = require_metric(&metrics, "AV")?;
    let ac_raw = require_metric(&metrics, "AC")?;
    let s_raw = require_metric(&metrics, "S")?;
    let pr_raw = require_metric(&metrics, "PR")?;
    let ui_raw = require_metric(&metrics, "UI")?;
    let c_raw = require_metric(&metrics, "C")?;
    let i_raw = require_metric(&metrics, "I")?;
    let a_raw = require_metric(&metrics, "A")?;

    let scope_changed = parse_scope(s_raw)?;

    Ok(BaseMetrics {
        attack_vector: parse_attack_vector(av_raw)?,
        attack_complexity: parse_attack_complexity(ac_raw)?,
        privileges_required: parse_privileges_required(pr_raw, scope_changed)?,
        user_interaction: parse_user_interaction(ui_raw)?,
        scope_changed,
        confidentiality: parse_impact("C", c_raw)?,
        integrity: parse_impact("I", i_raw)?,
        availability: parse_impact("A", a_raw)?,
    })
}

/// Rounds a score up to the nearest 0.1 (ceiling on first decimal place).
///
/// This matches the CVSS v3.1 specification Roundup function:
/// the result is the smallest value with one decimal place
/// greater than or equal to the input.
fn roundup(score: f64) -> f64 {
    let int_input = (score * 100_000.0).round() as i64;
    if int_input % 10000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input / 10000) + 1) as f64 / 10.0
    }
}

/// Computes the CVSS v3.1 base score from a vector string.
///
/// Parses the 8 required base metrics (AV, AC, PR, UI, S, C, I, A) and
/// applies the CVSS v3.1 formula to produce a score in the range [0.0, 10.0],
/// rounded up to one decimal place.
///
/// Returns `Err` for any malformed, missing, or invalid metric — never panics.
///
/// # Examples
///
/// Calling `base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")` returns `Ok(9.8)`.
pub fn base_score(vector: &str) -> Result<f64, CvssError> {
    let m = parse_base_metrics(vector)?;

    let isc_base = 1.0 - ((1.0 - m.confidentiality) * (1.0 - m.integrity) * (1.0 - m.availability));

    let isc = if m.scope_changed {
        7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02_f64).powi(15)
    } else {
        6.42 * isc_base
    };

    if isc <= 0.0 {
        return Ok(0.0);
    }

    let exploitability =
        8.22 * m.attack_vector * m.attack_complexity * m.privileges_required * m.user_interaction;

    let base = if m.scope_changed {
        f64::min(1.08 * (isc + exploitability), 10.0)
    } else {
        f64::min(isc + exploitability, 10.0)
    };

    Ok(roundup(base))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_score(vector: &str, expected: f64) {
        let result = base_score(vector).expect("expected valid vector");
        assert_eq!(
            result, expected,
            "vector: {vector} — got {result}, expected {expected}"
        );
    }

    #[test]
    fn fixture_critical_9_8() {
        assert_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8);
    }

    #[test]
    fn fixture_medium_5_4_scope_changed() {
        assert_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4);
    }

    #[test]
    fn fixture_medium_6_5() {
        assert_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5);
    }

    #[test]
    fn fixture_low_3_1() {
        assert_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1);
    }

    #[test]
    fn fixture_high_7_8() {
        assert_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8);
    }

    #[test]
    fn fixture_medium_6_1_scope_changed() {
        assert_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1);
    }

    #[test]
    fn fixture_medium_6_8_scope_changed_high_c() {
        assert_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N", 6.8);
    }

    #[test]
    fn fixture_medium_5_4_no_scope() {
        assert_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4);
    }

    #[test]
    fn error_on_missing_cvss_prefix() {
        let result = base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert_eq!(result, Err(CvssError::MissingPrefix));
    }

    #[test]
    fn error_on_wrong_version_prefix() {
        let result = base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert_eq!(result, Err(CvssError::MissingPrefix));
    }

    #[test]
    fn error_on_missing_metric_av() {
        let result = base_score("CVSS:3.1/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert_eq!(result, Err(CvssError::MissingMetric("AV".to_string())));
    }

    #[test]
    fn error_on_missing_metric_c() {
        let result = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/I:H/A:H");
        assert_eq!(result, Err(CvssError::MissingMetric("C".to_string())));
    }

    #[test]
    fn error_on_invalid_av_value() {
        let result = base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert_eq!(
            result,
            Err(CvssError::InvalidMetricValue {
                metric: "AV".to_string(),
                value: "X".to_string()
            })
        );
    }

    #[test]
    fn error_on_invalid_scope_value() {
        let result = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H");
        assert_eq!(
            result,
            Err(CvssError::InvalidMetricValue {
                metric: "S".to_string(),
                value: "X".to_string()
            })
        );
    }

    #[test]
    fn error_on_empty_vector() {
        let result = base_score("");
        assert_eq!(result, Err(CvssError::MissingPrefix));
    }

    #[test]
    fn zero_score_when_all_impact_none() {
        let result = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
        assert_eq!(result, Ok(0.0));
    }
}
