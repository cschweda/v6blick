//! Rendering: the report document, as JSON or as terminal text.

pub mod human;
pub mod json;

use serde::Serialize;

use crate::checks::{Finding, Severity};
use crate::observe::Observation;

/// Version of the JSON document. It changes only when a field is removed,
/// renamed or changes meaning; new fields may be added without a bump.
pub const SCHEMA_VERSION: u32 = 1;

/// Exit codes, the same as zoneblick's.
pub mod exit {
    /// No findings above `info`.
    pub const CLEAN: u8 = 0;
    /// Notices or warnings, nothing critical.
    pub const FINDINGS: u8 = 1;
    /// At least one critical finding.
    pub const CRITICAL: u8 = 2;
    /// The run itself failed.
    pub const RUN_FAILED: u8 = 3;
}

/// How many findings there are at each severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Summary {
    pub critical: usize,
    pub warning: usize,
    pub notice: usize,
    pub info: usize,
}

impl Summary {
    pub fn of(findings: &[Finding]) -> Self {
        let count = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
        Self {
            critical: count(Severity::Critical),
            warning: count(Severity::Warning),
            notice: count(Severity::Notice),
            info: count(Severity::Info),
        }
    }

    /// `info` findings alone do not change the exit code.
    pub fn exit_code(&self) -> u8 {
        if self.critical > 0 {
            exit::CRITICAL
        } else if self.warning + self.notice > 0 {
            exit::FINDINGS
        } else {
            exit::CLEAN
        }
    }
}

/// The result of a completed `check` run. This is the `--json` document:
/// what was recorded, then what the checks made of it.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: u32,
    /// The version of v6blick that made the report.
    pub version: String,
    #[serde(flatten)]
    pub observation: Observation,
    pub findings: Vec<Finding>,
    pub summary: Summary,
    pub exit_code: u8,
}

impl Report {
    pub fn new(observation: Observation, findings: Vec<Finding>) -> Self {
        let summary = Summary::of(&findings);
        Self {
            schema_version: SCHEMA_VERSION,
            version: env!("CARGO_PKG_VERSION").to_string(),
            observation,
            findings,
            summary,
            exit_code: summary.exit_code(),
        }
    }
}

/// The `--json` document for a run that failed before it could report.
#[derive(Debug, Clone, Serialize)]
pub struct FailureReport {
    pub schema_version: u32,
    /// What was given on the command line.
    pub target: String,
    pub error: FailureDetail,
    pub exit_code: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct FailureDetail {
    /// A stable identifier, for example `no_ipv6`.
    pub kind: String,
    pub message: String,
}

impl FailureReport {
    pub fn new(target: &str, kind: &str, message: String) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            target: target.to_string(),
            error: FailureDetail {
                kind: kind.to_string(),
                message,
            },
            exit_code: exit::RUN_FAILED,
        }
    }
}

/// A time as `2026-11-14 16:05 UTC`.
pub fn utc(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let rest = unix % 86_400;
    // Days since 1970-01-01 to a date in the Gregorian calendar.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Evidence;

    fn finding(severity: Severity) -> Finding {
        Finding {
            check_id: "ADR-01".to_string(),
            severity,
            name: "example.org.".to_string(),
            summary: String::new(),
            meaning: String::new(),
            fix: String::new(),
            evidence: Evidence::NoAaaa { ipv4: vec![] },
        }
    }

    #[test]
    fn exit_code_follows_the_worst_finding() {
        let code = |s: &[Severity]| {
            Summary::of(&s.iter().map(|s| finding(*s)).collect::<Vec<_>>()).exit_code()
        };
        assert_eq!(code(&[]), exit::CLEAN);
        assert_eq!(code(&[Severity::Info]), exit::CLEAN);
        assert_eq!(code(&[Severity::Notice]), exit::FINDINGS);
        assert_eq!(code(&[Severity::Warning, Severity::Info]), exit::FINDINGS);
        assert_eq!(
            code(&[Severity::Notice, Severity::Critical]),
            exit::CRITICAL
        );
    }

    #[test]
    fn times_are_printed_in_utc() {
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(1_700_000_000), "2023-11-14 22:13 UTC");
        assert_eq!(utc(4_948_000_000), "2126-10-18 12:26 UTC");
    }
}
