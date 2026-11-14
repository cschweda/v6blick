//! The check engine: pure functions from observations to findings.
//!
//! Nothing in this module does I/O. A check reads an [`Observation`] and
//! returns findings, so every check can be tested offline against
//! hand-built or recorded observations.
//!
//! One rule runs through the comparisons. A host may have several
//! addresses in each family, and the servers behind them need not be
//! identical: certificates are renewed one server at a time, for one. So
//! a difference is reported only when *no* IPv6 address agrees with *any*
//! IPv4 address.

pub mod adr;
pub mod eqv;
pub mod rch;

#[cfg(test)]
pub(crate) mod testkit;

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::observe::{Observation, SpecialUse};

/// Severity levels from `DESIGN.md`, most severe first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    Warning,
    Notice,
    Info,
}

impl Severity {
    pub const ALL: [Severity; 4] = [
        Severity::Critical,
        Severity::Warning,
        Severity::Notice,
        Severity::Info,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::Warning => "warning",
            Severity::Notice => "notice",
            Severity::Info => "info",
        }
    }
}

/// Where the line is drawn for the checks that measure. Open question 4
/// of the design; the values are in `DECISIONS.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thresholds {
    /// RCH-03: IPv6 takes this many milliseconds longer to connect than
    /// IPv4. 250 ms is the delay after which a browser that races the
    /// two families (RFC 8305) starts its IPv4 attempt.
    pub slower_ms: u64,
    /// RCH-04: a failing IPv6 attempt takes longer than this to fail.
    pub wait_ms: u64,
    /// EQV-03: body sizes differ by more than this share of the larger.
    pub size_percent: u64,
    /// EQV-03: and by more than this many bytes.
    pub size_bytes: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            slower_ms: 250,
            wait_ms: 1000,
            size_percent: 20,
            size_bytes: 256,
        }
    }
}

/// One connection attempt, as named in evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub port: u16,
    pub result: String,
}

/// A certificate and the address that presented it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServedCertificate {
    pub address: IpAddr,
    pub sha256: String,
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after_unix: Option<u64>,
    pub covers_host: bool,
}

/// How one address answered a URL: the first response, and where the
/// redirects ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    pub address: IpAddr,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// `page` when the redirects ended at a response, `failed` when one
    /// could not be followed, `redirecting` when they did not end.
    pub ended: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_status: Option<u16>,
    /// Why the last redirect could not be followed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
}

/// The body one address served at the end of its redirects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServedBody {
    pub address: IpAddr,
    pub url: String,
    pub bytes: u64,
    pub truncated: bool,
    pub body_sha256: String,
    pub shape_sha256: String,
}

/// The structured evidence behind a finding. The `kind` tag names the shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    NoAaaa {
        ipv4: Vec<IpAddr>,
    },
    UnusableAaaa {
        address: IpAddr,
        reason: SpecialUse,
    },
    Ipv6WalkFailed {
        /// The name that was being resolved.
        walked: String,
        /// The zone whose nameservers could not be asked over IPv6.
        zone: String,
        detail: String,
        /// The zones entered on the way, from the root down.
        path: Vec<String>,
    },
    NoConnection {
        address: IpAddr,
        attempts: Vec<Attempt>,
    },
    TlsFailure {
        address: IpAddr,
        port: u16,
        error: String,
        /// An IPv4 address of the host where the handshake succeeded.
        ipv4_address: IpAddr,
    },
    SlowerConnect {
        port: u16,
        ipv4_address: IpAddr,
        ipv4_ms: u64,
        ipv6_address: IpAddr,
        ipv6_ms: u64,
    },
    FallbackWait {
        address: IpAddr,
        port: u16,
        waited_ms: u64,
        result: String,
    },
    CertificateMismatch {
        port: u16,
        ipv4: Vec<ServedCertificate>,
        ipv6: Vec<ServedCertificate>,
    },
    ResponseMismatch {
        url: String,
        ipv4: Vec<Answer>,
        ipv6: Vec<Answer>,
    },
    BodyMismatch {
        url: String,
        ipv4: Vec<ServedBody>,
        ipv6: Vec<ServedBody>,
    },
}

/// One result of one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable check ID, for example `RCH-01`.
    pub check_id: String,
    pub severity: Severity,
    /// The host the finding is about.
    pub name: String,
    /// One line for people.
    pub summary: String,
    pub evidence: Evidence,
}

impl Finding {
    pub(crate) fn new(
        check_id: &str,
        severity: Severity,
        obs: &Observation,
        summary: String,
        evidence: Evidence,
    ) -> Finding {
        Finding {
            check_id: check_id.to_string(),
            severity,
            name: obs.host.clone(),
            summary,
            evidence,
        }
    }
}

/// Run every Phase 0 check. Findings come most severe first, then by
/// check ID.
pub fn run_all(obs: &Observation, thresholds: &Thresholds) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(adr::check(obs));
    findings.extend(rch::check(obs, thresholds));
    findings.extend(eqv::check(obs, thresholds));
    findings.sort_by(|a, b| (a.severity, &a.check_id).cmp(&(b.severity, &b.check_id)));
    findings
}
