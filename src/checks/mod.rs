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

    /// What a finding of this severity says about the site, in a line.
    pub fn meaning(self) -> &'static str {
        match self {
            Severity::Critical => "broken now for visitors who use IPv6; fix it first",
            Severity::Warning => {
                "wrong or missing for IPv6; visitors without IPv4 are affected, and it can be fixed"
            }
            Severity::Notice => "worth a look; it may be harmless, or chance in one measurement",
            Severity::Info => "for your information; nothing to fix",
        }
    }
}

/// What a check's finding means for visitors, and what to do about it.
/// The text belongs to the check, not to one finding: it is the same
/// for every host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Advice {
    pub meaning: &'static str,
    pub fix: &'static str,
}

/// The advice for a check ID. Every Phase 0 finding can be fixed by
/// whoever runs the site's DNS or its servers; none depends on a third
/// party.
pub fn advice(check_id: &str) -> Advice {
    let (meaning, fix) = match check_id {
        "ADR-01" => (
            "Visitors on an IPv6-only network cannot reach this host directly. Those whose network has a NAT64 translator, as many mobile networks do, still can; those without one cannot.",
            "Publish an AAAA record for the host. Most hosting providers and CDNs offer IPv6 as a setting; if yours has none for this name, put the name behind a service that does.",
        ),
        "ADR-02" => (
            "Clients that prefer IPv6 try this address first and fail. They reach the site only after falling back to IPv4, or not at all.",
            "Replace the record with the server's public IPv6 address, or remove it.",
        ),
        "ADR-03" => (
            "A resolver that has only IPv6 cannot look this name up at all, whatever addresses the host has.",
            "Give the nameservers of the zone named here IPv6 addresses (AAAA records, and glue at the parent zone), or move the zone to a DNS host whose nameservers have them.",
        ),
        "RCH-01" => (
            "Every client that can use IPv6 tries this address first. Visitors without IPv4 cannot reach the site; everyone else waits for the fallback to IPv4.",
            "Make the server listen on this address and let ports 80 and 443 through the firewall over IPv6. Until it does, remove the AAAA record: no record is better than one that does not answer.",
        ),
        "RCH-02" => (
            "Visitors on IPv6 cannot open a secure connection. A browser shows an error, or falls back to IPv4 if it can.",
            "Check the TLS setup of the IPv6 listener or load balancer: its certificate, its protocol versions, and that port 443 over IPv6 reaches the same service as over IPv4.",
        ),
        "RCH-03" => (
            "The site works over IPv6 and opens more slowly there. Browsers that race the two families will mostly end up on IPv4.",
            "Look at the route to the IPv6 address: a tunnel, a distant data centre, or a CDN with no IPv6 presence nearby. One measurement can be chance, so run the check again first.",
        ),
        "RCH-04" => (
            "A client without fast fallback waits this long before the page starts to load.",
            "Fix or remove the AAAA record that does not answer. A firewall that silently drops IPv6 packets causes the wait; one that rejects them ends it at once.",
        ),
        "EQV-01" => (
            "Visitors on IPv6 are shown another certificate. If it is expired or for another name, they get a security warning that IPv4 visitors never see.",
            "Install the same certificate on every server or load balancer behind the AAAA records, and make sure renewals reach them too.",
        ),
        "EQV-02" => (
            "Visitors on IPv6 get a different answer than visitors on IPv4: another page, an error, or a redirect that leads nowhere for them.",
            "Make the IPv6 side serve the same configuration as the IPv4 side. Where a redirect leads to a host with no IPv6 address, give that host an AAAA record, or redirect to a name that has one.",
        ),
        "EQV-03" => (
            "Visitors on IPv6 may be shown a different page. A page whose content changes on every load can cause this by chance.",
            "Compare the two responses. If they really differ, the servers behind the AAAA records run another version or configuration of the site.",
        ),
        _ => ("", ""),
    };
    Advice { meaning, fix }
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
    /// What this means for visitors. The same for every finding of the
    /// check.
    pub meaning: String,
    /// What to do about it.
    pub fix: String,
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
            meaning: advice(check_id).meaning.to_string(),
            fix: advice(check_id).fix.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_check_says_what_it_means_and_how_to_fix_it() {
        for id in [
            "ADR-01", "ADR-02", "ADR-03", "RCH-01", "RCH-02", "RCH-03", "RCH-04", "EQV-01",
            "EQV-02", "EQV-03",
        ] {
            let advice = advice(id);
            assert!(advice.meaning.ends_with('.'), "{id}");
            assert!(advice.fix.ends_with('.'), "{id}");
        }
        for severity in Severity::ALL {
            assert!(!severity.meaning().is_empty());
        }
    }

    #[test]
    fn a_finding_carries_its_advice() {
        let obs = testkit::healthy();
        let finding = Finding::new(
            "RCH-01",
            Severity::Critical,
            &obs,
            String::new(),
            Evidence::NoAaaa { ipv4: vec![] },
        );
        assert!(finding.meaning.contains("tries this address first"));
        assert!(finding.fix.contains("remove the AAAA record"));
    }
}
