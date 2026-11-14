//! Terminal output: addresses, the IPv6-only walk, one line per probe,
//! then the findings by severity.

use std::fmt::Write;
use std::net::IpAddr;

use super::{Report, utc};
use crate::checks::{Answer, Evidence, Finding, ServedBody, ServedCertificate, Severity};
use crate::observe::{
    AddressProbe, Connect, ExchangeOutcome, FamilyLookup, LookupSource, LookupStatus, Tls,
};

pub(crate) struct Style {
    pub color: bool,
}

impl Style {
    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn bold(&self, text: &str) -> String {
        self.paint("1", text)
    }

    pub fn dim(&self, text: &str) -> String {
        self.paint("2", text)
    }

    pub fn good(&self, text: &str) -> String {
        self.paint("32", text)
    }

    pub fn bad(&self, text: &str) -> String {
        self.paint("1;31", text)
    }

    fn severity(&self, severity: Severity, text: &str) -> String {
        let code = match severity {
            Severity::Critical => "1;31",
            Severity::Warning => "1;33",
            Severity::Notice => "1;36",
            Severity::Info => "1",
        };
        self.paint(code, text)
    }
}

/// Render a `check` report for a terminal. `color` turns ANSI colours on.
pub fn render(report: &Report, color: bool) -> String {
    let st = Style { color };
    let obs = &report.observation;
    let mut out = String::new();
    let w = &mut out;

    let _ = writeln!(w, "{}", st.bold(&format!("v6blick check {}", obs.target)));
    let _ = writeln!(
        w,
        "{}",
        st.dim(&format!(
            "{}   IPv6 on this machine: working",
            utc(obs.started_at_unix)
        ))
    );
    let _ = writeln!(w);
    addresses(w, &st, report);
    walks(w, &st, report);
    probes(w, &st, report);
    findings(w, &st, report);

    let s = report.summary;
    let _ = writeln!(
        w,
        "{} {} critical, {} warning, {} notice, {} info",
        st.bold("Summary:"),
        s.critical,
        s.warning,
        s.notice,
        s.info
    );
    out
}

fn list<T: ToString>(items: &[T]) -> String {
    if items.is_empty() {
        return "(none)".to_string();
    }
    items
        .iter()
        .map(T::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn family_line(lookup: &FamilyLookup) -> String {
    match lookup.status {
        LookupStatus::Answer => list(&lookup.addresses),
        LookupStatus::Nodata => "(no record)".to_string(),
        LookupStatus::Nxdomain => "(the name does not exist)".to_string(),
        LookupStatus::Failed => format!(
            "(lookup failed: {})",
            lookup.error.as_deref().unwrap_or("no answer")
        ),
    }
}

fn addresses(w: &mut String, st: &Style, report: &Report) {
    let lookup = &report.observation.lookup;
    let _ = writeln!(w, "{}", st.bold("Addresses"));
    let _ = writeln!(w, "  {}", lookup.name);
    for target in &lookup.cname_chain {
        let _ = writeln!(w, "  {}", st.dim(&format!("is an alias for {target}")));
    }
    let _ = writeln!(w, "  A     {}", family_line(&lookup.a));
    let _ = writeln!(w, "  AAAA  {}", family_line(&lookup.aaaa));
    if lookup.source == LookupSource::System {
        let _ = writeln!(
            w,
            "  {}",
            st.dim("from this machine's own resolver: the public DNS does not know the name")
        );
    }
    let _ = writeln!(w);
}

fn walks(w: &mut String, st: &Style, report: &Report) {
    let walks = &report.observation.ipv6_walks;
    if walks.is_empty() {
        return;
    }
    let _ = writeln!(w, "{}", st.bold("Resolving over IPv6 only"));
    for walk in walks {
        let mut zones = vec![".".to_string()];
        zones.extend(walk.path.iter().map(|s| s.to_zone.clone()));
        let path = zones.join(" -> ");
        match &walk.failed_at {
            None => {
                let _ = writeln!(w, "  {}  {}", walk.name, st.good("reached"));
                let _ = writeln!(w, "    {}", st.dim(&path));
            }
            Some(failure) => {
                let _ = writeln!(
                    w,
                    "  {}  {}",
                    walk.name,
                    st.bad(&format!("stops at {}", failure.zone))
                );
                let _ = writeln!(w, "    {}", st.dim(&path));
                let _ = writeln!(w, "    {}", st.dim(&failure.detail));
            }
        }
    }
    let _ = writeln!(w);
}

/// What one probe came to, in a few words per stage.
fn probe_line(probe: &AddressProbe) -> (String, bool) {
    let mut parts = Vec::new();
    let mut ok = true;
    match &probe.connect {
        Connect::Connected { ms } => parts.push(format!("connected in {ms} ms")),
        other => {
            ok = false;
            parts.push(other.label());
        }
    }
    match &probe.tls {
        Some(Tls::Ok { certificate, .. }) => parts.push(format!(
            "TLS ok, certificate {}{}",
            &certificate.sha256[..certificate.sha256.len().min(12)],
            if certificate.covers_host {
                ""
            } else {
                " (not for this host)"
            }
        )),
        Some(Tls::Failed { message }) => {
            ok = false;
            parts.push(format!("TLS failed: {message}"));
        }
        None => {}
    }
    let mut chain = Vec::new();
    for exchange in &probe.exchanges {
        match &exchange.outcome {
            ExchangeOutcome::Response(r) => match &r.location {
                Some(to) if (300..400).contains(&r.status) => {
                    chain.push(format!("{} to {to}", r.status))
                }
                _ => chain.push(format!("{}, {} bytes", r.status, r.body_bytes)),
            },
            ExchangeOutcome::Failed { message, .. } => {
                ok = false;
                chain.push(format!("failed: {message}"));
            }
        }
    }
    if !chain.is_empty() {
        parts.push(chain.join(" -> "));
    }
    (parts.join("; "), ok)
}

fn probes(w: &mut String, st: &Style, report: &Report) {
    let probes = &report.observation.probes;
    if probes.is_empty() {
        return;
    }
    let _ = writeln!(w, "{}", st.bold("Probes"));
    let width = probes
        .iter()
        .map(|p| p.address.to_string().len())
        .max()
        .unwrap_or(0);
    let mut last = None;
    for probe in probes {
        if last != Some((probe.scheme, probe.port)) {
            last = Some((probe.scheme, probe.port));
            let _ = writeln!(w, "  {} on port {}", probe.scheme.as_str(), probe.port);
        }
        let (line, ok) = probe_line(probe);
        let _ = writeln!(
            w,
            "    {}  {:<width$}  {}",
            probe.family.as_str(),
            probe.address.to_string(),
            if ok { line } else { st.bad(&line) },
        );
    }
    let _ = writeln!(w);
}

fn findings(w: &mut String, st: &Style, report: &Report) {
    let _ = writeln!(w, "{}", st.bold("Findings"));
    if report.findings.is_empty() {
        let _ = writeln!(w, "  None. All checks passed.");
        let _ = writeln!(w);
        return;
    }
    for severity in Severity::ALL {
        let group: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.severity == severity)
            .collect();
        if group.is_empty() {
            continue;
        }
        let heading = format!("{} ({})", severity.as_str().to_uppercase(), group.len());
        let _ = writeln!(w, "  {}", st.severity(severity, &heading));
        for finding in group {
            let _ = writeln!(w, "    {}  {}", st.bold(&finding.check_id), finding.name);
            let _ = writeln!(w, "      {}", finding.summary);
            for line in evidence_lines(&finding.evidence) {
                let _ = writeln!(w, "      {}", st.dim(&line));
            }
        }
        let _ = writeln!(w);
    }
}

fn short(sha256: &str) -> &str {
    &sha256[..sha256.len().min(12)]
}

fn certificate_line(family: &str, c: &ServedCertificate) -> String {
    let expires = c
        .not_after_unix
        .map(|t| format!(", expires {}", utc(t)))
        .unwrap_or_default();
    format!(
        "{family} {}: {} for {}{expires}",
        c.address,
        short(&c.sha256),
        list(&c.names)
    )
}

fn answer_line(family: &str, a: &Answer) -> String {
    let mut line = format!("{family} {}: {}", a.address, a.status);
    if let Some(to) = &a.location {
        let _ = write!(line, " to {to}");
    }
    match a.ended.as_str() {
        "page" => {
            if a.final_url.is_some() && a.location.is_some() {
                let _ = write!(
                    line,
                    ", ends at {} with {}",
                    a.final_url.as_deref().unwrap_or_default(),
                    a.final_status.unwrap_or_default()
                );
            }
        }
        "failed" => {
            let _ = write!(
                line,
                ", then fails ({})",
                a.failure.as_deref().unwrap_or("no response")
            );
        }
        _ => line.push_str(", and the redirects do not end"),
    }
    line
}

fn body_line(family: &str, b: &ServedBody) -> String {
    format!(
        "{family} {}: {} bytes{}, structure {}",
        b.address,
        b.bytes,
        if b.truncated { " (cut off)" } else { "" },
        short(&b.shape_sha256)
    )
}

fn addresses_of(list: &[IpAddr]) -> String {
    self::list(list)
}

/// The evidence behind a finding, a line at a time.
pub fn evidence_lines(evidence: &Evidence) -> Vec<String> {
    match evidence {
        Evidence::NoAaaa { ipv4 } => vec![
            format!("A: {}", addresses_of(ipv4)),
            "AAAA: (none)".to_string(),
        ],
        Evidence::UnusableAaaa { address, reason } => {
            vec![format!("{address}: {}", reason.describe())]
        }
        Evidence::Ipv6WalkFailed {
            zone, detail, path, ..
        } => {
            let mut zones = vec![".".to_string()];
            zones.extend(path.iter().cloned());
            vec![
                format!("path over IPv6: {}", zones.join(" -> ")),
                format!("{zone}: {detail}"),
            ]
        }
        Evidence::NoConnection { attempts, .. } => attempts
            .iter()
            .map(|a| format!("port {}: {}", a.port, a.result))
            .collect(),
        Evidence::TlsFailure {
            port,
            error,
            ipv4_address,
            ..
        } => vec![
            format!("port {port} over IPv6: {error}"),
            format!("port {port} over IPv4: handshake ok at {ipv4_address}"),
        ],
        Evidence::SlowerConnect {
            port,
            ipv4_address,
            ipv4_ms,
            ipv6_address,
            ipv6_ms,
        } => vec![
            format!("port {port} IPv4 {ipv4_address}: {ipv4_ms} ms"),
            format!("port {port} IPv6 {ipv6_address}: {ipv6_ms} ms"),
        ],
        Evidence::FallbackWait { port, result, .. } => vec![format!("port {port}: {result}")],
        Evidence::CertificateMismatch { ipv4, ipv6, .. } => ipv4
            .iter()
            .map(|c| certificate_line("IPv4", c))
            .chain(ipv6.iter().map(|c| certificate_line("IPv6", c)))
            .collect(),
        Evidence::ResponseMismatch { ipv4, ipv6, .. } => ipv4
            .iter()
            .map(|a| answer_line("IPv4", a))
            .chain(ipv6.iter().map(|a| answer_line("IPv6", a)))
            .collect(),
        Evidence::BodyMismatch { ipv4, ipv6, .. } => ipv4
            .iter()
            .map(|b| body_line("IPv4", b))
            .chain(ipv6.iter().map(|b| body_line("IPv6", b)))
            .collect(),
    }
}
