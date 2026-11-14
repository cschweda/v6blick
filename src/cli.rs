//! The command line: argument parsing, and the `check` and `doctor`
//! commands. [`observe`] is the whole of a `check` run up to the checks,
//! with the DNS client and the probe settings handed in, so that tests
//! can run it without the network.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};

use crate::checks::{self, Thresholds};
use crate::doctor;
use crate::observe::{HostLookup, LookupStatus, Observation, Vantage, special_use};
use crate::output::human::Style;
use crate::output::{FailureReport, Report, exit, human, json};
use crate::probe::{self, BoxFuture, ProbeConfig, Resolve};
use crate::resolve::iterate::printable;
use crate::resolve::{self, Client, NetConfig, hints::ROOT_HINTS};

#[derive(Debug, Parser)]
#[command(
    name = "v6blick",
    version,
    about = "Tests whether a website works for someone who has no IPv4",
    after_help = "Exit codes: 0 clean, 1 notices or warnings, 2 at least one critical finding, 3 the run itself failed.\nTest your own sites, or sites you have permission to test."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Look a host up, connect to it over IPv4 and over IPv6 separately,
    /// and compare the two
    Check(CheckArgs),
    /// Load a page in an installed Chrome or Chromium, once on an
    /// ordinary connection and once without IPv4, and say what breaks
    Page(PageArgs),
    /// Say whether this machine has working IPv6 and whether Chrome or
    /// Chromium is installed
    Doctor,
}

/// The network a page is tested in, after the `dual` baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ModeArg {
    /// An IPv6-only network with no translator
    V6only,
}

#[derive(Debug, Args)]
pub struct PageArgs {
    /// The page: an http or https address, or a host name for https
    #[arg(value_name = "URL")]
    pub url: String,
    /// The network to test the page in
    #[arg(long, value_enum, default_value = "v6only")]
    pub mode: ModeArg,
    /// Print one JSON document instead of text
    #[arg(long)]
    pub json: bool,
    /// Let private, loopback and link-local addresses be contacted, for
    /// testing a build on your own machine or network
    #[arg(long)]
    pub allow_private: bool,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// A host name such as example.org, or an http or https address
    #[arg(value_name = "HOST-OR-URL")]
    pub target: String,
    /// Print one JSON document instead of text
    #[arg(long)]
    pub json: bool,
    /// Let private, loopback and link-local addresses be contacted, for
    /// testing a build on your own machine or network
    #[arg(long)]
    pub allow_private: bool,
}

/// What a command printed and how it ended.
#[derive(Debug, Default)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: u8,
}

/// Why a `check` run could not produce a report.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("{0}")]
    InvalidTarget(String),
    #[error(
        "this machine has no working network: no root server answered over IPv4 or IPv6. Nothing was tested"
    )]
    NoNetwork,
    #[error(
        "this machine has no working IPv6, so the IPv6 half of every comparison cannot run. Nothing was tested, and nothing is wrong with {host} as far as v6blick can tell. Run `v6blick doctor` for details"
    )]
    NoIpv6 { host: String },
    #[error(
        "this machine has no working IPv4, so there is nothing to compare IPv6 with. Nothing was tested"
    )]
    NoIpv4,
    #[error("{host} does not exist (NXDOMAIN)")]
    NotFound { host: String },
    #[error("{host} has no A and no AAAA record")]
    NoAddresses { host: String },
    #[error("{host} could not be resolved: {detail}")]
    LookupFailed { host: String, detail: String },
    #[error("TLS could not be set up: {0}")]
    Tls(#[from] rustls::Error),
    #[error(
        "no Chrome or Chromium was found, in the usual places or on the search path. The page test needs one; `v6blick check` does not"
    )]
    NoBrowser,
    #[error("the browser could not be used: {0}")]
    Browser(String),
    #[error(
        "{url} does not load on an ordinary connection ({why}), so there is nothing to compare"
    )]
    PageUnreachable { url: String, why: String },
    #[error(
        "nothing accepts a connection at {host}, over IPv4 or over IPv6, so there is nothing to compare. The site may be down, or this machine may be unable to reach it"
    )]
    Unreachable { host: String },
    #[error(
        "every address of {host} is one v6blick does not contact ({reason}), so nothing was tested"
    )]
    NotContacted { host: String, reason: String },
    #[error(
        "the run did not finish in {secs} s and was stopped. Nothing is reported, because half a comparison would mislead"
    )]
    Deadline { secs: u64 },
}

impl RunError {
    /// A stable identifier for the JSON error document.
    pub fn kind(&self) -> &'static str {
        match self {
            RunError::InvalidTarget(_) => "invalid_target",
            RunError::NoNetwork => "no_network",
            RunError::NoIpv6 { .. } => "no_ipv6",
            RunError::NoIpv4 => "no_ipv4",
            RunError::NotFound { .. } => "host_not_found",
            RunError::NoAddresses { .. } => "no_addresses",
            RunError::LookupFailed { .. } => "lookup_failed",
            RunError::Tls(_) => "tls_setup",
            RunError::Deadline { .. } => "deadline",
            RunError::Unreachable { .. } => "unreachable",
            RunError::NoBrowser => "no_browser",
            RunError::Browser(_) => "browser",
            RunError::PageUnreachable { .. } => "page_unreachable",
            RunError::NotContacted { .. } => "not_contacted",
        }
    }
}

/// Resolves the hosts that redirects name, the same way as the host
/// that was asked for.
struct Redirects {
    client: Arc<Client>,
    vantage: Vantage,
    allow_private: bool,
}

impl Resolve for Redirects {
    fn addresses<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, String>> {
        Box::pin(async move {
            let name = resolve::normalise_host(host).map_err(|e| e.to_string())?;
            let lookup =
                find_host(self.client.clone(), self.vantage, &name, self.allow_private).await;
            let all: Vec<IpAddr> = lookup
                .a
                .addresses
                .iter()
                .chain(lookup.aaaa.addresses.iter())
                .copied()
                .collect();
            if all.is_empty() {
                Err("no address was found".to_string())
            } else {
                Ok(all)
            }
        })
    }
}

/// The addresses of a host: from the root, or, for a name the public DNS
/// does not have and with private destinations allowed, from this
/// machine's own resolver.
async fn find_host(
    client: Arc<Client>,
    vantage: Vantage,
    host: &str,
    allow_private: bool,
) -> HostLookup {
    let lookup = resolve::lookup_host(client, vantage, host).await;
    // Only a definite "no such name" from the public DNS sends the
    // question to this machine's resolver. A zone that merely fails to
    // answer must not get the name looked up somewhere else, with the
    // IPv6-only walk skipped.
    let no_such_name =
        lookup.a.status == LookupStatus::Nxdomain && lookup.aaaa.status == LookupStatus::Nxdomain;
    if !allow_private || !no_such_name {
        return lookup;
    }
    let system = resolve::lookup_host_system(host).await;
    if system.a.addresses.is_empty() && system.aaaa.addresses.is_empty() {
        lookup
    } else {
        system
    }
}

/// Everything a `check` run does on the network: find out which address
/// families work here, look the host up, walk to it over IPv6 only, and
/// probe each address. The whole of it has one deadline.
pub async fn observe(
    target: &str,
    client: Arc<Client>,
    config: ProbeConfig,
) -> Result<Observation, RunError> {
    let deadline = config.run_deadline;
    match tokio::time::timeout(deadline, observe_within(target, client, config)).await {
        Ok(outcome) => outcome,
        Err(_) => Err(RunError::Deadline {
            secs: deadline.as_secs(),
        }),
    }
}

async fn observe_within(
    target: &str,
    client: Arc<Client>,
    config: ProbeConfig,
) -> Result<Observation, RunError> {
    let urls = probe::targets(target).map_err(RunError::InvalidTarget)?;
    let host = resolve::normalise_host(&urls[0].host)
        .map_err(|e| RunError::InvalidTarget(e.to_string()))?;
    let started_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Before anything is said about the host: can this machine tell?
    let vantage = resolve::detect_vantage(&client).await;
    match (vantage.ipv4, vantage.ipv6) {
        (false, false) => return Err(RunError::NoNetwork),
        (true, false) => return Err(RunError::NoIpv6 { host }),
        (false, true) => return Err(RunError::NoIpv4),
        (true, true) => {}
    }

    let lookup = find_host(client.clone(), vantage, &host, config.allow_private).await;
    if lookup.a.addresses.is_empty() && lookup.aaaa.addresses.is_empty() {
        let failed = [&lookup.a, &lookup.aaaa]
            .into_iter()
            .find(|f| f.status == LookupStatus::Failed);
        return Err(match failed {
            Some(family) => RunError::LookupFailed {
                host,
                detail: family.error.clone().unwrap_or_default(),
            },
            None if lookup.a.status == LookupStatus::Nxdomain => RunError::NotFound { host },
            None => RunError::NoAddresses { host },
        });
    }

    let addresses = probe::select_addresses(&lookup, config.max_addresses);
    let redirects = Arc::new(Redirects {
        client: client.clone(),
        vantage,
        allow_private: config.allow_private,
    });
    let walks = async {
        let mut walks = Vec::new();
        // A name from the system resolver is not in the public DNS, so
        // there is no delegation to walk.
        if lookup.source == crate::observe::LookupSource::Root {
            walks.push(resolve::walk_ipv6_only(client.clone(), &host).await);
            let canonical = lookup.canonical_name();
            if canonical != host {
                walks.push(resolve::walk_ipv6_only(client.clone(), canonical).await);
            }
        }
        walks
    };
    let probes = probe::probe_all(&urls, &addresses, Arc::new(config), redirects);
    let (ipv6_walks, probes) = tokio::join!(walks, probes);
    let probes = probes?;

    // A report compares two families. When no connection opened at all
    // there is nothing to compare, and saying "IPv6 is broken" of a site
    // that is down, or of addresses that were never contacted, would be
    // a false finding.
    if !probes.iter().any(|p| p.connect.connected_ms().is_some()) {
        let refused = probes.iter().find_map(|p| match &p.connect {
            crate::observe::Connect::NotProbed { reason } => Some(reason.clone()),
            _ => None,
        });
        let tried = probes.iter().any(|p| p.connect.is_failure());
        return Err(match refused {
            Some(reason) if !tried => RunError::NotContacted { host, reason },
            _ => RunError::Unreachable { host },
        });
    }

    Ok(Observation {
        host,
        // What was typed may come from a pull request, and is printed.
        target: printable(target.trim()),
        started_at_unix,
        vantage,
        lookup,
        ipv6_walks,
        probes,
    })
}

/// Turn the outcome of a run into what `check` prints.
pub fn report(
    target: &str,
    outcome: Result<Observation, RunError>,
    as_json: bool,
    color: bool,
) -> CommandOutput {
    match outcome {
        Ok(observation) => {
            let findings = checks::run_all(&observation, &Thresholds::default());
            let report = Report::new(observation, findings);
            CommandOutput {
                stdout: if as_json {
                    json::render(&report)
                } else {
                    human::render(&report, color)
                },
                stderr: String::new(),
                exit_code: report.exit_code,
            }
        }
        Err(e) => {
            let mut output = CommandOutput {
                exit_code: exit::RUN_FAILED,
                ..Default::default()
            };
            // An error may quote what was typed; it stays on one line
            // and holds no control characters.
            let message = printable(&e.to_string());
            if as_json {
                let doc = FailureReport::new(&printable(target), e.kind(), message);
                output.stdout = json::render(&doc);
            } else {
                output.stderr = format!("v6blick: {message}\n");
            }
            output
        }
    }
}

/// `v6blick check`.
pub async fn check(args: &CheckArgs, color: bool) -> CommandOutput {
    let client = Arc::new(Client::live(NetConfig {
        allow_private: args.allow_private,
        ..NetConfig::default()
    }));
    let config = ProbeConfig {
        allow_private: args.allow_private,
        ..ProbeConfig::default()
    };
    let outcome = observe(&args.target, client, config).await;
    report(&args.target, outcome, args.json, color)
}

/// Turn the outcome of a page run into what `page` prints.
pub fn report_page(
    target: &str,
    outcome: Result<crate::observe::PageObservation, RunError>,
    as_json: bool,
    color: bool,
) -> CommandOutput {
    match outcome {
        Ok(observation) => {
            let findings = checks::pge::check(&observation);
            let report = crate::output::PageReport::new(observation, findings);
            CommandOutput {
                stdout: if as_json {
                    json::render(&report)
                } else {
                    human::render_page(&report, color)
                },
                stderr: String::new(),
                exit_code: report.exit_code,
            }
        }
        Err(e) => report(target, Err(e), as_json, color),
    }
}

/// `v6blick page`.
pub async fn page(args: &PageArgs, color: bool) -> CommandOutput {
    // What is wrong with the address is said before a browser is looked for.
    if let Err(why) = crate::page::page_url(&args.url) {
        let bad = Err(RunError::InvalidTarget(why));
        return report_page(&args.url, bad, args.json, color);
    }
    let candidates = doctor::chrome_candidates(|name| std::env::var_os(name));
    let Some(chrome) = doctor::find_chrome(&candidates).cloned() else {
        return report_page(&args.url, Err(RunError::NoBrowser), args.json, color);
    };
    // A page names many hosts, so it may ask more of the DNS than a
    // check of one host.
    let client = Arc::new(Client::live(NetConfig {
        allow_private: args.allow_private,
        max_queries: 5000,
        ..NetConfig::default()
    }));
    let mode = match args.mode {
        ModeArg::V6only => crate::observe::Mode::V6only,
    };
    let settings = crate::page::PageSettings {
        allow_private: args.allow_private,
        ..crate::page::PageSettings::new(chrome, mode)
    };
    let outcome = crate::page::observe_page(&args.url, client, settings).await;
    report_page(&args.url, outcome, args.json, color)
}

/// `v6blick doctor`.
pub async fn doctor(color: bool) -> CommandOutput {
    let client = Client::live(NetConfig::default());
    let vantage = resolve::detect_vantage(&client).await;
    let candidates = doctor::chrome_candidates(|name| std::env::var_os(name));
    let chrome = doctor::find_chrome(&candidates).map(|p| p.display().to_string());
    let root_v6: IpAddr = ROOT_HINTS[0].2.parse().expect("root hint address is valid");
    let source = doctor::source_address(root_v6);
    render_doctor(vantage, source, chrome.as_deref(), color)
}

/// What `doctor` prints for what it found.
pub fn render_doctor(
    vantage: Vantage,
    ipv6_source: Option<IpAddr>,
    chrome: Option<&str>,
    color: bool,
) -> CommandOutput {
    use std::fmt::Write;
    let st = Style { color };
    let mut out = String::new();
    let w = &mut out;
    let state = |ok: bool, yes: &str, no: &str| {
        if ok {
            st.good(&format!("{yes:<9}"))
        } else {
            st.bad(&format!("{no:<9}"))
        }
    };
    let _ = writeln!(w, "{}", st.bold("v6blick doctor"));
    let _ = writeln!(w);
    let _ = writeln!(
        w,
        "  IPv4    {}  {}",
        state(vantage.ipv4, "working", "missing"),
        if vantage.ipv4 {
            "a root server answered over IPv4"
        } else {
            "no root server answered over IPv4"
        }
    );
    let _ = writeln!(
        w,
        "  IPv6    {}  {}",
        state(vantage.ipv6, "working", "missing"),
        if vantage.ipv6 {
            "a root server answered over IPv6"
        } else {
            "no root server answered over IPv6"
        }
    );
    let detail = match ipv6_source {
        Some(address) => match special_use(address) {
            None => format!("this machine's IPv6 address is {address}"),
            Some(kind) => format!(
                "this machine's IPv6 address is {address}, a {} address that does not reach the internet",
                kind.describe()
            ),
        },
        None => "this machine has no IPv6 address with a route to the internet".to_string(),
    };
    let _ = writeln!(w, "  {:<19}{}", "", st.dim(&detail));
    let _ = writeln!(
        w,
        "  Chrome  {}  {}",
        state(chrome.is_some(), "found", "not found"),
        chrome.unwrap_or("no Chrome or Chromium in the usual places or on the search path")
    );
    let _ = writeln!(w);
    let ready = vantage.ipv4 && vantage.ipv6;
    let verdict = match (vantage.ipv4, vantage.ipv6) {
        (true, true) => "This machine can run `v6blick check`.",
        (true, false) => {
            "This machine cannot run `v6blick check`: without working IPv6 the IPv6 half of every comparison would fail for every site. Try a network with IPv6, or a server that has it."
        }
        (false, true) => {
            "This machine cannot run `v6blick check`: without working IPv4 there is nothing to compare IPv6 with."
        }
        (false, false) => "This machine cannot run `v6blick check`: the network does not work.",
    };
    let _ = writeln!(w, "{verdict}");
    if chrome.is_none() {
        let _ = writeln!(
            w,
            "The page test, when it is built, will need Chrome or Chromium. `check` does not."
        );
    }
    CommandOutput {
        stdout: out,
        stderr: String::new(),
        exit_code: if ready { exit::CLEAN } else { exit::RUN_FAILED },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOTH: Vantage = Vantage {
        ipv4: true,
        ipv6: true,
    };

    #[test]
    fn doctor_says_when_all_is_well() {
        let out = render_doctor(
            BOTH,
            Some("2606:4700::1".parse().unwrap()),
            Some("/usr/bin/chromium"),
            false,
        );
        assert_eq!(out.exit_code, exit::CLEAN);
        assert!(out.stdout.contains("IPv6    working"));
        assert!(out.stdout.contains("Chrome  found      /usr/bin/chromium"));
        assert!(out.stdout.contains("can run `v6blick check`"));
        assert!(!out.stdout.contains('\x1b'));
    }

    #[test]
    fn doctor_fails_without_ipv6_and_says_why() {
        let only_v4 = Vantage {
            ipv4: true,
            ipv6: false,
        };
        let out = render_doctor(only_v4, Some("fe80::1".parse().unwrap()), None, false);
        assert_eq!(out.exit_code, exit::RUN_FAILED);
        assert!(out.stdout.contains("IPv6    missing"));
        assert!(
            out.stdout
                .contains("link-local address that does not reach the internet")
        );
        assert!(out.stdout.contains("Chrome  not found"));
        assert!(out.stdout.contains("cannot run `v6blick check`"));
    }

    #[test]
    fn a_missing_browser_alone_is_not_a_failure() {
        let out = render_doctor(BOTH, Some("2606:4700::1".parse().unwrap()), None, false);
        assert_eq!(out.exit_code, exit::CLEAN);
        assert!(out.stdout.contains("`check` does not"));
    }

    #[test]
    fn a_failed_run_is_text_on_stderr_or_json_on_stdout() {
        let error = || {
            Err(RunError::NoIpv6 {
                host: "example.org.".to_string(),
            })
        };
        let text = report("example.org", error(), false, false);
        assert_eq!(text.exit_code, exit::RUN_FAILED);
        assert!(text.stdout.is_empty());
        assert!(
            text.stderr
                .starts_with("v6blick: this machine has no working IPv6")
        );
        assert!(text.stderr.contains("nothing is wrong with example.org."));

        let doc = report("example.org", error(), true, false);
        assert!(doc.stderr.is_empty());
        let value: serde_json::Value = serde_json::from_str(&doc.stdout).unwrap();
        assert_eq!(value["error"]["kind"], "no_ipv6");
        assert_eq!(value["exit_code"], 3);
        assert_eq!(value["target"], "example.org");
    }
}
