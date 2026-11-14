//! A whole `check` run, offline: the DNS side answers from a hand-built
//! world, and the host is a local server with an IPv4 and an IPv6
//! listener that can be made to differ.

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use common::World;
use common::server::{Site, serve};
use v6blick::checks::{self, Finding, Severity, Thresholds};
use v6blick::cli::{CommandOutput, RunError, observe, report};
use v6blick::observe::{LookupSource, Observation};
use v6blick::output::{Report, exit, json};
use v6blick::probe::ProbeConfig;
use v6blick::resolve::{Client, NetConfig};

const PAGE: &str = "<html><body><h1>Hello</h1></body></html>";

fn local() -> ProbeConfig {
    ProbeConfig {
        allow_private: true,
        connect_timeout: Duration::from_secs(2),
        tls_timeout: Duration::from_secs(2),
        http_timeout: Duration::from_secs(2),
        ..ProbeConfig::default()
    }
}

/// Run `check` against the local server on `port`. The root servers of
/// the world answer over both families, so this machine counts as having
/// IPv6; `localhost` is not in that world and comes from the system.
async fn check_local(scheme: &str, port: u16) -> (String, Result<Observation, RunError>) {
    let target = format!("{scheme}://localhost:{port}/");
    let outcome = observe(&target, World::new().client(), local()).await;
    (target, outcome)
}

fn ids(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.check_id.as_str()).collect()
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// One listener serves the page with certificate `a`; the other has
/// certificate `b` and redirects to a page that is gone.
async fn different_ipv6() -> u16 {
    serve(|port| {
        (
            Some(Site::page(Some('a'), 200, PAGE)),
            Some(Site::page(Some('b'), 200, "unused").redirect(
                "/",
                301,
                &format!("https://localhost:{port}/old"),
            )),
        )
    })
    .await
}

#[tokio::test]
async fn the_same_site_over_both_families_is_clean() {
    let site = Site::page(Some('a'), 200, PAGE);
    let port = serve(|_| (Some(site.clone()), Some(site))).await;
    let (target, outcome) = check_local("https", port).await;
    let obs = outcome.as_ref().unwrap();
    assert_eq!(obs.host, "localhost.");
    assert_eq!(obs.lookup.source, LookupSource::System);
    assert!(obs.ipv6_walks.is_empty());
    assert_eq!(obs.probes.len(), 2);
    assert!(checks::run_all(obs, &Thresholds::default()).is_empty());

    let out = report(&target, outcome, false, false);
    assert_eq!(out.exit_code, exit::CLEAN);
    assert!(
        out.stdout.contains("None. All checks passed."),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("127.0.0.1") && out.stdout.contains("::1"));
}

#[tokio::test]
async fn a_different_ipv6_listener_is_eqv_01_and_eqv_02() {
    let port = different_ipv6().await;
    let (target, outcome) = check_local("https", port).await;
    let findings = checks::run_all(outcome.as_ref().unwrap(), &Thresholds::default());
    assert_eq!(ids(&findings), ["EQV-01", "EQV-02"]);
    assert!(findings.iter().all(|f| f.severity == Severity::Warning));
    assert!(findings.iter().all(|f| f.name == "localhost."));

    let out = report(&target, outcome, false, false);
    assert_eq!(out.exit_code, exit::FINDINGS);
    // Each finding shows its check ID, the host and the evidence.
    assert!(out.stdout.contains("WARNING (2)"), "{}", out.stdout);
    assert!(out.stdout.contains("EQV-01  localhost."));
    assert!(
        out.stdout
            .contains("serves a different certificate over IPv6")
    );
    assert!(out.stdout.contains("EQV-02  localhost."));
    assert!(
        out.stdout
            .contains("answers 200 over IPv4 and 301 over IPv6")
    );
    assert!(out.stdout.contains("IPv4 127.0.0.1: 200"));
    assert!(
        out.stdout
            .contains(&format!("IPv6 ::1: 301 to https://localhost:{port}/old"))
    );
    assert!(
        out.stdout
            .ends_with("Summary: 0 critical, 2 warning, 0 notice, 0 info\n")
    );
}

#[tokio::test]
async fn a_dead_ipv6_listener_is_rch_01() {
    let port = serve(|_| (Some(Site::page(None, 200, PAGE)), None)).await;
    let (target, outcome) = check_local("http", port).await;
    let findings = checks::run_all(outcome.as_ref().unwrap(), &Thresholds::default());
    assert_eq!(ids(&findings), ["RCH-01"]);
    assert_eq!(findings[0].severity, Severity::Critical);

    let out = report(&target, outcome, false, false);
    assert_eq!(out.exit_code, exit::CRITICAL);
    assert!(out.stdout.contains("CRITICAL (1)"), "{}", out.stdout);
    assert!(out.stdout.contains("RCH-01  localhost."));
    assert!(
        out.stdout
            .contains("the AAAA record ::1 is published and nothing accepts a connection there")
    );
    assert!(out.stdout.contains(&format!("port {port}: refused after")));
}

#[tokio::test]
async fn a_handshake_that_fails_over_ipv6_only_is_rch_02() {
    let port = serve(|_| {
        (
            Some(Site::page(Some('a'), 200, PAGE)),
            Some(Site::page(None, 200, PAGE)),
        )
    })
    .await;
    let (_, outcome) = check_local("https", port).await;
    let findings = checks::run_all(&outcome.unwrap(), &Thresholds::default());
    assert_eq!(ids(&findings), ["RCH-02"]);
}

#[tokio::test]
async fn without_ipv6_on_this_machine_nothing_is_tested() {
    // A site whose IPv6 side is dead: a careless tool would call it broken.
    let port = serve(|_| (Some(Site::page(None, 200, PAGE)), None)).await;
    // The root answers over IPv4 only, as on a network without IPv6.
    let mut world = World::default();
    world.answer(
        common::ROOT_V4,
        ".",
        v6blick::observe::QType::Ns,
        &[common::ns(".", "a.root-servers.net.")],
    );
    let target = format!("http://localhost:{port}/");
    let outcome = observe(&target, world.client(), local()).await;
    assert!(matches!(outcome, Err(RunError::NoIpv6 { .. })));

    let out = report(&target, outcome, false, false);
    assert_eq!(out.exit_code, exit::RUN_FAILED);
    assert!(out.stdout.is_empty());
    assert!(out.stderr.contains("no working IPv6"), "{}", out.stderr);
    assert!(!out.stderr.contains("RCH-01"));
}

#[tokio::test]
async fn without_any_network_the_run_fails() {
    let outcome = observe("example.org", World::default().client(), local()).await;
    assert!(matches!(outcome, Err(RunError::NoNetwork)));
}

#[tokio::test]
async fn a_host_that_does_not_exist_is_a_failed_run() {
    use v6blick::observe::QType;
    let mut world = World::new();
    for qtype in [QType::A, QType::Aaaa] {
        for root in [common::ROOT_V4, common::ROOT_V6] {
            world.nxdomain(root, "nothing.invalid.", qtype, ".");
        }
    }
    // Without --allow-private the system resolver is never asked.
    let config = ProbeConfig::default();
    let outcome = observe("nothing.invalid", world.client(), config).await;
    assert!(
        matches!(outcome, Err(RunError::NotFound { .. })),
        "{outcome:?}"
    );
    let out = report("nothing.invalid", outcome, true, false);
    let doc: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(doc["error"]["kind"], "host_not_found");
    assert_eq!(
        doc["error"]["message"],
        "nothing.invalid. does not exist (NXDOMAIN)"
    );
}

#[tokio::test]
async fn the_json_document_has_a_fixed_shape() {
    let port = different_ipv6().await;
    let (target, outcome) = check_local("https", port).await;
    let out: CommandOutput = report(&target, outcome, true, false);
    assert_eq!(out.exit_code, exit::FINDINGS);
    assert!(out.stderr.is_empty());
    let doc: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    // serde_json keeps the order the fields were written in only with a
    // feature v6blick does not use, so the order is read from the text.
    let top: Vec<&str> = out
        .stdout
        .lines()
        .filter(|l| l.starts_with("  \""))
        .map(|l| l.trim().split('"').nth(1).unwrap())
        .collect();
    assert_eq!(
        top,
        [
            "schema_version",
            "version",
            "host",
            "target",
            "started_at_unix",
            "vantage",
            "lookup",
            "ipv6_walks",
            "probes",
            "findings",
            "summary",
            "exit_code"
        ]
    );
    assert_eq!(doc["schema_version"], 1);
    assert_eq!(doc["host"], "localhost.");
    assert_eq!(doc["vantage"]["ipv6"], true);
    assert_eq!(doc["lookup"]["source"], "system");
    assert_eq!(doc["probes"][1]["family"], "ipv6");
    assert_eq!(doc["probes"][1]["connect"]["result"], "connected");
    assert_eq!(doc["probes"][1]["tls"]["result"], "ok");
    assert_eq!(doc["probes"][1]["exchanges"][0]["result"], "response");
    assert_eq!(doc["probes"][1]["exchanges"][0]["status"], 301);
    assert_eq!(doc["findings"][0]["check_id"], "EQV-01");
    assert_eq!(doc["findings"][0]["severity"], "warning");
    assert_eq!(
        doc["findings"][0]["evidence"]["kind"],
        "certificate_mismatch"
    );
    assert_eq!(doc["findings"][1]["evidence"]["kind"], "response_mismatch");
    assert_eq!(doc["summary"]["warning"], 2);
    assert_eq!(doc["exit_code"], 1);
}

/// A saved `--json` document holds the whole observation, so the checks
/// can be run on it again, and must come to what was saved.
fn replay(name: &str) -> (serde_json::Value, serde_json::Value) {
    let text = std::fs::read_to_string(fixture(name)).unwrap();
    let saved: serde_json::Value = serde_json::from_str(&text).unwrap();
    let observation: Observation = serde_json::from_str(&text).unwrap();
    let findings = checks::run_all(&observation, &Thresholds::default());
    let again = Report::new(observation, findings);
    let mut again: serde_json::Value = serde_json::from_str(&json::render(&again)).unwrap();
    // The version is that of the build, not of the recording.
    again["version"] = saved["version"].clone();
    (saved, again)
}

#[test]
fn a_recorded_run_of_a_healthy_site_checks_clean_again() {
    let (saved, again) = replay("zoneblick.com.report.json");
    assert_eq!(saved, again);
    assert_eq!(again["findings"].as_array().unwrap().len(), 0);
    assert_eq!(again["exit_code"], 0);
    assert_eq!(again["probes"].as_array().unwrap().len(), 16);
}

#[test]
fn a_recorded_run_of_a_differing_site_gives_the_same_findings_again() {
    let (saved, again) = replay("different-ipv6.report.json");
    assert_eq!(saved, again);
    let found: Vec<&str> = again["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["check_id"].as_str().unwrap())
        .collect();
    assert_eq!(found, ["EQV-01", "EQV-02"]);
}

/// Writes the two fixtures above again. The first needs the network.
/// Run with `cargo test --test check record_fixtures -- --ignored`.
#[tokio::test]
#[ignore = "uses the live network and rewrites tests/fixtures"]
async fn record_fixtures() {
    let live = Arc::new(Client::live(NetConfig::default()));
    let outcome = observe("zoneblick.com", live, ProbeConfig::default()).await;
    let out = report("zoneblick.com", outcome, true, false);
    std::fs::write(fixture("zoneblick.com.report.json"), out.stdout).unwrap();

    let port = different_ipv6().await;
    let (target, outcome) = check_local("https", port).await;
    let out = report(&target, outcome, true, false);
    std::fs::write(fixture("different-ipv6.report.json"), out.stdout).unwrap();
}

#[tokio::test]
#[ignore = "uses the live network"]
async fn zoneblick_com_has_no_critical_finding_live() {
    let live = Arc::new(Client::live(NetConfig::default()));
    let obs = observe("zoneblick.com", live, ProbeConfig::default())
        .await
        .unwrap();
    assert!(!obs.lookup.aaaa.addresses.is_empty());
    assert!(obs.ipv6_walks.iter().all(|w| w.failed_at.is_none()));
    let findings = checks::run_all(&obs, &Thresholds::default());
    assert!(findings.iter().all(|f| f.severity != Severity::Critical));
}
