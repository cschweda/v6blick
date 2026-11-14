//! The page: does everything the page loads arrive without IPv4?
//!
//! The page is loaded twice, in `dual` and in the mode under test. A
//! request counts against the mode only when it worked in `dual`: what
//! fails on an ordinary connection too is not an IPv6 fault.

use std::collections::BTreeMap;

use super::{Evidence, Finding, Severity};
use crate::observe::{Mode, PageLoad, PageObservation, PageRequest, ProxyOutcome, RefusalReason};

/// The registrable domain a host belongs to, by the Public Suffix List:
/// `static.example.co.uk` belongs to `example.co.uk`. A host the list
/// does not place, such as an address, is its own site.
pub fn site_of(host: &str) -> &str {
    // The list is about names; it would take the last numbers of an
    // address for a domain.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host;
    }
    psl::domain_str(host).unwrap_or(host)
}

/// True when `host` is not of the same site as the page.
pub fn is_third_party(page_host: &str, host: &str) -> bool {
    site_of(page_host) != site_of(host)
}

/// What the proxy said about a host in this load, in a few words.
fn reason(load: &PageLoad, host: &str) -> (String, Option<RefusalReason>) {
    match load.connection(host).map(|c| &c.outcome) {
        Some(ProxyOutcome::Refused { reason, message }) => (message.clone(), Some(*reason)),
        Some(ProxyOutcome::Failed { stage, message, .. }) => {
            (format!("{stage} failed: {message}"), None)
        }
        Some(ProxyOutcome::Connected { address, .. }) => (
            format!("a connection to {address} opened, and the request still failed"),
            None,
        ),
        None => ("the browser never asked for a connection".to_string(), None),
    }
}

/// The mode in words, for a summary.
fn network(mode: Mode) -> &'static str {
    match mode {
        Mode::Dual => "an ordinary connection",
        Mode::V6only => "an IPv6-only network",
    }
}

pub fn check(obs: &PageObservation) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(dual) = obs.load(Mode::Dual) else {
        return findings;
    };
    let worked_in_dual = |url: &str| dual.requests.iter().any(|r| r.url == url && r.answered());

    for load in obs.loads.iter().filter(|l| l.mode != Mode::Dual) {
        let mode = load.mode;

        // PGE-01: the page's own document does not load in this mode,
        // and does in `dual`.
        let dual_ok = dual.document().is_some_and(PageRequest::answered);
        let here = load.document();
        if dual_ok && !here.is_some_and(PageRequest::answered) {
            let (url, host, error, redirected_from) = match here {
                Some(r) => (
                    r.url.clone(),
                    r.host.clone(),
                    r.failed().unwrap_or("no response").to_string(),
                    r.redirected_from.clone(),
                ),
                None => (
                    obs.url.clone(),
                    obs.host.clone(),
                    "no request was made".to_string(),
                    None,
                ),
            };
            let (why, _) = reason(load, &host);
            let summary = match &redirected_from {
                Some(from) => format!(
                    "the page cannot be loaded on {}: {from} redirects to {url}, and {why}",
                    network(mode)
                ),
                None => format!("the page cannot be loaded on {}: {why}", network(mode)),
            };
            findings.push(Finding::about(
                "PGE-01",
                Severity::Critical,
                &host,
                summary,
                Evidence::PageUnloadable {
                    mode,
                    url,
                    error,
                    redirected_from,
                    reason: why,
                },
            ));
        }

        // The rest: requests that are not the document, failed here and
        // worked in `dual`, by host. PGE-04 when a redirect led there,
        // PGE-02 when the host has no IPv6 address, PGE-03 otherwise.
        let mut by_host: BTreeMap<(&str, &str), Vec<&PageRequest>> = BTreeMap::new();
        for request in &load.requests {
            if request.document || request.failed().is_none() || !worked_in_dual(&request.url) {
                continue;
            }
            let (_, refused) = reason(load, &request.host);
            // A literal IPv4 address is the business of the LIT checks,
            // and what v6blick itself held back is no fault of the host.
            if matches!(
                refused,
                Some(RefusalReason::LiteralIpv4 | RefusalReason::NotAskedByPage)
            ) {
                continue;
            }
            let check = if request.redirected_from.is_some() {
                "PGE-04"
            } else if refused == Some(RefusalReason::NoIpv6Address) {
                "PGE-02"
            } else {
                "PGE-03"
            };
            by_host
                .entry((check, request.host.as_str()))
                .or_default()
                .push(request);
        }
        for ((check, host), requests) in by_host {
            let third_party = is_third_party(&obs.host, host);
            let (why, _) = reason(load, host);
            let count = requests.len();
            let plural = if count == 1 { "request" } else { "requests" };
            let whose = if third_party { " (third party)" } else { "" };
            let (severity, summary) = match check {
                "PGE-02" => (
                    if third_party {
                        Severity::Notice
                    } else {
                        Severity::Warning
                    },
                    format!(
                        "{count} {plural} to {host}{whose} fail on {}: the host has no IPv6 address",
                        network(mode)
                    ),
                ),
                "PGE-04" => (
                    Severity::Warning,
                    format!(
                        "{count} {plural} are redirected to {host}{whose}, which cannot be reached on {}",
                        network(mode)
                    ),
                ),
                _ => (
                    Severity::Warning,
                    format!(
                        "{count} {plural} to {host}{whose} fail on {}, though the host has an IPv6 address",
                        network(mode)
                    ),
                ),
            };
            let mut kinds: Vec<String> = requests.iter().map(|r| r.kind.clone()).collect();
            kinds.sort();
            kinds.dedup();
            findings.push(Finding::about(
                check,
                severity,
                host,
                summary,
                Evidence::HostFails {
                    mode,
                    host: host.to_string(),
                    site: site_of(host).to_string(),
                    third_party,
                    requests: count,
                    kinds,
                    urls: requests.iter().take(5).map(|r| r.url.clone()).collect(),
                    reason: why,
                },
            ));
        }
    }
    findings.sort_by(|a, b| (a.severity, &a.check_id).cmp(&(b.severity, &b.check_id)));
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::{Family, ProxiedConnection, RequestOutcome, Vantage};

    fn request(url: &str, kind: &str, outcome: RequestOutcome) -> PageRequest {
        let host = crate::probe::http::Url::parse(url).unwrap().host;
        PageRequest {
            url: url.to_string(),
            host,
            kind: kind.to_string(),
            document: kind == "document",
            redirected_from: None,
            outcome,
        }
    }

    fn ok(url: &str, kind: &str) -> PageRequest {
        request(url, kind, RequestOutcome::Loaded { status: 200 })
    }

    fn failed(url: &str, kind: &str) -> PageRequest {
        request(
            url,
            kind,
            RequestOutcome::Failed {
                error: "net::ERR_TUNNEL_CONNECTION_FAILED".to_string(),
            },
        )
    }

    fn connected(host: &str) -> ProxiedConnection {
        ProxiedConnection {
            host: host.to_string(),
            port: 443,
            tunnel: true,
            outcome: ProxyOutcome::Connected {
                address: "2606:4700::10".parse().unwrap(),
                family: Family::Ipv6,
                ms: 12,
            },
        }
    }

    fn no_ipv6(host: &str) -> ProxiedConnection {
        ProxiedConnection {
            host: host.to_string(),
            port: 443,
            tunnel: true,
            outcome: ProxyOutcome::Refused {
                reason: RefusalReason::NoIpv6Address,
                message: format!("{host} has no IPv6 address"),
            },
        }
    }

    const PAGE: &str = "https://www.example.org/";
    const CSS: &str = "https://static.example.org/site.css";
    const FONT: &str = "https://fonts.thirdparty.example/a.woff2";
    const FONT2: &str = "https://fonts.thirdparty.example/b.woff2";
    const SCRIPT: &str = "https://cdn.widgets.example/w.js";

    /// A page with a stylesheet of its own site and two third parties,
    /// all of which load in both modes.
    fn healthy() -> PageObservation {
        let requests = vec![
            ok(PAGE, "document"),
            ok(CSS, "stylesheet"),
            ok(FONT, "font"),
            ok(FONT2, "font"),
            ok(SCRIPT, "script"),
        ];
        let connections: Vec<ProxiedConnection> = [
            "www.example.org",
            "static.example.org",
            "fonts.thirdparty.example",
            "cdn.widgets.example",
        ]
        .iter()
        .map(|h| connected(h))
        .collect();
        let load = |mode| PageLoad {
            mode,
            ended: "settled".to_string(),
            requests: requests.clone(),
            connections: connections.clone(),
        };
        PageObservation {
            url: PAGE.to_string(),
            host: "www.example.org".to_string(),
            started_at_unix: 1_700_000_000,
            vantage: Vantage {
                ipv4: true,
                ipv6: true,
            },
            browser: Some("Chrome/130.0".to_string()),
            loads: vec![load(Mode::Dual), load(Mode::V6only)],
        }
    }

    /// In the `v6only` load: these addresses fail, and the proxy refused
    /// these hosts for want of an IPv6 address.
    fn break_v6only(obs: &mut PageObservation, urls: &[&str], hosts_without_ipv6: &[&str]) {
        let load = &mut obs.loads[1];
        for r in &mut load.requests {
            if urls.contains(&r.url.as_str()) {
                r.outcome = RequestOutcome::Failed {
                    error: "net::ERR_TUNNEL_CONNECTION_FAILED".to_string(),
                };
            }
        }
        for c in &mut load.connections {
            if hosts_without_ipv6.contains(&c.host.as_str()) {
                *c = no_ipv6(&c.host);
            }
        }
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.check_id.as_str()).collect()
    }

    #[test]
    fn a_page_that_loads_alike_is_clean() {
        assert!(check(&healthy()).is_empty());
    }

    #[test]
    fn sites_follow_the_public_suffix_list() {
        assert_eq!(site_of("static.example.co.uk"), "example.co.uk");
        assert_eq!(site_of("www.example.org"), "example.org");
        // A hosting domain: each customer is a site of their own.
        assert_eq!(site_of("one.netlify.app"), "one.netlify.app");
        assert_eq!(site_of("192.0.2.1"), "192.0.2.1");
        assert!(!is_third_party("www.example.org", "static.example.org"));
        assert!(is_third_party("www.example.org", "example.net"));
        assert!(is_third_party("one.netlify.app", "two.netlify.app"));
    }

    #[test]
    fn a_first_party_host_without_ipv6_is_a_warning_pge_02() {
        let mut obs = healthy();
        break_v6only(&mut obs, &[CSS], &["static.example.org"]);
        let findings = check(&obs);
        assert_eq!(ids(&findings), ["PGE-02"]);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].name, "static.example.org");
        assert_eq!(
            findings[0].summary,
            "1 request to static.example.org fail on an IPv6-only network: the host has no IPv6 address"
        );
    }

    #[test]
    fn a_third_party_without_ipv6_is_a_notice_and_one_finding_per_host() {
        let mut obs = healthy();
        break_v6only(
            &mut obs,
            &[FONT, FONT2, SCRIPT],
            &["fonts.thirdparty.example", "cdn.widgets.example"],
        );
        let findings = check(&obs);
        assert_eq!(ids(&findings), ["PGE-02", "PGE-02"]);
        assert!(findings.iter().all(|f| f.severity == Severity::Notice));
        match &findings[1].evidence {
            Evidence::HostFails {
                host,
                site,
                third_party,
                requests,
                kinds,
                urls,
                ..
            } => {
                assert_eq!(host, "fonts.thirdparty.example");
                assert_eq!(site, "thirdparty.example");
                assert!(third_party);
                assert_eq!(
                    (*requests, kinds.as_slice()),
                    (2, &["font".to_string()][..])
                );
                assert_eq!(urls, &[FONT, FONT2]);
            }
            other => panic!("{other:?}"),
        }
        assert!(
            findings[1]
                .summary
                .contains("2 requests to fonts.thirdparty.example (third party)")
        );
    }

    #[test]
    fn a_host_with_ipv6_whose_requests_fail_is_pge_03() {
        let mut obs = healthy();
        // The connection opened; the request failed all the same.
        break_v6only(&mut obs, &[SCRIPT], &[]);
        let findings = check(&obs);
        assert_eq!(ids(&findings), ["PGE-03"]);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(
            findings[0]
                .summary
                .contains("though the host has an IPv6 address")
        );
    }

    #[test]
    fn what_fails_on_an_ordinary_connection_too_is_not_reported() {
        let mut obs = healthy();
        break_v6only(&mut obs, &[SCRIPT], &["cdn.widgets.example"]);
        // The same request fails in dual.
        obs.loads[0].requests[4] = failed(SCRIPT, "script");
        assert!(check(&obs).is_empty());
    }

    #[test]
    fn a_page_whose_host_has_no_ipv6_is_critical_pge_01() {
        let mut obs = healthy();
        obs.loads[1].requests = vec![failed(PAGE, "document")];
        obs.loads[1].connections = vec![no_ipv6("www.example.org")];
        let findings = check(&obs);
        assert_eq!(ids(&findings), ["PGE-01"]);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(
            findings[0].summary,
            "the page cannot be loaded on an IPv6-only network: www.example.org has no IPv6 address"
        );
    }

    #[test]
    fn a_page_that_redirects_to_a_host_without_ipv6_is_pge_01() {
        let mut obs = healthy();
        let apex = "https://example.org/";
        let mut first = request(PAGE, "document", RequestOutcome::Redirected { status: 301 });
        first.document = true;
        let mut second = failed(apex, "document");
        second.redirected_from = Some(PAGE.to_string());
        obs.loads[1].requests = vec![first, second];
        obs.loads[1].connections = vec![connected("www.example.org"), no_ipv6("example.org")];
        let findings = check(&obs);
        assert_eq!(ids(&findings), ["PGE-01"]);
        assert_eq!(findings[0].name, "example.org");
        assert_eq!(
            findings[0].summary,
            "the page cannot be loaded on an IPv6-only network: https://www.example.org/ redirects to https://example.org/, and example.org has no IPv6 address"
        );
    }

    #[test]
    fn a_resource_redirected_to_an_unreachable_host_is_pge_04() {
        let mut obs = healthy();
        let moved = "https://old.widgets.example/w.js";
        for load in &mut obs.loads {
            load.requests[4].outcome = RequestOutcome::Redirected { status: 302 };
            let mut target = ok(moved, "script");
            target.redirected_from = Some(SCRIPT.to_string());
            load.requests.push(target);
            load.connections.push(connected("old.widgets.example"));
        }
        break_v6only(&mut obs, &[moved], &["old.widgets.example"]);
        let findings = check(&obs);
        assert_eq!(ids(&findings), ["PGE-04"]);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(
            findings[0]
                .summary
                .contains("are redirected to old.widgets.example")
        );
    }

    #[test]
    fn a_literal_ipv4_address_is_left_to_the_lit_checks() {
        let mut obs = healthy();
        let pixel = "http://192.0.2.44/track.gif";
        for load in &mut obs.loads {
            load.requests.push(ok(pixel, "image"));
        }
        break_v6only(&mut obs, &[pixel], &[]);
        obs.loads[1].connections.push(ProxiedConnection {
            host: "192.0.2.44".to_string(),
            port: 80,
            tunnel: false,
            outcome: ProxyOutcome::Refused {
                reason: RefusalReason::LiteralIpv4,
                message: "192.0.2.44 is an IPv4 address".to_string(),
            },
        });
        assert!(check(&obs).is_empty());
    }

    #[test]
    fn without_a_baseline_nothing_is_judged() {
        let mut obs = healthy();
        obs.loads.remove(0);
        assert!(check(&obs).is_empty());
    }
}
