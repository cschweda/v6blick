//! Equivalence: is it the same site over IPv6 as over IPv4?
//!
//! Each check compares, for one URL, what the IPv4 addresses did with
//! what the IPv6 addresses did, and reports only when no IPv6 address
//! agrees with any IPv4 address.

use super::{Answer, Evidence, Finding, ServedBody, ServedCertificate, Severity, Thresholds};
use crate::observe::{AddressProbe, ExchangeOutcome, Family, Observation, Response, Scheme};

/// The URLs that were probed, as (scheme, port), HTTPS first.
fn urls(obs: &Observation) -> Vec<(Scheme, u16)> {
    let mut urls: Vec<(Scheme, u16)> = obs.probes.iter().map(|p| (p.scheme, p.port)).collect();
    urls.sort();
    urls.dedup();
    urls
}

fn certificate_of(probe: &AddressProbe) -> Option<ServedCertificate> {
    let c = probe.tls.as_ref()?.certificate()?;
    Some(ServedCertificate {
        address: probe.address,
        sha256: c.sha256.clone(),
        names: c.names.clone(),
        not_after_unix: c.not_after_unix,
        covers_host: c.covers_host,
    })
}

fn answer_of(probe: &AddressProbe) -> Option<Answer> {
    let first = probe.first_response()?;
    let last = probe.exchanges.last()?;
    let mut answer = Answer {
        address: probe.address,
        status: first.status,
        location: first.location.clone(),
        ended: "redirecting".to_string(),
        final_url: None,
        final_status: None,
        failure: None,
    };
    match &last.outcome {
        ExchangeOutcome::Response(r) if !(300..400).contains(&r.status) => {
            answer.ended = "page".to_string();
            answer.final_url = Some(last.url.clone());
            answer.final_status = Some(r.status);
        }
        ExchangeOutcome::Response(_) => {}
        ExchangeOutcome::Failed { stage, message } => {
            answer.ended = "failed".to_string();
            answer.final_url = Some(last.url.clone());
            answer.failure = Some(format!("{stage}: {message}"));
        }
    }
    Some(answer)
}

/// Two answers agree when a visitor would see the same thing happen. The
/// wording of a failure is left out: it carries addresses and timings.
fn same_answer(a: &Answer, b: &Answer) -> bool {
    (
        a.status,
        &a.location,
        &a.ended,
        &a.final_url,
        a.final_status,
    ) == (
        b.status,
        &b.location,
        &b.ended,
        &b.final_url,
        b.final_status,
    )
}

fn body_of(probe: &AddressProbe) -> Option<(ServedBody, &Response)> {
    let (exchange, response) = probe.final_response()?;
    Some((
        ServedBody {
            address: probe.address,
            url: exchange.url.clone(),
            bytes: response.body_bytes,
            truncated: response.body_truncated,
            body_sha256: response.body_sha256.clone(),
            shape_sha256: response.shape_sha256.clone(),
        },
        response,
    ))
}

/// Two bodies agree when they have the same structure and about the same
/// size. Pages with per-request content differ in their bytes on every
/// load; they keep their structure.
fn same_body(a: &ServedBody, b: &ServedBody, thresholds: &Thresholds) -> bool {
    if a.body_sha256 == b.body_sha256 {
        return true;
    }
    let (small, large) = (a.bytes.min(b.bytes), a.bytes.max(b.bytes));
    let gap = large - small;
    let sizes_differ = gap > thresholds.size_bytes && gap * 100 > large * thresholds.size_percent;
    a.shape_sha256 == b.shape_sha256 && !sizes_differ
}

pub fn check(obs: &Observation, thresholds: &Thresholds) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut compared_pages: Vec<String> = Vec::new();
    let mut differing_urls: Vec<String> = Vec::new();
    for (scheme, port) in urls(obs) {
        let of = |family: Family| -> Vec<&AddressProbe> {
            obs.probes_of(family)
                .filter(|p| p.scheme == scheme && p.port == port)
                .collect()
        };
        let (v4, v6) = (of(Family::Ipv4), of(Family::Ipv6));
        let host = obs.host.trim_end_matches('.');
        let default_port = port == scheme.default_port();
        let origin = if default_port {
            format!("{}://{host}", scheme.as_str())
        } else {
            format!("{}://{host}:{port}", scheme.as_str())
        };

        // EQV-01: a different certificate.
        let certs4: Vec<ServedCertificate> = v4.iter().filter_map(|p| certificate_of(p)).collect();
        let certs6: Vec<ServedCertificate> = v6.iter().filter_map(|p| certificate_of(p)).collect();
        let shared = certs6
            .iter()
            .any(|c6| certs4.iter().any(|c4| c4.sha256 == c6.sha256));
        if !certs4.is_empty() && !certs6.is_empty() && !shared {
            let stale = certs6.iter().any(|c| !c.covers_host);
            findings.push(Finding::new(
                "EQV-01",
                Severity::Warning,
                obs,
                if stale {
                    format!("{origin} serves a different certificate over IPv6, and it is not for this host")
                } else {
                    format!("{origin} serves a different certificate over IPv6 than over IPv4")
                },
                Evidence::CertificateMismatch {
                    port,
                    ipv4: certs4,
                    ipv6: certs6,
                },
            ));
        }

        // EQV-02: a different status or redirect.
        let answers4: Vec<Answer> = v4.iter().filter_map(|p| answer_of(p)).collect();
        let answers6: Vec<Answer> = v6.iter().filter_map(|p| answer_of(p)).collect();
        let url = v4
            .iter()
            .chain(v6.iter())
            .find_map(|p| p.exchanges.first().map(|e| e.url.clone()))
            .unwrap_or_else(|| format!("{origin}/"));
        let agree = answers6
            .iter()
            .any(|a6| answers4.iter().any(|a4| same_answer(a4, a6)));
        // http:// usually redirects to the https:// address. When that
        // one already has a finding, the same fault is not told twice.
        let through_reported = v4.iter().any(|p| {
            p.exchanges
                .iter()
                .skip(1)
                .any(|e| differing_urls.contains(&e.url))
        });
        if through_reported {
            continue;
        }
        let mut answers_differ = false;
        if !answers4.is_empty() && !answers6.is_empty() && !agree {
            answers_differ = true;
            differing_urls.push(url.clone());
            let (a4, a6) = (&answers4[0], &answers6[0]);
            let summary = if a4.status != a6.status {
                format!(
                    "{url} answers {} over IPv4 and {} over IPv6",
                    a4.status, a6.status
                )
            } else if a4.location != a6.location {
                format!("{url} redirects to a different place over IPv6 than over IPv4")
            } else if a6.ended == "failed" {
                format!(
                    "{url} redirects to {}, which works over IPv4 and fails over IPv6",
                    a6.final_url.as_deref().unwrap_or("another address")
                )
            } else {
                format!("{url} ends at a different page over IPv6 than over IPv4")
            };
            findings.push(Finding::new(
                "EQV-02",
                Severity::Warning,
                obs,
                summary,
                Evidence::ResponseMismatch {
                    url: url.clone(),
                    ipv4: answers4,
                    ipv6: answers6,
                },
            ));
        }

        // EQV-03: a different page. When the answers already differ the
        // bodies do too, and EQV-02 has said so.
        if answers_differ {
            continue;
        }
        let bodies4: Vec<ServedBody> = v4.iter().filter_map(|p| body_of(p)).map(|b| b.0).collect();
        let bodies6: Vec<ServedBody> = v6.iter().filter_map(|p| body_of(p)).map(|b| b.0).collect();
        let (Some(first4), Some(_)) = (bodies4.first(), bodies6.first()) else {
            continue;
        };
        // http:// usually ends at the https:// page, which was compared.
        if compared_pages.contains(&first4.url) {
            continue;
        }
        compared_pages.push(first4.url.clone());
        let alike = bodies6
            .iter()
            .any(|b6| bodies4.iter().any(|b4| same_body(b4, b6, thresholds)));
        if !alike {
            findings.push(Finding::new(
                "EQV-03",
                Severity::Notice,
                obs,
                format!(
                    "{} returns a different page over IPv6 than over IPv4",
                    first4.url
                ),
                Evidence::BodyMismatch {
                    url: first4.url.clone(),
                    ipv4: bodies4,
                    ipv6: bodies6,
                },
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testkit::*;
    use crate::observe::{Exchange, Tls};

    fn run(obs: &Observation) -> Vec<Finding> {
        check(obs, &Thresholds::default())
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.check_id.as_str()).collect()
    }

    fn set_cert(obs: &mut Observation, address: &str, tag: &str, covers_host: bool) {
        let mut cert = certificate(tag);
        cert.covers_host = covers_host;
        at(obs, address, Scheme::Https).tls = Some(Tls::Ok {
            ms: 20,
            certificate: cert,
        });
    }

    fn set_first(obs: &mut Observation, address: &str, scheme: Scheme, r: Response) {
        let probe = at(obs, address, scheme);
        let url = probe.exchanges[0].url.clone();
        probe.exchanges = vec![exchange(&url, address, r)];
    }

    #[test]
    fn a_healthy_host_is_clean() {
        assert!(run(&healthy()).is_empty());
    }

    #[test]
    fn a_different_certificate_over_ipv6_is_eqv_01() {
        let mut obs = healthy();
        set_cert(&mut obs, V6, "b", true);
        let findings = run(&obs);
        assert_eq!(ids(&findings), ["EQV-01"]);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(!findings[0].summary.contains("not for this host"));

        set_cert(&mut obs, V6, "b", false);
        assert!(run(&obs)[0].summary.contains("not for this host"));
    }

    #[test]
    fn one_shared_certificate_among_several_addresses_is_enough() {
        let mut obs = healthy();
        // Two servers per family, mid-renewal: old and new on each side.
        obs.probes.push(probe("192.0.2.11", Scheme::Https, 20));
        obs.probes.push(probe("2001:db8::11", Scheme::Https, 20));
        set_cert(&mut obs, "192.0.2.11", "b", true);
        set_cert(&mut obs, V6, "b", true);
        assert!(run(&obs).is_empty());
        // No overlap at all is a finding.
        set_cert(&mut obs, "2001:db8::11", "c", true);
        set_cert(&mut obs, "192.0.2.11", "a", true);
        assert_eq!(ids(&run(&obs)), ["EQV-01"]);
    }

    #[test]
    fn a_different_status_is_eqv_02_and_not_also_eqv_03() {
        let mut obs = healthy();
        set_first(
            &mut obs,
            V6,
            Scheme::Https,
            response(503, None, "maintenance"),
        );
        let findings = run(&obs);
        assert_eq!(ids(&findings), ["EQV-02"]);
        assert_eq!(
            findings[0].summary,
            "https://www.example.org/ answers 200 over IPv4 and 503 over IPv6"
        );
    }

    #[test]
    fn a_different_redirect_is_eqv_02() {
        let mut obs = healthy();
        for (address, to) in [
            (V4, "https://www.example.org/new"),
            (V6, "https://www.example.org/old"),
        ] {
            set_first(&mut obs, address, Scheme::Http, response(301, Some(to), ""));
        }
        let findings = run(&obs);
        assert_eq!(ids(&findings), ["EQV-02"]);
        assert!(
            findings[0]
                .summary
                .starts_with("http://www.example.org/ redirects to a different place")
        );
    }

    #[test]
    fn a_redirect_to_a_host_without_ipv6_is_eqv_02() {
        let mut obs = healthy();
        let to = "https://shop.example.org/";
        for address in [V4, V6] {
            set_first(
                &mut obs,
                address,
                Scheme::Https,
                response(302, Some(to), ""),
            );
        }
        at(&mut obs, V4, Scheme::Https).exchanges.push(exchange(
            to,
            "192.0.2.99",
            response(200, None, "shop page"),
        ));
        at(&mut obs, V6, Scheme::Https).exchanges.push(Exchange {
            url: to.to_string(),
            address: None,
            outcome: ExchangeOutcome::Failed {
                stage: "resolve".to_string(),
                message: "shop.example.org has no IPv6 address".to_string(),
            },
        });
        let findings = run(&obs);
        assert_eq!(ids(&findings), ["EQV-02"]);
        assert_eq!(
            findings[0].summary,
            "https://www.example.org/ redirects to https://shop.example.org/, which works over IPv4 and fails over IPv6"
        );
        match &findings[0].evidence {
            Evidence::ResponseMismatch { ipv6, .. } => {
                assert_eq!(ipv6[0].ended, "failed");
                assert!(
                    ipv6[0]
                        .failure
                        .as_deref()
                        .unwrap()
                        .contains("no IPv6 address")
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_fault_behind_a_redirect_from_http_is_told_once() {
        let mut obs = healthy();
        let (https, shop) = ("https://www.example.org/", "https://shop.example.org/");
        let lost = || Exchange {
            url: shop.to_string(),
            address: None,
            outcome: ExchangeOutcome::Failed {
                stage: "resolve".to_string(),
                message: "shop.example.org has no IPv6 address".to_string(),
            },
        };
        for address in [V4, V6] {
            set_first(
                &mut obs,
                address,
                Scheme::Https,
                response(302, Some(shop), ""),
            );
            set_first(
                &mut obs,
                address,
                Scheme::Http,
                response(301, Some(https), ""),
            );
            at(&mut obs, address, Scheme::Http).exchanges.push(exchange(
                https,
                address,
                response(302, Some(shop), ""),
            ));
        }
        for scheme in [Scheme::Https, Scheme::Http] {
            at(&mut obs, V4, scheme).exchanges.push(exchange(
                shop,
                "192.0.2.99",
                response(200, None, "shop page"),
            ));
            at(&mut obs, V6, scheme).exchanges.push(lost());
        }
        let findings = run(&obs);
        assert_eq!(ids(&findings), ["EQV-02"]);
        assert!(
            findings[0]
                .summary
                .starts_with("https://www.example.org/ redirects")
        );
    }

    #[test]
    fn a_page_with_another_structure_is_eqv_03() {
        let mut obs = healthy();
        for scheme in [Scheme::Https, Scheme::Http] {
            set_first(&mut obs, V6, scheme, response(200, None, "other page"));
        }
        let findings = run(&obs);
        // https:// and http:// end at different addresses here, so both are told.
        assert_eq!(ids(&findings), ["EQV-03", "EQV-03"]);
        assert_eq!(findings[0].severity, Severity::Notice);
    }

    #[test]
    fn per_request_content_is_not_eqv_03() {
        let mut obs = healthy();
        // Same structure ("page"), other bytes, about the same size.
        set_first(&mut obs, V6, Scheme::Https, response(200, None, "page two"));
        set_first(&mut obs, V6, Scheme::Http, response(200, None, "page 2!!"));
        assert!(run(&obs).is_empty());
    }

    #[test]
    fn the_same_structure_at_a_very_different_size_is_eqv_03() {
        let mut obs = healthy();
        let long = format!("page {}", "x".repeat(2000));
        set_first(&mut obs, V4, Scheme::Https, response(200, None, &long));
        let findings = run(&obs);
        assert_eq!(ids(&findings), ["EQV-03"]);

        // A small difference in a small body is not worth a finding.
        let mut obs = healthy();
        set_first(
            &mut obs,
            V4,
            Scheme::Https,
            response(200, None, &format!("page {}", "x".repeat(200))),
        );
        assert!(run(&obs).is_empty());
    }

    #[test]
    fn a_page_reached_from_both_schemes_is_compared_once() {
        let mut obs = healthy();
        let page = "https://www.example.org/";
        for address in [V4, V6] {
            set_first(
                &mut obs,
                address,
                Scheme::Http,
                response(301, Some(page), ""),
            );
            let body = if address == V4 {
                "page one"
            } else {
                "other page"
            };
            at(&mut obs, address, Scheme::Http).exchanges.push(exchange(
                page,
                address,
                response(200, None, body),
            ));
            set_first(&mut obs, address, Scheme::Https, response(200, None, body));
        }
        assert_eq!(ids(&run(&obs)), ["EQV-03"]);
    }

    #[test]
    fn with_one_family_missing_there_is_nothing_to_compare() {
        let mut obs = healthy();
        obs.probes.retain(|p| p.family == Family::Ipv4);
        assert!(run(&obs).is_empty());
    }
}
