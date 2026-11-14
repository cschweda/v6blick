//! Reachability: does anything answer at the IPv6 address?

use std::collections::BTreeMap;
use std::net::IpAddr;

use super::{Attempt, Evidence, Finding, Severity, Thresholds};
use crate::observe::{AddressProbe, Connect, Family, Observation, Scheme, Tls};

pub fn check(obs: &Observation, thresholds: &Thresholds) -> Vec<Finding> {
    let mut findings = Vec::new();
    let v4: Vec<&AddressProbe> = obs.probes_of(Family::Ipv4).collect();
    let mut by_address: BTreeMap<IpAddr, Vec<&AddressProbe>> = BTreeMap::new();
    for probe in obs.probes_of(Family::Ipv6) {
        by_address.entry(probe.address).or_default().push(probe);
    }

    // When IPv4 was tried and nothing opened there either, the site is
    // down, or this machine cannot reach it. That is not an IPv6 fault.
    let v4_tried = v4
        .iter()
        .any(|p| !matches!(p.connect, Connect::NotProbed { .. }));
    let v4_opens = v4.iter().any(|p| p.connect.connected_ms().is_some());
    let down_everywhere = v4_tried && !v4_opens;

    for (address, probes) in &by_address {
        // RCH-01: a published address where no port accepts a connection.
        // An address that was not contacted says nothing either way.
        let tried: Vec<&&AddressProbe> = probes
            .iter()
            .filter(|p| !matches!(p.connect, Connect::NotProbed { .. }))
            .collect();
        if !down_everywhere && !tried.is_empty() && tried.iter().all(|p| p.connect.is_failure()) {
            findings.push(Finding::new(
                "RCH-01",
                Severity::Critical,
                obs,
                format!(
                    "the AAAA record {address} is published and nothing accepts a connection there"
                ),
                Evidence::NoConnection {
                    address: *address,
                    attempts: tried
                        .iter()
                        .map(|p| Attempt {
                            port: p.port,
                            result: p.connect.label(),
                        })
                        .collect(),
                },
            ));
        }

        // RCH-02: the handshake fails here and succeeds over IPv4.
        for probe in probes.iter().filter(|p| p.scheme == Scheme::Https) {
            let Some(Tls::Failed { message }) = &probe.tls else {
                continue;
            };
            let works = v4
                .iter()
                .find(|p| p.port == probe.port && matches!(p.tls, Some(Tls::Ok { .. })));
            if let Some(works) = works {
                findings.push(Finding::new(
                    "RCH-02",
                    Severity::Critical,
                    obs,
                    format!("the TLS handshake fails over IPv6 ({address}) and succeeds over IPv4"),
                    Evidence::TlsFailure {
                        address: *address,
                        port: probe.port,
                        error: message.clone(),
                        ipv4_address: works.address,
                    },
                ));
            }
        }

        // RCH-04: a client that tries this address first waits this long
        // before it can fall back to an IPv4 address that works.
        let slowest = probes
            .iter()
            .filter(|p| {
                v4.iter()
                    .any(|q| q.port == p.port && q.connect.connected_ms().is_some())
            })
            .filter_map(|p| p.connect.failure_ms().map(|ms| (ms, p)))
            .filter(|(ms, _)| *ms > thresholds.wait_ms)
            .max_by_key(|(ms, _)| *ms);
        if let Some((waited_ms, probe)) = slowest {
            findings.push(Finding::new(
                "RCH-04",
                Severity::Notice,
                obs,
                format!(
                    "a client that tries IPv6 first waits {waited_ms} ms at {address} before it can fall back to IPv4"
                ),
                Evidence::FallbackWait {
                    address: *address,
                    port: probe.port,
                    waited_ms,
                    result: probe.connect.label(),
                },
            ));
        }
    }

    // RCH-03: IPv6 opens much more slowly than IPv4. The fastest address
    // of each family is compared, on each port; the widest gap is told.
    let fastest = |family: Family, port: u16| {
        obs.probes_of(family)
            .filter(|p| p.port == port)
            .filter_map(|p| p.connect.connected_ms().map(|ms| (ms, p.address)))
            .min()
    };
    let mut ports: Vec<u16> = obs.probes.iter().map(|p| p.port).collect();
    ports.sort_unstable();
    ports.dedup();
    let widest = ports
        .into_iter()
        .filter_map(|port| {
            Some((
                port,
                fastest(Family::Ipv4, port)?,
                fastest(Family::Ipv6, port)?,
            ))
        })
        .filter(|(_, (ms4, _), (ms6, _))| *ms6 > ms4 + thresholds.slower_ms)
        .max_by_key(|(_, (ms4, _), (ms6, _))| ms6 - ms4);
    if let Some((port, (ipv4_ms, ipv4_address), (ipv6_ms, ipv6_address))) = widest {
        findings.push(Finding::new(
            "RCH-03",
            Severity::Notice,
            obs,
            format!(
                "a connection over IPv6 takes {ipv6_ms} ms to open, against {ipv4_ms} ms over IPv4"
            ),
            Evidence::SlowerConnect {
                port,
                ipv4_address,
                ipv4_ms,
                ipv6_address,
                ipv6_ms,
            },
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testkit::*;

    fn run(obs: &Observation) -> Vec<Finding> {
        check(obs, &Thresholds::default())
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.check_id.as_str()).collect()
    }

    #[test]
    fn a_healthy_host_is_clean() {
        assert!(run(&healthy()).is_empty());
    }

    #[test]
    fn an_address_that_refuses_every_port_is_rch_01() {
        let mut obs = healthy();
        *at(&mut obs, V6, Scheme::Https) = dead(V6, Scheme::Https, Connect::Refused { ms: 3 });
        // One port still answers: something is there.
        assert!(run(&obs).is_empty());
        *at(&mut obs, V6, Scheme::Http) = dead(V6, Scheme::Http, Connect::Refused { ms: 2 });
        let findings = run(&obs);
        assert_eq!(ids(&findings), ["RCH-01"]);
        assert_eq!(findings[0].severity, Severity::Critical);
        match &findings[0].evidence {
            Evidence::NoConnection { address, attempts } => {
                assert_eq!(*address, ip(V6));
                assert_eq!(attempts.len(), 2);
                assert_eq!(attempts[0].result, "refused after 3 ms");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_address_that_was_not_contacted_is_not_rch_01() {
        let mut obs = healthy();
        for scheme in [Scheme::Https, Scheme::Http] {
            *at(&mut obs, V6, scheme) = dead(
                V6,
                scheme,
                Connect::NotProbed {
                    reason: "private".to_string(),
                },
            );
        }
        assert!(run(&obs).is_empty());
    }

    #[test]
    fn a_site_that_is_down_over_ipv4_too_is_not_an_ipv6_fault() {
        let mut obs = healthy();
        for address in [V4, V6] {
            for scheme in [Scheme::Https, Scheme::Http] {
                *at(&mut obs, address, scheme) = dead(address, scheme, Connect::Refused { ms: 1 });
            }
        }
        assert!(run(&obs).is_empty());
        // A host with IPv6 addresses only has no IPv4 to excuse it.
        obs.probes.retain(|p| p.family == Family::Ipv6);
        assert_eq!(ids(&run(&obs)), ["RCH-01"]);
    }

    #[test]
    fn each_dead_address_is_its_own_finding() {
        let mut obs = healthy();
        let other = "2001:db8::11";
        obs.probes
            .push(dead(other, Scheme::Https, Connect::TimedOut { ms: 400 }));
        obs.probes
            .push(dead(other, Scheme::Http, Connect::TimedOut { ms: 400 }));
        let findings = run(&obs);
        assert_eq!(ids(&findings), ["RCH-01"]);
        assert!(findings[0].summary.contains(other));
    }

    #[test]
    fn a_handshake_that_fails_over_ipv6_only_is_rch_02() {
        let mut obs = healthy();
        let broken = Some(Tls::Failed {
            message: "received fatal alert: HandshakeFailure".to_string(),
        });
        let probe = at(&mut obs, V6, Scheme::Https);
        probe.tls = broken.clone();
        probe.exchanges.clear();
        let findings = run(&obs);
        assert_eq!(ids(&findings), ["RCH-02"]);
        assert_eq!(findings[0].severity, Severity::Critical);

        // When it fails over IPv4 as well, it is not an IPv6 fault.
        let probe = at(&mut obs, V4, Scheme::Https);
        probe.tls = broken;
        probe.exchanges.clear();
        assert!(run(&obs).is_empty());
    }

    #[test]
    fn a_much_slower_ipv6_connect_is_rch_03() {
        let mut obs = healthy();
        at(&mut obs, V6, Scheme::Https).connect = Connect::Connected { ms: 270 };
        // 250 ms more is the line; exactly on it is not over it.
        assert!(run(&obs).is_empty());
        at(&mut obs, V6, Scheme::Https).connect = Connect::Connected { ms: 271 };
        at(&mut obs, V6, Scheme::Http).connect = Connect::Connected { ms: 400 };
        let findings = run(&obs);
        // One finding, for the port with the wider gap.
        assert_eq!(ids(&findings), ["RCH-03"]);
        assert_eq!(findings[0].severity, Severity::Notice);
        assert!(matches!(
            findings[0].evidence,
            Evidence::SlowerConnect {
                port: 80,
                ipv4_ms: 20,
                ipv6_ms: 400,
                ..
            }
        ));
    }

    #[test]
    fn the_fastest_address_of_each_family_is_compared() {
        let mut obs = healthy();
        at(&mut obs, V6, Scheme::Https).connect = Connect::Connected { ms: 900 };
        at(&mut obs, V6, Scheme::Http).connect = Connect::Connected { ms: 900 };
        // A second IPv6 address that is quick: a client would use it.
        obs.probes.push(probe("2001:db8::11", Scheme::Https, 25));
        obs.probes.push(probe("2001:db8::11", Scheme::Http, 25));
        assert!(run(&obs).is_empty());
    }

    #[test]
    fn a_slow_failure_is_rch_04_and_a_quick_one_is_not() {
        let mut obs = healthy();
        for scheme in [Scheme::Https, Scheme::Http] {
            *at(&mut obs, V6, scheme) = dead(V6, scheme, Connect::Refused { ms: 4 });
        }
        // Refused at once: dead, but no wait.
        assert_eq!(ids(&run(&obs)), ["RCH-01"]);

        *at(&mut obs, V6, Scheme::Https) = dead(V6, Scheme::Https, Connect::TimedOut { ms: 5000 });
        let findings = run(&obs);
        assert_eq!(ids(&findings), ["RCH-01", "RCH-04"]);
        assert!(matches!(
            findings[1].evidence,
            Evidence::FallbackWait {
                port: 443,
                waited_ms: 5000,
                ..
            }
        ));

        // With nothing to fall back to there is no fallback to wait for,
        // and a site that is down over IPv4 too is not an IPv6 fault.
        for scheme in [Scheme::Https, Scheme::Http] {
            *at(&mut obs, V4, scheme) = dead(V4, scheme, Connect::Refused { ms: 4 });
        }
        assert!(run(&obs).is_empty());
    }
}
