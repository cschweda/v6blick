//! Addresses: does the name have an IPv6 address a client can use?

use super::{Evidence, Finding, Severity};
use crate::observe::{LookupSource, LookupStatus, Observation, special_use};

pub fn check(obs: &Observation) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lookup = &obs.lookup;

    // ADR-01: an A record and no AAAA record. A lookup that failed is
    // not "no record": nothing is known then.
    if !lookup.a.addresses.is_empty()
        && matches!(
            lookup.aaaa.status,
            LookupStatus::Nodata | LookupStatus::Nxdomain
        )
    {
        findings.push(Finding::new(
            "ADR-01",
            Severity::Warning,
            obs,
            "the host has an IPv4 address and no IPv6 address".to_string(),
            Evidence::NoAaaa {
                ipv4: lookup.a.addresses.clone(),
            },
        ));
    }

    // ADR-02: an AAAA record no client can use. A name the system
    // resolver supplied (`localhost`, a hosts file) is local on purpose.
    if lookup.source == LookupSource::Root {
        for address in &lookup.aaaa.addresses {
            if let Some(reason) = special_use(*address) {
                findings.push(Finding::new(
                    "ADR-02",
                    Severity::Warning,
                    obs,
                    format!(
                        "the AAAA record {address} is a {} address, which no client can use",
                        reason.describe()
                    ),
                    Evidence::UnusableAaaa {
                        address: *address,
                        reason,
                    },
                ));
            }
        }
    }

    // ADR-03: the zone cannot be resolved over IPv6 alone.
    for walk in &obs.ipv6_walks {
        let Some(failure) = &walk.failed_at else {
            continue;
        };
        // An alias and its target often fail at the same zone; say it once.
        let repeated = findings.iter().any(|f: &Finding| {
            matches!(&f.evidence, Evidence::Ipv6WalkFailed { zone, .. } if zone == &failure.zone)
        });
        if repeated {
            continue;
        }
        findings.push(Finding::new(
            "ADR-03",
            Severity::Warning,
            obs,
            format!(
                "{} cannot be resolved over IPv6 alone: no nameserver of {} answers over IPv6",
                walk.name, failure.zone
            ),
            Evidence::Ipv6WalkFailed {
                walked: walk.name.clone(),
                zone: failure.zone.clone(),
                detail: failure.detail.clone(),
                path: walk.path.iter().map(|s| s.to_zone.clone()).collect(),
            },
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testkit::*;
    use crate::observe::{Ipv6Walk, SpecialUse, WalkFailure};

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.check_id.as_str()).collect()
    }

    #[test]
    fn a_dual_stack_host_is_clean() {
        assert!(check(&healthy()).is_empty());
    }

    #[test]
    fn no_aaaa_record_is_adr_01() {
        let mut obs = healthy();
        obs.lookup.aaaa = family(LookupStatus::Nodata, &[]);
        let findings = check(&obs);
        assert_eq!(ids(&findings), ["ADR-01"]);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].name, "www.example.org.");
    }

    #[test]
    fn a_failed_aaaa_lookup_is_not_adr_01() {
        let mut obs = healthy();
        obs.lookup.aaaa = family(LookupStatus::Failed, &[]);
        assert!(check(&obs).is_empty());
        // Nor is a host with no address at all.
        obs.lookup.a = family(LookupStatus::Nodata, &[]);
        obs.lookup.aaaa = family(LookupStatus::Nodata, &[]);
        assert!(check(&obs).is_empty());
    }

    #[test]
    fn unusable_aaaa_records_are_adr_02() {
        let mut obs = healthy();
        obs.lookup.aaaa = family(
            LookupStatus::Answer,
            &[
                "2001:db8:6::1",
                "::ffff:192.0.2.1",
                "fd00::1",
                "::1",
                "2002:c000:201::1",
            ],
        );
        let findings = check(&obs);
        // The first is from a documentation range, like the test's IPv4 one.
        assert_eq!(ids(&findings), ["ADR-02"; 5]);
        let reasons: Vec<SpecialUse> = findings
            .iter()
            .map(|f| match &f.evidence {
                Evidence::UnusableAaaa { reason, .. } => *reason,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            reasons,
            [
                SpecialUse::Documentation,
                SpecialUse::Ipv4Mapped,
                SpecialUse::Private,
                SpecialUse::Loopback,
                SpecialUse::RetiredTransition
            ]
        );
        assert!(findings[1].summary.contains("IPv4-mapped"));
    }

    #[test]
    fn a_name_from_the_system_resolver_may_be_local() {
        let mut obs = healthy();
        obs.lookup.source = LookupSource::System;
        obs.lookup.aaaa = family(LookupStatus::Answer, &["::1"]);
        assert!(check(&obs).is_empty());
    }

    #[test]
    fn a_zone_without_ipv6_nameservers_is_adr_03() {
        let mut obs = public();
        let failed = |name: &str| Ipv6Walk {
            name: name.to_string(),
            path: vec![],
            failed_at: Some(WalkFailure {
                zone: "example.org.".to_string(),
                detail: "none of its nameservers has an IPv6 address".to_string(),
            }),
        };
        obs.ipv6_walks = vec![failed("www.example.org."), failed("edge.example.org.")];
        let findings = check(&obs);
        // Two walks that stop at the same zone are one finding.
        assert_eq!(ids(&findings), ["ADR-03"]);
        assert!(
            findings[0]
                .summary
                .contains("no nameserver of example.org.")
        );
    }
}
