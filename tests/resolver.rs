//! The resolver, run offline against hand-built worlds.

mod common;

use common::*;
use v6blick::observe::{LookupSource, LookupStatus, QType, Vantage};
use v6blick::resolve::{detect_vantage, lookup_host, normalise_host, walk_ipv6_only};

const BOTH: Vantage = Vantage {
    ipv4: true,
    ipv6: true,
};

const A4: &str = "192.0.2.10";
const A6: &str = "2001:db8::10";

/// `www.dual.example.` has both kinds of address, and so have the
/// nameservers of its zone.
fn dual_world() -> World {
    let mut w = World::new();
    let glue = [
        ("ns1.dual.example.", "192.0.2.53"),
        ("ns1.dual.example.", "2001:db8::53"),
    ];
    for (qtype, ip) in [(QType::A, A4), (QType::Aaaa, A6)] {
        w.delegate("www.dual.example.", qtype, "dual.example.", &glue);
        for server in ["192.0.2.53", "2001:db8::53"] {
            w.answer(
                server,
                "www.dual.example.",
                qtype,
                &[addr("www.dual.example.", ip)],
            );
        }
    }
    w
}

/// `www.old.example.` has both kinds of address, but the only nameserver
/// of its zone has an IPv4 address and nothing else.
fn v4_only_nameserver_world() -> World {
    let mut w = World::new();
    let glue = [("ns1.old.example.", "192.0.2.54")];
    for (qtype, ip) in [(QType::A, A4), (QType::Aaaa, A6)] {
        w.delegate("www.old.example.", qtype, "old.example.", &glue);
        w.answer(
            "192.0.2.54",
            "www.old.example.",
            qtype,
            &[addr("www.old.example.", ip)],
        );
    }
    w
}

#[tokio::test]
async fn both_families_are_seen_to_work() {
    let vantage = detect_vantage(&World::new().client()).await;
    assert_eq!(vantage, BOTH);
    // With no recorded answers nothing works.
    let none = detect_vantage(&World::default().client()).await;
    assert!(!none.ipv4 && !none.ipv6);
}

#[tokio::test]
async fn finds_the_addresses_of_both_families() {
    let lookup = lookup_host(dual_world().client(), BOTH, "www.dual.example.").await;
    assert_eq!(lookup.source, LookupSource::Root);
    assert!(lookup.cname_chain.is_empty());
    assert_eq!(lookup.a.status, LookupStatus::Answer);
    assert_eq!(
        lookup.a.addresses,
        [A4.parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(
        lookup.aaaa.addresses,
        [A6.parse::<std::net::IpAddr>().unwrap()]
    );
}

#[tokio::test]
async fn a_host_without_aaaa_is_nodata_not_an_error() {
    let mut w = dual_world();
    for server in ["192.0.2.53", "2001:db8::53"] {
        w.nodata(server, "www.dual.example.", QType::Aaaa, "dual.example.");
    }
    let lookup = lookup_host(w.client(), BOTH, "www.dual.example.").await;
    assert_eq!(lookup.a.status, LookupStatus::Answer);
    assert_eq!(lookup.aaaa.status, LookupStatus::Nodata);
    assert!(lookup.aaaa.addresses.is_empty() && lookup.aaaa.error.is_none());
}

#[tokio::test]
async fn a_name_that_does_not_exist_is_nxdomain() {
    let mut w = dual_world();
    for qtype in [QType::A, QType::Aaaa] {
        w.delegate(
            "gone.dual.example.",
            qtype,
            "dual.example.",
            &[
                ("ns1.dual.example.", "192.0.2.53"),
                ("ns1.dual.example.", "2001:db8::53"),
            ],
        );
        for server in ["192.0.2.53", "2001:db8::53"] {
            w.nxdomain(server, "gone.dual.example.", qtype, "dual.example.");
        }
    }
    let lookup = lookup_host(w.client(), BOTH, "gone.dual.example.").await;
    assert_eq!(lookup.a.status, LookupStatus::Nxdomain);
    assert_eq!(lookup.aaaa.status, LookupStatus::Nxdomain);
}

#[tokio::test]
async fn follows_an_alias_into_another_zone() {
    let mut w = dual_world();
    let glue = [("ns1.shop.example.", "192.0.2.55")];
    for qtype in [QType::A, QType::Aaaa] {
        w.delegate("www.shop.example.", qtype, "shop.example.", &glue);
        // The alias points out of the zone, so the answer holds no address.
        w.answer(
            "192.0.2.55",
            "www.shop.example.",
            qtype,
            &[cname("www.shop.example.", "www.dual.example.")],
        );
    }
    let lookup = lookup_host(w.client(), BOTH, "www.shop.example.").await;
    assert_eq!(lookup.cname_chain, ["www.dual.example."]);
    assert_eq!(lookup.canonical_name(), "www.dual.example.");
    assert_eq!(lookup.a.addresses.len(), 1);
    assert_eq!(lookup.aaaa.addresses.len(), 1);
}

#[tokio::test]
async fn an_alias_loop_ends_as_a_failure() {
    let mut w = World::new();
    let glue = [("ns1.loop.example.", "192.0.2.56")];
    for qtype in [QType::A, QType::Aaaa] {
        for (from, to) in [
            ("a.loop.example.", "b.loop.example."),
            ("b.loop.example.", "a.loop.example."),
        ] {
            w.delegate(from, qtype, "loop.example.", &glue);
            // Each answer holds one alias only, as from separate zones.
            w.answer("192.0.2.56", from, qtype, &[cname(from, to)]);
        }
    }
    let lookup = lookup_host(w.client(), BOTH, "a.loop.example.").await;
    assert_eq!(lookup.a.status, LookupStatus::Failed);
    assert_eq!(lookup.a.error.as_deref(), Some("the aliases form a loop"));
}

#[tokio::test]
async fn the_ipv6_walk_reaches_a_zone_with_ipv6_nameservers() {
    let walk = walk_ipv6_only(dual_world().client(), "www.dual.example.").await;
    assert!(walk.failed_at.is_none(), "{:?}", walk.failed_at);
    let zones: Vec<&str> = walk.path.iter().map(|s| s.to_zone.as_str()).collect();
    assert_eq!(zones, ["example.", "dual.example."]);
    // Every server on the way was asked over IPv6.
    assert!(walk.path.iter().all(|s| s.server_address.is_ipv6()));
}

#[tokio::test]
async fn the_ipv6_walk_names_the_zone_it_cannot_enter() {
    let w = v4_only_nameserver_world();
    // With both families the host resolves, so nothing looks wrong.
    let lookup = lookup_host(w.client(), BOTH, "www.old.example.").await;
    assert_eq!(lookup.aaaa.status, LookupStatus::Answer);

    let walk = walk_ipv6_only(w.client(), "www.old.example.").await;
    let failure = walk.failed_at.expect("the walk must fail");
    assert_eq!(failure.zone, "old.example.");
    assert_eq!(
        failure.detail,
        "none of its nameservers has an IPv6 address"
    );
    // The path up to the failing zone is kept.
    let zones: Vec<&str> = walk.path.iter().map(|s| s.to_zone.as_str()).collect();
    assert_eq!(zones, ["example.", "old.example."]);
}

#[tokio::test]
async fn the_ipv6_walk_reports_a_nameserver_that_is_silent_over_ipv6() {
    // The nameserver has an IPv6 address in the glue, and nothing answers
    // there: no exchange is recorded for it.
    let mut w = World::new();
    let glue = [
        ("ns1.quiet.example.", "192.0.2.57"),
        ("ns1.quiet.example.", "2001:db8::57"),
    ];
    w.delegate("www.quiet.example.", QType::Aaaa, "quiet.example.", &glue);
    let walk = walk_ipv6_only(w.client(), "www.quiet.example.").await;
    let failure = walk.failed_at.expect("the walk must fail");
    assert_eq!(failure.zone, "quiet.example.");
    assert!(
        failure.detail.contains("2001:db8::57"),
        "{}",
        failure.detail
    );
}

#[test]
fn host_names_are_normalised() {
    assert_eq!(normalise_host("Example.ORG").unwrap(), "example.org.");
    assert_eq!(
        normalise_host(" www.example.org. ").unwrap(),
        "www.example.org."
    );
    assert!(normalise_host("").is_err());
    assert!(normalise_host(".").is_err());
    assert!(normalise_host("a..b").is_err());
}
