//! Red team: the resolver against hostile zones, and the two address
//! classifiers. Offline: every DNS answer comes from a hand-built world.
//!
//! Every test asserts the SAFE behaviour. The ones marked `DEFECT` fail
//! at commit 595371b; the ones marked `HELD` pass.

mod common;

use std::net::IpAddr;
use std::sync::Arc;

use common::*;
use v6blick::observe::{LookupStatus, QType, Vantage, special_use};
use v6blick::probe::refusal;
use v6blick::resolve::transport::never_contacted;
use v6blick::resolve::{Client, Exchange, Fixture, RawOutcome, lookup_host, walk_ipv6_only};

const BOTH: Vantage = Vantage {
    ipv4: true,
    ipv6: true,
};

fn recording(world: &World) -> Arc<Client> {
    Arc::new(Client::replay(&world.fixture("test.")).with_recording())
}

/// Both root servers refer `qname` to the server of `example.`.
fn from_root(w: &mut World, qname: &str, qtype: QType) {
    for root in [ROOT_V4, ROOT_V6] {
        w.referral(
            root,
            qname,
            qtype,
            &[ns("example.", "ns.nic.example.")],
            &[
                addr("ns.nic.example.", TLD_V4),
                addr("ns.nic.example.", TLD_V6),
            ],
        );
    }
}

// ---------------------------------------------------------------- DEFECT

/// DEFECT (medium, reaching into the user's network). A zone names its
/// own nameservers and their addresses. `never_contacted` stops loopback
/// and link-local and lets every private range through, so a hostile
/// zone (the checked name's, an alias target's, or one a redirect leads
/// to) makes v6blick send DNS queries, over UDP and over TCP, to port 53
/// of any host inside the network it runs in, without `--allow-private`.
/// The answer or the kind of failure ("timeout", "REFUSED", "connection
/// refused") is printed in the lookup error and in the IPv6 walk's
/// detail, which tells whoever reads the CI log what is listening there.
///
/// The prober's own rule (`refusal`) is the stricter one, and is the one
/// the README promises: "Private, loopback and link-local destinations
/// are not contacted unless `--allow-private` is given."
#[test]
fn fixed_dns_queries_are_not_sent_to_private_addresses() {
    let mut reachable = Vec::new();
    for address in [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "fd00::1",
        "fc00::53",
        "::ffff:10.0.0.1",
        "::ffff:192.168.1.1",
        // Everything the prober refuses always, the resolver should too.
        "0.1.2.3",
        "240.0.0.1",
        "192.0.2.1",
        "198.18.0.1",
        "::127.0.0.1",
        "::10.0.0.1",
        "64:ff9b::7f00:1",
        "64:ff9b::a00:1",
        "2002:7f00:1::1",
        "2002:a00:1::1",
        "fec0::1",
    ] {
        let ip: IpAddr = address.parse().unwrap();
        assert!(
            refusal(ip, false).is_some(),
            "the prober would contact {address}"
        );
        if never_contacted(ip).is_none() {
            reachable.push(address);
        }
    }
    assert!(
        reachable.is_empty(),
        "the resolver sends DNS queries to: {reachable:?}"
    );
}

/// DEFECT, the same seen from the resolver: a referral whose glue is a
/// private address is followed, and the client is handed a query for
/// 10.0.0.53. (The replay client has no address rule at all; if the fix
/// stays inside the live client, this test cannot pass and should be
/// replaced by one at that level.)
#[tokio::test]
async fn fixed_glue_in_a_private_range_is_not_followed() {
    let mut w = World::new();
    let glue = [("ns1.evil.example.", "10.0.0.53")];
    for qtype in [QType::A, QType::Aaaa] {
        w.delegate("www.evil.example.", qtype, "evil.example.", &glue);
    }
    w.answer(
        "10.0.0.53",
        "www.evil.example.",
        QType::A,
        &[addr("www.evil.example.", "192.0.2.10")],
    );
    let client = recording(&w);
    let lookup = lookup_host(client.clone(), BOTH, "www.evil.example.").await;
    let asked: Vec<String> = client
        .take_recording()
        .iter()
        .map(|e| e.query.server.to_string())
        .filter(|s| s.starts_with("10."))
        .collect();
    assert!(
        asked.is_empty(),
        "queries went to {asked:?}; the lookup came back with {:?}",
        lookup.a.addresses
    );
}

/// DEFECT (low). Ranges `special_use` does not know. None of them is
/// loopback or RFC 1918, so the effect is on ADR-02 (an unusable AAAA
/// record that gets no finding) and, for the two NAT64 ones, on what a
/// network with a translator would carry to an IPv4 host.
#[test]
fn fixed_special_ranges_that_are_missed() {
    let mut missed = Vec::new();
    for (address, what) in [
        ("192.0.0.8", "192.0.0.0/24, IETF protocol assignments"),
        ("192.0.0.170", "192.0.0.0/24, NAT64 discovery"),
        (
            "192.88.99.1",
            "192.88.99.0/24, 6to4 relay anycast (retired)",
        ),
        (
            "64:ff9b:1::a00:1",
            "64:ff9b:1::/48, local-use NAT64 (RFC 8215), here 10.0.0.1",
        ),
        (
            "64:ff9b:1::7f00:1",
            "64:ff9b:1::/48, local-use NAT64, here 127.0.0.1",
        ),
        ("2001:2::1", "2001:2::/48, benchmarking"),
        ("2001:20::1", "2001:20::/28, ORCHIDv2"),
        ("3fff::1", "3fff::/20, documentation (RFC 9637)"),
        ("5f00::1", "5f00::/16, segment routing SIDs"),
        ("4000::1", "outside 2000::/3: not global unicast"),
        ("1::1", "outside 2000::/3: not global unicast"),
        ("::1:0:0:1", "outside 2000::/3: not global unicast"),
    ] {
        if special_use(address.parse().unwrap()).is_none() {
            missed.push(format!("{address} ({what})"));
        }
    }
    assert!(
        missed.is_empty(),
        "treated as ordinary public addresses:\n  {}",
        missed.join("\n  ")
    );
}

// ------------------------------------------------------------------ HELD

/// HELD. The ranges that matter for reaching into a network are all
/// refused by the prober: every block of loopback, RFC 1918, CGNAT,
/// link-local (with the cloud metadata address), unique-local, and each
/// way of writing an IPv4 address inside an IPv6 one.
#[test]
fn held_the_prober_refuses_every_local_range() {
    for address in [
        "127.0.0.1",
        "127.255.255.254",
        "10.0.0.0",
        "10.255.255.255",
        "172.16.0.0",
        "172.31.255.255",
        "192.168.0.0",
        "192.168.255.255",
        "100.64.0.0",
        "100.127.255.255",
        "169.254.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "0.255.255.255",
        "224.0.0.251",
        "239.255.255.250",
        "255.255.255.255",
        "::1",
        "::",
        "fc00::1",
        "fdff:ffff::1",
        "fe80::1",
        "febf::1",
        "fec0::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
        "::127.0.0.1",
        "::169.254.169.254",
        "64:ff9b::7f00:1",
        "64:ff9b::a9fe:a9fe",
        "2002:7f00:1::",
        "2002:a9fe:a9fe::1",
        "2001:0:7f00:1::1",
    ] {
        assert!(
            refusal(address.parse().unwrap(), false).is_some(),
            "{address}"
        );
    }
    // The boundaries on the public side stay open.
    for address in [
        "9.255.255.255",
        "11.0.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.167.255.255",
        "192.169.0.0",
        "100.63.255.255",
        "100.128.0.0",
        "169.253.255.255",
        "169.255.0.0",
        "126.255.255.255",
        "128.0.0.0",
        "2600::1",
        "2a00::1",
    ] {
        assert!(
            refusal(address.parse().unwrap(), false).is_none(),
            "{address}"
        );
    }
}

/// HELD. Aliases that loop between two zones, an alias to itself and a
/// chain of thirty aliases all end as a failed lookup, after a bounded
/// number of queries.
#[tokio::test]
async fn held_alias_loops_and_long_chains_end() {
    // a -> b -> a, each in its own zone.
    let mut w = World::new();
    for (name, zone, server, to) in [
        (
            "a.one.example.",
            "one.example.",
            "192.0.2.61",
            "b.two.example.",
        ),
        (
            "b.two.example.",
            "two.example.",
            "192.0.2.62",
            "a.one.example.",
        ),
    ] {
        let ns_name = format!("ns.{zone}");
        for qtype in [QType::A, QType::Aaaa] {
            w.delegate(name, qtype, zone, &[(ns_name.as_str(), server)]);
            w.answer(server, name, qtype, &[cname(name, to)]);
        }
    }
    let client = recording(&w);
    let lookup = lookup_host(client.clone(), BOTH, "a.one.example.").await;
    assert_eq!(lookup.a.status, LookupStatus::Failed);
    assert_eq!(lookup.a.error.as_deref(), Some("the aliases form a loop"));
    assert!(client.queries_sent() < 40, "{}", client.queries_sent());

    // n0 -> n1 -> ... -> n30, one answer each.
    let mut w = World::new();
    let glue = [("ns.chain.example.", "192.0.2.63")];
    for i in 0..30 {
        let (name, to) = (
            format!("n{i}.chain.example."),
            format!("n{}.chain.example.", i + 1),
        );
        for qtype in [QType::A, QType::Aaaa] {
            w.delegate(&name, qtype, "chain.example.", &glue);
            w.answer("192.0.2.63", &name, qtype, &[cname(&name, &to)]);
        }
    }
    let client = recording(&w);
    let lookup = lookup_host(client.clone(), BOTH, "n0.chain.example.").await;
    assert_eq!(lookup.a.status, LookupStatus::Failed);
    assert_eq!(lookup.a.error.as_deref(), Some("too many aliases"));
    assert!(lookup.cname_chain.len() <= 9, "{:?}", lookup.cname_chain);
    assert!(client.queries_sent() < 80, "{}", client.queries_sent());

    // One answer that holds a chain of thirty and a loop.
    let mut w = World::new();
    let mut records: Vec<_> = (0..30)
        .map(|i| {
            cname(
                &format!("m{i}.chain.example."),
                &format!("m{}.chain.example.", (i + 1) % 30),
            )
        })
        .collect();
    records.push(cname("m0.chain.example.", "m0.chain.example."));
    for qtype in [QType::A, QType::Aaaa] {
        w.delegate("m0.chain.example.", qtype, "chain.example.", &glue);
        w.answer("192.0.2.63", "m0.chain.example.", qtype, &records);
    }
    let client = recording(&w);
    let lookup = lookup_host(client.clone(), BOTH, "m0.chain.example.").await;
    assert!(lookup.a.addresses.is_empty());
    assert!(client.queries_sent() < 80, "{}", client.queries_sent());
}

/// HELD. Two zones whose only nameservers are named in each other, with
/// no glue, and a zone with fifty nameserver names that do not resolve:
/// the lookup and the IPv6 walk fail after a bounded number of queries.
#[tokio::test]
async fn held_glueless_delegations_that_point_at_each_other_end() {
    let mut w = World::new();
    let cuts = [
        ("www.one.example.", "one.example.", "ns.two.example."),
        ("ns.one.example.", "one.example.", "ns.two.example."),
        ("ns.two.example.", "two.example.", "ns.one.example."),
    ];
    for (qname, zone, ns_name) in cuts {
        for qtype in [QType::A, QType::Aaaa] {
            from_root(&mut w, qname, qtype);
            for tld in [TLD_V4, TLD_V6] {
                w.referral(tld, qname, qtype, &[ns(zone, ns_name)], &[]);
            }
        }
    }
    let client = recording(&w);
    let lookup = lookup_host(client.clone(), BOTH, "www.one.example.").await;
    assert_eq!(lookup.a.status, LookupStatus::Failed);
    let walk = walk_ipv6_only(client.clone(), "www.one.example.").await;
    assert!(walk.failed_at.is_some());
    assert!(client.queries_sent() < 100, "{}", client.queries_sent());

    // Fifty nameserver names, none with glue, none of which exists.
    let mut w = World::new();
    let names: Vec<String> = (0..50).map(|i| format!("ns{i}.nowhere.example.")).collect();
    let records: Vec<_> = names.iter().map(|n| ns("many.example.", n)).collect();
    for qtype in [QType::A, QType::Aaaa] {
        from_root(&mut w, "www.many.example.", qtype);
        for tld in [TLD_V4, TLD_V6] {
            w.referral(tld, "www.many.example.", qtype, &records, &[]);
        }
        for name in &names {
            from_root(&mut w, name, qtype);
            for tld in [TLD_V4, TLD_V6] {
                w.nxdomain(tld, name, qtype, "example.");
            }
        }
    }
    let client = recording(&w);
    let lookup = lookup_host(client.clone(), BOTH, "www.many.example.").await;
    assert_eq!(lookup.a.status, LookupStatus::Failed);
    assert!(client.queries_sent() < 100, "{}", client.queries_sent());
}

/// HELD. A referral that points up, sideways or at the zone itself is
/// not followed, so a zone cannot take over names outside itself or keep
/// the walk going round.
#[tokio::test]
async fn held_referrals_only_lead_downwards() {
    for (cut, ns_name) in [
        ("example.", "ns.evil.example."),
        (".", "ns.evil.example."),
        ("evil.example.", "ns.evil.example."),
        ("bank.example.", "ns.evil.example."),
        ("com.", "ns.evil.example."),
    ] {
        let mut w = World::new();
        let glue = [("ns.evil.example.", "192.0.2.66")];
        for qtype in [QType::A, QType::Aaaa] {
            w.delegate("www.evil.example.", qtype, "evil.example.", &glue);
            w.referral(
                "192.0.2.66",
                "www.evil.example.",
                qtype,
                &[ns(cut, ns_name)],
                &[addr("ns.evil.example.", "192.0.2.66")],
            );
        }
        let client = recording(&w);
        let lookup = lookup_host(client.clone(), BOTH, "www.evil.example.").await;
        assert_eq!(lookup.a.status, LookupStatus::Failed, "{cut}");
        assert!(
            client.queries_sent() < 20,
            "{cut}: {}",
            client.queries_sent()
        );
    }
}

/// HELD. Damaged DNS responses never panic the resolver: every recorded
/// answer of a small world, with random bytes changed, cut off or
/// inserted, replayed through a lookup and an IPv6 walk.
#[tokio::test]
async fn held_fuzz_dns_responses() {
    let mut w = World::new();
    let glue = [
        ("ns1.dual.example.", "192.0.2.53"),
        ("ns1.dual.example.", "2001:db8::53"),
    ];
    for (qtype, ip) in [(QType::A, "192.0.2.10"), (QType::Aaaa, "2001:db8::10")] {
        w.delegate("www.dual.example.", qtype, "dual.example.", &glue);
        for server in ["192.0.2.53", "2001:db8::53"] {
            w.answer(
                server,
                "www.dual.example.",
                qtype,
                &[
                    cname("www.dual.example.", "host.dual.example."),
                    addr("host.dual.example.", ip),
                ],
            );
        }
    }
    let base = w.fixture("test.");
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..4_000 {
        let exchanges: Vec<Exchange> = base
            .exchanges
            .iter()
            .map(|e| {
                let mut e = e.clone();
                if let RawOutcome::Response { wire } = &mut e.outcome {
                    for _ in 0..(next() % 4) {
                        let at = (next() % wire.len().max(1) as u64) as usize;
                        match next() % 4 {
                            0 if at < wire.len() => wire[at] = next() as u8,
                            1 => wire.truncate(at),
                            2 if at < wire.len() => wire[at] = 0xc0,
                            _ => wire.insert(at.min(wire.len()), next() as u8),
                        }
                    }
                }
                e
            })
            .collect();
        let fixture = Fixture {
            exchanges,
            ..base.clone()
        };
        let client = Arc::new(Client::replay(&fixture));
        let lookup = lookup_host(client.clone(), BOTH, "www.dual.example.").await;
        let walk = walk_ipv6_only(client.clone(), "www.dual.example.").await;
        // Whatever came back is printable.
        let text = format!("{lookup:?}{walk:?}");
        assert!(!text.chars().any(|c| c.is_control()), "{text:?}");
        assert!(client.queries_sent() < 200);
    }
}

/// DEFECT (low, needs `--allow-private`). The operating system's resolver
/// is documented as the fallback "for a name the public DNS does not
/// know". It is in fact asked whenever the lookup from the root gives no
/// address for any reason: a zone that exists and whose servers do not
/// answer, a SERVFAIL, an alias loop, or the query budget running out.
/// A zone can therefore choose to fail for v6blick's own queries and
/// have the name looked up by the user's recursive resolver instead
/// (search domains, hosts file and split-horizon answers included); the
/// run is then marked `system`, and the IPv6 walk and ADR-02 are skipped.
/// The same holds for every host a redirect names.
///
/// Here the root delegates `localhost.` to a server that never answers:
/// the public DNS knows the name, the lookup fails, and the system
/// resolver supplies 127.0.0.1 anyway.
#[tokio::test]
async fn fixed_the_system_resolver_is_only_asked_after_a_definite_no() {
    use v6blick::observe::LookupSource;
    let mut w = World::new();
    for qtype in [QType::A, QType::Aaaa] {
        for root in [ROOT_V4, ROOT_V6] {
            w.referral(
                root,
                "localhost.",
                qtype,
                &[ns("localhost.", "ns.broken.example.")],
                &[addr("ns.broken.example.", "192.0.2.99")],
            );
        }
        // 192.0.2.99 has no recorded answer: the zone's server is down.
    }
    let config = v6blick::probe::ProbeConfig {
        allow_private: true,
        connect_timeout: std::time::Duration::from_secs(1),
        ..Default::default()
    };
    // Port 1: nothing listens there, so the probes end at once.
    let outcome = v6blick::cli::observe("http://localhost:1/", w.client(), config).await;
    match outcome {
        Err(e) => assert!(e.to_string().contains("could not be resolved"), "{e}"),
        Ok(obs) => panic!(
            "the lookup from the root failed and the answer came from {:?}: {:?}",
            obs.lookup.source,
            (obs.lookup.source == LookupSource::System).then_some(&obs.lookup.a.addresses)
        ),
    }
}
