//! Hand-built DNS worlds for offline tests, after zoneblick's
//! `tests/common/mod.rs`.
//!
//! A [`World`] is a set of canned responses, built with real DNS messages and
//! turned into a [`Fixture`] that the replay client answers from. Zones live
//! under `example.`, which is reserved (RFC 2606), and servers use the
//! documentation address ranges (RFC 5737, RFC 3849).

#![allow(dead_code)]

use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::op::{Edns, Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, NS, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use v6blick::observe::{QType, Transport};
use v6blick::resolve::{Client, Exchange, Fixture, QuerySpec, RawOutcome};

pub const ROOT_V4: &str = "198.41.0.4";
pub const ROOT_V6: &str = "2001:503:ba3e::2:30";
pub const TLD_V4: &str = "192.0.2.1";
pub const TLD_V6: &str = "2001:db8::1";
pub const STARTED_AT: u64 = 1_700_000_000;

/// The three ways a query can be sent: (transport, edns).
const VARIANTS: [(Transport, bool); 3] = [
    (Transport::Udp, true),
    (Transport::Udp, false),
    (Transport::Tcp, true),
];

pub fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

pub fn ns(owner: &str, target: &str) -> Record {
    Record::from_rdata(name(owner), 3600, RData::NS(NS(name(target))))
}

pub fn addr(owner: &str, ip: &str) -> Record {
    let rdata = match ip.parse::<IpAddr>().unwrap() {
        IpAddr::V4(v4) => RData::A(A(v4)),
        IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
    };
    Record::from_rdata(name(owner), 3600, rdata)
}

pub fn cname(owner: &str, target: &str) -> Record {
    Record::from_rdata(name(owner), 3600, RData::CNAME(CNAME(name(target))))
}

pub fn soa(owner: &str) -> Record {
    // The root's own name is a lone dot, which nothing can be put before.
    let zone = if owner == "." { "" } else { owner };
    let rdata = SOA::new(
        name(&format!("ns1.{zone}")),
        name(&format!("hostmaster.{zone}")),
        1,
        7200,
        3600,
        1209600,
        3600,
    );
    Record::from_rdata(name(owner), 3600, RData::SOA(rdata))
}

fn record_type(qtype: QType) -> RecordType {
    match qtype {
        QType::Ns => RecordType::NS,
        QType::A => RecordType::A,
        QType::Aaaa => RecordType::AAAA,
        QType::Cname => RecordType::CNAME,
    }
}

#[derive(Default)]
pub struct World {
    exchanges: Vec<Exchange>,
}

impl World {
    /// A world whose root answers over IPv4 and IPv6, and delegates
    /// `example.` to one server that has both kinds of address.
    pub fn new() -> Self {
        let mut w = World::default();
        for root in [ROOT_V4, ROOT_V6] {
            w.answer(root, ".", QType::Ns, &[ns(".", "a.root-servers.net.")]);
            // As the real root does: there is no `localhost.` in the
            // public DNS. Tests that run a check against a local server
            // get the name from the system resolver after this answer.
            for qtype in [QType::A, QType::Aaaa] {
                w.nxdomain(root, "localhost.", qtype, ".");
            }
        }
        w
    }

    /// Set the raw outcome for one exact query. A later call replaces an
    /// earlier one for the same query.
    pub fn outcome(
        &mut self,
        server: &str,
        transport: Transport,
        edns: bool,
        qname: &str,
        qtype: QType,
        outcome: RawOutcome,
    ) {
        let query = QuerySpec {
            server: server.parse().unwrap(),
            transport,
            qname: qname.to_string(),
            qtype,
            edns,
        };
        self.exchanges.retain(|e| e.query != query);
        self.exchanges.push(Exchange { query, outcome });
    }

    /// Answer a query the same way however it is sent.
    pub fn reply(&mut self, server: &str, qname: &str, qtype: QType, build: impl Fn(&mut Message)) {
        for (transport, edns) in VARIANTS {
            let mut msg = Message::response(0, OpCode::Query);
            msg.add_query(Query::query(name(qname), record_type(qtype)));
            if edns {
                let mut opt = Edns::new();
                opt.set_max_payload(1232);
                msg.set_edns(opt);
            }
            build(&mut msg);
            let wire = msg.to_vec().unwrap();
            self.outcome(
                server,
                transport,
                edns,
                qname,
                qtype,
                RawOutcome::Response { wire },
            );
        }
    }

    /// An authoritative answer.
    pub fn answer(&mut self, server: &str, qname: &str, qtype: QType, answers: &[Record]) {
        self.reply(server, qname, qtype, |m| {
            m.metadata.authoritative = true;
            m.add_answers(answers.to_vec());
        });
    }

    /// An authoritative "no such data" answer from `zone`.
    pub fn nodata(&mut self, server: &str, qname: &str, qtype: QType, zone: &str) {
        self.reply(server, qname, qtype, |m| {
            m.metadata.authoritative = true;
            m.add_authority(soa(zone));
        });
    }

    /// An authoritative NXDOMAIN from `zone`.
    pub fn nxdomain(&mut self, server: &str, qname: &str, qtype: QType, zone: &str) {
        self.reply(server, qname, qtype, |m| {
            m.metadata.authoritative = true;
            m.metadata.response_code = ResponseCode::NXDomain;
            m.add_authority(soa(zone));
        });
    }

    /// A referral: NS records in the authority section, glue in additional.
    pub fn referral(
        &mut self,
        server: &str,
        qname: &str,
        qtype: QType,
        ns_records: &[Record],
        glue: &[Record],
    ) {
        self.reply(server, qname, qtype, |m| {
            m.add_authorities(ns_records.to_vec());
            m.add_additionals(glue.to_vec());
        });
    }

    /// For one question: both root servers delegate `example.`, and both
    /// addresses of its server delegate `zone` to these nameservers.
    /// `glue` is (nameserver, address) pairs.
    pub fn delegate(&mut self, qname: &str, qtype: QType, zone: &str, glue: &[(&str, &str)]) {
        for root in [ROOT_V4, ROOT_V6] {
            self.referral(
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
        let mut names: Vec<&str> = glue.iter().map(|(n, _)| *n).collect();
        names.dedup();
        let ns_records: Vec<Record> = names.iter().map(|n| ns(zone, n)).collect();
        let glue: Vec<Record> = glue.iter().map(|(n, a)| addr(n, a)).collect();
        for tld in [TLD_V4, TLD_V6] {
            self.referral(tld, qname, qtype, &ns_records, &glue);
        }
    }

    pub fn fixture(&self, name: &str) -> Fixture {
        Fixture {
            version: Fixture::VERSION,
            name: name.to_string(),
            started_at_unix: STARTED_AT,
            exchanges: self.exchanges.clone(),
        }
    }

    pub fn client(&self) -> Arc<Client> {
        Arc::new(Client::replay(&self.fixture("test.")))
    }
}
pub mod server;
