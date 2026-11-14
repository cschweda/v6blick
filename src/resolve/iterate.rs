//! Copied from zoneblick (`src/resolver/iterate.rs`); see `DECISIONS.md` for
//! the commit and for what was changed.
//!
//! The iterative resolver.
//!
//! Starts at the root hints and follows referrals down, one server at a time.
//! Unlike a normal resolver it keeps the intermediate answers: every referral,
//! the NS set in it and the glue that came with it.
//!
//! Recursion is never requested and no recursive resolver is ever asked.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{Name, RData};

use super::ResolveError;
use super::hints::root_servers;
use super::transport::{Client, QuerySpec, RawOutcome, record_type};
use crate::observe::{
    Glue, QType, ReferralStep, Transport, Vantage, is_ancestor_or_equal, parent_name,
};

/// Upper bound on referrals followed for one name.
const MAX_REFERRALS: usize = 24;
/// Upper bound on nested lookups of nameserver addresses.
const MAX_DEPTH: usize = 4;
/// How many servers of one zone are tried before giving up on it.
const MAX_SERVERS_TRIED: usize = 4;

/// A lowercase, fully qualified form of a name.
pub(crate) fn norm(name: &Name) -> String {
    let mut s = printable(&name.to_ascii().to_ascii_lowercase());
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

/// Make text from the network safe to print and store.
///
/// DNS data is chosen by whoever runs the zone or its nameservers. Control
/// characters (which include the escape character that starts terminal
/// control sequences) and Unicode direction overrides are replaced with a
/// visible escape, so a record cannot rewrite or hide terminal output.
pub(crate) fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        // Direction overrides, and characters that are invisible or
        // break a line without being control characters.
        let direction_override = matches!(
            c,
            '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{2060}'..='\u{2069}'
                | '\u{061c}'
                | '\u{feff}'
                // Added for v6blick: other characters that print as
                // nothing or as a blank that is not a space.
                | '\u{00ad}'
                | '\u{034f}'
                | '\u{115f}'..='\u{1160}'
                | '\u{17b4}'..='\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{ffa0}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{e0000}'..='\u{e0fff}'
        );
        if c.is_control() {
            // DNS presentation style: backslash and three decimal digits.
            out.push_str(&format!("\\{:03}", c as u32));
        } else if direction_override {
            out.push_str(&format!("\\u{{{:04x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// The standard mnemonic for a response code.
pub(crate) fn rcode_name(rcode: ResponseCode) -> String {
    match u16::from(rcode) {
        0 => "NOERROR".to_string(),
        1 => "FORMERR".to_string(),
        2 => "SERVFAIL".to_string(),
        3 => "NXDOMAIN".to_string(),
        4 => "NOTIMP".to_string(),
        5 => "REFUSED".to_string(),
        9 => "NOTAUTH".to_string(),
        16 => "BADVERS".to_string(),
        n => format!("RCODE{n}"),
    }
}

/// Parse a response and check it answers the question that was asked.
pub(crate) fn parse_response(spec: &QuerySpec, wire: &[u8]) -> Result<Message, String> {
    let msg = Message::from_vec(wire).map_err(|e| printable(&e.to_string()))?;
    if msg.metadata.message_type != MessageType::Response {
        return Err("not a response".to_string());
    }
    // Some servers drop the question on errors such as FORMERR; accept
    // that, but an answer without its question could be an answer to
    // anything.
    match msg.queries.first() {
        Some(q) if norm(q.name()) != spec.qname || q.query_type() != record_type(spec.qtype) => {
            return Err("response is for a different question".to_string());
        }
        None if msg.metadata.response_code == hickory_proto::op::ResponseCode::NoError => {
            return Err("response has no question section".to_string());
        }
        _ => {}
    }
    Ok(msg)
}

/// One nameserver of a zone and the addresses known for it.
#[derive(Debug, Clone)]
struct NsEntry {
    name: String,
    addrs: Vec<IpAddr>,
}

/// How a walk ended.
enum Terminal {
    /// A response with records in the answer section.
    Answer(Message),
    NxDomain,
    NoData,
}

struct Walk {
    #[allow(dead_code)]
    steps: Vec<ReferralStep>,
    terminal: Terminal,
}

/// What one usable response from a zone's server means.
enum Reply {
    Terminal(Terminal),
    Referral {
        cut: String,
        ns: Vec<String>,
        glue: Vec<Glue>,
    },
}

/// The result of resolving a hostname to addresses.
#[derive(Debug, Default, Clone)]
pub struct HostResolution {
    pub addresses: Vec<IpAddr>,
    pub cname: Option<String>,
    pub error: Option<String>,
}

/// What one name and type resolved to, from the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    pub name: String,
    pub qtype: QType,
    /// `answer`, `nodata`, `nxdomain` or `failed`.
    pub status: String,
    /// Record data in text form, sorted.
    pub rdata: Vec<String>,
    /// Each alias target found in the answer, in order. The record data
    /// belongs to the last one.
    pub cname_chain: Vec<String>,
    /// For `failed`: why.
    pub error: Option<String>,
}

/// A walk towards a name that keeps what it saw, also when it fails.
#[derive(Debug)]
pub struct Trace {
    /// The referrals that were followed, from the root down.
    pub path: Vec<ReferralStep>,
    /// The zone whose servers could not be asked, and why.
    pub failed: Option<(String, String)>,
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub struct Resolver {
    client: Arc<Client>,
    vantage: Vantage,
    /// Zone cut -> its nameservers, learned from referrals.
    cache: Mutex<HashMap<String, Vec<NsEntry>>>,
    /// Hostnames being resolved right now, to break dependency loops.
    visiting: Mutex<HashSet<String>>,
    /// Added for v6blick's page test, which looks up many hosts in one
    /// run: when set, the servers of a zone are tried starting from a
    /// different one each time, so that the same few servers of a
    /// top-level domain are not asked for every host.
    spread: Option<std::sync::atomic::AtomicUsize>,
}

impl Resolver {
    pub fn new(client: Arc<Client>, vantage: Vantage) -> Self {
        let roots = root_servers()
            .into_iter()
            .map(|(name, addrs)| NsEntry { name, addrs })
            .collect();
        Self {
            client,
            vantage,
            cache: Mutex::new(HashMap::from([(".".to_string(), roots)])),
            visiting: Mutex::new(HashSet::new()),
            spread: None,
        }
    }

    /// Spread queries over the servers of each zone. For runs that
    /// resolve many names. A replayed run keeps the fixed order, so
    /// that it asks what was recorded.
    pub fn spreading(mut self) -> Self {
        self.spread = Some(std::sync::atomic::AtomicUsize::new(0));
        self
    }

    /// Walk from the root towards `name` and record every referral on the
    /// way. A name that does not exist still counts as reached: its zone's
    /// servers answered.
    pub async fn trace(&self, name: &str, qtype: QType) -> Trace {
        let mut path = Vec::new();
        let failed = match self.walk_into(name, qtype, 0, &mut path).await {
            Ok(_) => None,
            Err(ResolveError::ServersFailed { zone, detail }) => Some((zone, detail)),
            Err(other) => Some((name.to_string(), other.to_string())),
        };
        Trace { path, failed }
    }

    /// Resolve a hostname to its addresses, from the root, following CNAMEs.
    pub fn resolve_host(&self, name: String, depth: usize) -> BoxFuture<'_, HostResolution> {
        Box::pin(async move {
            let mut res = HostResolution::default();
            if depth > MAX_DEPTH {
                res.error = Some("nameserver address lookups nested too deeply".to_string());
                return res;
            }
            if !self.visiting.lock().expect("lock").insert(name.clone()) {
                res.error = Some("resolution loop".to_string());
                return res;
            }
            for qtype in [QType::A, QType::Aaaa] {
                match self.walk(&name, qtype, depth).await {
                    Ok(Walk {
                        terminal: Terminal::Answer(msg),
                        ..
                    }) => {
                        let (addrs, target) = follow_answer(&msg, &name);
                        let found = !addrs.is_empty();
                        res.addresses.extend(addrs);
                        if target != name {
                            res.cname.get_or_insert(first_cname(&msg, &name));
                            if !found {
                                // The alias target lives elsewhere; resolve it
                                // for both families and stop.
                                let sub = self.resolve_host(target, depth + 1).await;
                                res.addresses.extend(sub.addresses);
                                res.error = sub.error;
                                break;
                            }
                        }
                    }
                    Ok(Walk {
                        terminal: Terminal::NxDomain,
                        ..
                    }) => {
                        res.error = Some("NXDOMAIN".to_string());
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => res.error = Some(e.to_string()),
                }
            }
            self.visiting.lock().expect("lock").remove(&name);
            res.addresses.sort();
            res.addresses.dedup();
            if !res.addresses.is_empty() {
                res.error = None;
            } else if res.error.is_none() {
                res.error = Some("no address records".to_string());
            }
            res
        })
    }

    /// Resolve one name and type from the root and say what was found.
    /// A CNAME at the name is reported, and followed inside the same answer.
    pub async fn lookup(&self, name: &str, qtype: QType) -> Lookup {
        let mut out = Lookup {
            name: name.to_string(),
            qtype,
            status: "failed".to_string(),
            rdata: Vec::new(),
            cname_chain: Vec::new(),
            error: None,
        };
        match self.walk(name, qtype, 0).await {
            Ok(Walk {
                terminal: Terminal::Answer(msg),
                ..
            }) => {
                let mut owner = name.to_string();
                for _ in 0..8 {
                    let next = msg.answers.iter().find_map(|rec| match &rec.data {
                        RData::CNAME(c) if norm(&rec.name) == owner => Some(norm(&c.0)),
                        _ => None,
                    });
                    match next {
                        Some(next) if next != owner && !out.cname_chain.contains(&next) => {
                            out.cname_chain.push(next.clone());
                            owner = next;
                        }
                        _ => break,
                    }
                }
                let wanted = record_type(qtype);
                out.rdata = msg
                    .answers
                    .iter()
                    .filter(|rec| rec.record_type() == wanted && norm(&rec.name) == owner)
                    .map(|rec| match &rec.data {
                        RData::A(a) => a.0.to_string(),
                        RData::AAAA(a) => a.0.to_string(),
                        other => printable(&other.to_string()),
                    })
                    .collect();
                out.rdata.sort();
                out.rdata.dedup();
                out.status = if out.rdata.is_empty() && out.cname_chain.is_empty() {
                    "nodata"
                } else {
                    "answer"
                }
                .to_string();
            }
            Ok(Walk {
                terminal: Terminal::NxDomain,
                ..
            }) => out.status = "nxdomain".to_string(),
            Ok(Walk {
                terminal: Terminal::NoData,
                ..
            }) => out.status = "nodata".to_string(),
            Err(e) => out.error = Some(e.to_string()),
        }
        out
    }

    /// Follow referrals for `qname` until something other than a referral
    /// comes back.
    async fn walk(&self, qname: &str, qtype: QType, depth: usize) -> Result<Walk, ResolveError> {
        let mut steps = Vec::new();
        let terminal = self.walk_into(qname, qtype, depth, &mut steps).await?;
        Ok(Walk { steps, terminal })
    }

    /// [`Resolver::walk`], adding each referral to `steps` as it is
    /// followed, so that they are kept when the walk fails.
    async fn walk_into(
        &self,
        qname: &str,
        qtype: QType,
        depth: usize,
        steps: &mut Vec<ReferralStep>,
    ) -> Result<Terminal, ResolveError> {
        let (mut zone, mut entries) = self.closest_cached(qname);
        for _ in 0..MAX_REFERRALS {
            let (reply, server_name, server_address) =
                self.ask_zone(&zone, &entries, qname, qtype, depth).await?;
            match reply {
                Reply::Terminal(terminal) => return Ok(terminal),
                Reply::Referral { cut, ns, glue } => {
                    entries = ns
                        .iter()
                        .map(|name| NsEntry {
                            name: name.clone(),
                            addrs: glue
                                .iter()
                                .filter(|g| &g.name == name)
                                .map(|g| g.address)
                                .collect(),
                        })
                        .collect();
                    self.cache
                        .lock()
                        .expect("lock")
                        .insert(cut.clone(), entries.clone());
                    steps.push(ReferralStep {
                        from_zone: zone,
                        to_zone: cut.clone(),
                        server_name: Some(server_name),
                        server_address,
                        ns,
                        glue,
                    });
                    zone = cut;
                }
            }
        }
        Err(ResolveError::TooManyReferrals {
            name: qname.to_string(),
        })
    }

    /// The deepest zone cut already known on the way to `qname`.
    fn closest_cached(&self, qname: &str) -> (String, Vec<NsEntry>) {
        let cache = self.cache.lock().expect("lock");
        let mut name = qname;
        loop {
            if let Some(entries) = cache.get(name) {
                return (name.to_string(), entries.clone());
            }
            // The root is always cached, so this ends.
            name = parent_name(name);
        }
    }

    /// Ask the servers of `zone` in turn until one gives a usable reply.
    async fn ask_zone(
        &self,
        zone: &str,
        entries: &[NsEntry],
        qname: &str,
        qtype: QType,
        depth: usize,
    ) -> Result<(Reply, String, IpAddr), ResolveError> {
        let mut candidates = self.candidates(entries);
        if candidates.is_empty() && depth < MAX_DEPTH {
            // A glueless delegation: resolve nameserver names until one
            // works. Each of them may be glueless in turn, so only the
            // first level tries several names; deeper levels try one.
            let tries = if depth == 0 { 3 } else { 1 };
            for entry in entries.iter().take(tries) {
                let res = self.resolve_host(entry.name.clone(), depth + 1).await;
                if res.addresses.is_empty() {
                    continue;
                }
                let resolved = [NsEntry {
                    name: entry.name.clone(),
                    addrs: res.addresses,
                }];
                candidates = self.candidates(&resolved);
                if !candidates.is_empty() {
                    break;
                }
            }
        }
        if candidates.is_empty() {
            return Err(ResolveError::ServersFailed {
                zone: zone.to_string(),
                detail: match (self.vantage.ipv4, self.vantage.ipv6) {
                    (false, true) => "none of its nameservers has an IPv6 address",
                    (true, false) => "none of its nameservers has an IPv4 address",
                    _ => "no nameserver address could be found",
                }
                .to_string(),
            });
        }
        let mut errors = Vec::new();
        for (name, addr) in candidates.into_iter().take(MAX_SERVERS_TRIED) {
            match self.ask(addr, qname, qtype).await {
                Ok(msg) => match classify(msg, zone, qname) {
                    Ok(reply) => return Ok((reply, name, addr)),
                    Err(why) => errors.push(format!("{addr}: {why}")),
                },
                Err(why) => errors.push(format!("{addr}: {why}")),
            }
        }
        Err(ResolveError::ServersFailed {
            zone: zone.to_string(),
            detail: errors.join("; "),
        })
    }

    /// Addresses to try, reachable families only, IPv4 before IPv6.
    fn candidates(&self, entries: &[NsEntry]) -> Vec<(String, IpAddr)> {
        let mut out: Vec<(String, IpAddr)> = entries
            .iter()
            .flat_map(|e| e.addrs.iter().map(|a| (e.name.clone(), *a)))
            .filter(|(_, a)| self.vantage.can_reach(a))
            .collect();
        out.sort_by_key(|(_, a)| a.is_ipv6());
        if let Some(turn) = &self.spread {
            // Rotate within each family, keeping IPv4 before IPv6.
            let turn = turn.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let split = out
                .iter()
                .position(|(_, a)| a.is_ipv6())
                .unwrap_or(out.len());
            let (v4, v6) = out.split_at_mut(split);
            for group in [v4, v6] {
                if !group.is_empty() {
                    group.rotate_left(turn % group.len());
                }
            }
        }
        out
    }

    /// One question to one server: UDP with EDNS, without EDNS if the server
    /// rejects it, and TCP if the answer is truncated.
    pub(crate) async fn ask(
        &self,
        server: IpAddr,
        qname: &str,
        qtype: QType,
    ) -> Result<Message, String> {
        let mut spec = QuerySpec {
            server,
            transport: Transport::Udp,
            qname: qname.to_string(),
            qtype,
            edns: true,
        };
        let mut msg = self.send(&spec).await?;
        if msg.metadata.response_code == ResponseCode::FormErr {
            spec.edns = false;
            msg = self.send(&spec).await?;
        }
        if msg.metadata.truncation {
            spec.transport = Transport::Tcp;
            msg = self.send(&spec).await?;
        }
        Ok(msg)
    }

    async fn send(&self, spec: &QuerySpec) -> Result<Message, String> {
        match self.client.exchange(spec).await {
            RawOutcome::Response { wire } => parse_response(spec, &wire),
            RawOutcome::Timeout => Err("timeout".to_string()),
            RawOutcome::NetError { message } => Err(message),
        }
    }
}

/// Decide what a response from a server of `zone` means for `qname`.
/// `Err` means the server is no use and the next one should be tried.
fn classify(msg: Message, zone: &str, qname: &str) -> Result<Reply, String> {
    let rcode = msg.metadata.response_code;
    let aa = msg.metadata.authoritative;
    match rcode {
        ResponseCode::NXDomain if aa => {
            return Ok(Reply::Terminal(Terminal::NxDomain));
        }
        ResponseCode::NoError => {}
        other => return Err(rcode_name(other)),
    }
    if !msg.answers.is_empty() {
        return Ok(Reply::Terminal(Terminal::Answer(msg)));
    }
    let mut ns = Vec::new();
    let mut cut: Option<String> = None;
    for rec in &msg.authorities {
        if let RData::NS(target) = &rec.data {
            let owner = norm(&rec.name);
            if cut.get_or_insert_with(|| owner.clone()) == &owner {
                ns.push(norm(&target.0));
            }
        }
    }
    if let Some(cut) = cut {
        // A real referral points strictly downwards, towards the name asked.
        if cut != zone && is_ancestor_or_equal(zone, &cut) && is_ancestor_or_equal(&cut, qname) {
            ns.sort();
            ns.dedup();
            let mut glue: Vec<Glue> = msg
                .additionals
                .iter()
                .filter_map(|rec| {
                    let address = match &rec.data {
                        RData::A(a) => IpAddr::V4(a.0),
                        RData::AAAA(a) => IpAddr::V6(a.0),
                        _ => return None,
                    };
                    let name = norm(&rec.name);
                    ns.contains(&name).then_some(Glue { name, address })
                })
                .collect();
            glue.sort();
            glue.dedup();
            return Ok(Reply::Referral { cut, ns, glue });
        }
    }
    if aa {
        return Ok(Reply::Terminal(Terminal::NoData));
    }
    Err("not authoritative and no referral (lame)".to_string())
}

/// Collect the addresses for `name` in an answer, following any CNAME chain
/// inside the same response. Returns the addresses and the last name reached.
fn follow_answer(msg: &Message, name: &str) -> (Vec<IpAddr>, String) {
    let mut target = name.to_string();
    for _ in 0..8 {
        let next = msg.answers.iter().find_map(|rec| match &rec.data {
            RData::CNAME(c) if norm(&rec.name) == target => Some(norm(&c.0)),
            _ => None,
        });
        match next {
            Some(next) if next != target => target = next,
            _ => break,
        }
    }
    let addrs = msg
        .answers
        .iter()
        .filter(|rec| norm(&rec.name) == target)
        .filter_map(|rec| match &rec.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect();
    (addrs, target)
}

fn first_cname(msg: &Message, name: &str) -> String {
    msg.answers
        .iter()
        .find_map(|rec| match &rec.data {
            RData::CNAME(c) if norm(&rec.name) == name => Some(norm(&c.0)),
            _ => None,
        })
        .unwrap_or_default()
}
