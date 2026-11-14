//! DNS: all name resolution lives under this module.
//!
//! - [`transport`]: sends one query to one server; live, recorded or replayed
//! - [`limiter`]: bounded concurrency and the per-server rate cap
//! - [`hints`]: built-in root hints
//! - [`iterate`]: walks from the root to a name, recording each referral
//!
//! Those four are copied from zoneblick. This file adds what v6blick asks
//! of them: which address families work from here, the addresses of a
//! host, and the walk that reaches every nameserver over IPv6 only.

pub mod hints;
pub mod iterate;
pub mod limiter;
pub mod transport;

use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::rr::Name;

use crate::observe::{
    FamilyLookup, HostLookup, Ipv6Walk, LookupSource, LookupStatus, QType, Transport, Vantage,
    WalkFailure,
};
use hints::ROOT_HINTS;
use iterate::{Lookup, Resolver, norm};
pub use transport::{Client, Exchange, Fixture, NetConfig, QuerySpec, RawOutcome};

/// Why a name could not be resolved.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("'{0}' is not a valid host name")]
    InvalidName(String),
    #[error("no usable answer from the nameservers of {zone} ({detail})")]
    ServersFailed { zone: String, detail: String },
    #[error("gave up resolving {name}: too many referrals")]
    TooManyReferrals { name: String },
}

/// At most this many aliases are followed from one host name.
const MAX_ALIASES: usize = 8;

/// A lowercase, fully qualified form of a host name.
pub fn normalise_host(input: &str) -> Result<String, ResolveError> {
    let trimmed = input.trim();
    let invalid = || ResolveError::InvalidName(input.to_string());
    if trimmed.is_empty() || trimmed == "." {
        return Err(invalid());
    }
    let name = Name::from_utf8(trimmed).map_err(|_| invalid())?;
    Ok(norm(&name))
}

/// Find out which address families work from here by asking root servers.
pub async fn detect_vantage(client: &Client) -> Vantage {
    let mut works = [false, false];
    for (family, slot) in works.iter_mut().enumerate() {
        for (_, v4, v6) in ROOT_HINTS.iter().take(2) {
            let server = if family == 0 { v4 } else { v6 };
            let spec = QuerySpec {
                server: server.parse().expect("root hint address is valid"),
                transport: Transport::Udp,
                qname: ".".to_string(),
                qtype: QType::Ns,
                edns: true,
            };
            if matches!(client.exchange(&spec).await, RawOutcome::Response { .. }) {
                *slot = true;
                break;
            }
        }
    }
    Vantage {
        ipv4: works[0],
        ipv6: works[1],
    }
}

/// Look up the A and AAAA records of `host` from the root, following
/// aliases from zone to zone. `host` is normalised.
pub async fn lookup_host(client: Arc<Client>, vantage: Vantage, host: &str) -> HostLookup {
    let resolver = Resolver::new(client, vantage);
    let mut name = host.to_string();
    let mut chain: Vec<String> = Vec::new();
    loop {
        let a = resolver.lookup(&name, QType::A).await;
        let aaaa = resolver.lookup(&name, QType::Aaaa).await;
        let hops = if a.cname_chain.is_empty() {
            &aaaa.cname_chain
        } else {
            &a.cname_chain
        };
        let found = !a.rdata.is_empty() || !aaaa.rdata.is_empty();
        let next = hops.last().cloned();
        let looped = hops.iter().any(|h| h == host || chain.contains(h));
        chain.extend(hops.iter().cloned());
        let more = match &next {
            Some(_) if found => false,
            Some(_) => !looped && chain.len() <= MAX_ALIASES,
            None => false,
        };
        if !more {
            let stuck = (next.is_some() && !found).then(|| {
                if looped {
                    "the aliases form a loop".to_string()
                } else {
                    "too many aliases".to_string()
                }
            });
            return HostLookup {
                name: host.to_string(),
                source: LookupSource::Root,
                cname_chain: chain,
                a: family_lookup(&a, stuck.clone()),
                aaaa: family_lookup(&aaaa, stuck),
            };
        }
        name = next.expect("an alias target");
    }
}

fn family_lookup(lookup: &Lookup, stuck: Option<String>) -> FamilyLookup {
    let mut addresses: Vec<IpAddr> = lookup.rdata.iter().filter_map(|r| r.parse().ok()).collect();
    addresses.sort();
    addresses.dedup();
    let error = lookup.error.clone().or(stuck);
    let status = if !addresses.is_empty() {
        LookupStatus::Answer
    } else if error.is_some() {
        LookupStatus::Failed
    } else if lookup.status == "nxdomain" {
        LookupStatus::Nxdomain
    } else {
        LookupStatus::Nodata
    };
    FamilyLookup {
        status,
        addresses,
        error: if status == LookupStatus::Failed {
            error
        } else {
            None
        },
    }
}

/// Look `host` up with the operating system's resolver. For names the
/// public DNS does not know, such as `localhost` or a name in a hosts
/// file, when private destinations are allowed.
pub async fn lookup_host_system(host: &str) -> HostLookup {
    let plain = host.trim_end_matches('.');
    let (mut v4, mut v6, mut error) = (Vec::new(), Vec::new(), None);
    match tokio::net::lookup_host((plain, 0)).await {
        Ok(found) => {
            for address in found.map(|a| a.ip()) {
                match address {
                    IpAddr::V4(_) => v4.push(address),
                    IpAddr::V6(_) => v6.push(address),
                }
            }
        }
        Err(e) => error = Some(e.to_string()),
    }
    let family = |mut addresses: Vec<IpAddr>| {
        addresses.sort();
        addresses.dedup();
        FamilyLookup {
            status: match (addresses.is_empty(), &error) {
                (false, _) => LookupStatus::Answer,
                (true, Some(_)) => LookupStatus::Failed,
                (true, None) => LookupStatus::Nodata,
            },
            error: if addresses.is_empty() {
                error.clone()
            } else {
                None
            },
            addresses,
        }
    };
    HostLookup {
        name: host.to_string(),
        source: LookupSource::System,
        cname_chain: Vec::new(),
        a: family(v4),
        aaaa: family(v6),
    }
}

/// Resolve `name` from the root again, reaching every nameserver over
/// IPv6 only, and say where that stops working. Each walk starts with
/// nothing cached, so its path is complete.
pub async fn walk_ipv6_only(client: Arc<Client>, name: &str) -> Ipv6Walk {
    let only_v6 = Vantage {
        ipv4: false,
        ipv6: true,
    };
    let trace = Resolver::new(client.clone(), only_v6)
        .trace(name, QType::Aaaa)
        .await;
    // A walk that failed after the query budget ran out failed for want
    // of budget. It says nothing about the zone.
    let unfinished = (trace.failed.is_some() && client.budget_spent())
        .then(|| "this run used up its DNS queries before the walk ended".to_string());
    Ipv6Walk {
        name: name.to_string(),
        path: trace.path,
        failed_at: match unfinished {
            Some(_) => None,
            None => trace
                .failed
                .map(|(zone, detail)| WalkFailure { zone, detail }),
        },
        unfinished,
    }
}
