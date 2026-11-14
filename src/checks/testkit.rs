//! Hand-built observations for the check tests.

use std::net::IpAddr;

use crate::observe::{
    AddressProbe, Certificate, Connect, Exchange, ExchangeOutcome, Family, FamilyLookup,
    HostLookup, Ipv6Walk, LookupSource, LookupStatus, Observation, Response, Scheme, Tls, Vantage,
};

pub const V4: &str = "192.0.2.10";
pub const V6: &str = "2001:db8::10";

pub fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

pub fn family(status: LookupStatus, addresses: &[&str]) -> FamilyLookup {
    FamilyLookup {
        status,
        addresses: addresses.iter().map(|a| ip(a)).collect(),
        error: (status == LookupStatus::Failed).then(|| "timeout".to_string()),
    }
}

pub fn certificate(tag: &str) -> Certificate {
    Certificate {
        sha256: tag.repeat(64)[..64].to_string(),
        names: vec!["www.example.org".to_string()],
        not_after_unix: Some(1_900_000_000),
        covers_host: true,
    }
}

pub fn response(status: u16, location: Option<&str>, body: &str) -> Response {
    Response {
        status,
        location: location.map(str::to_string),
        body_bytes: body.len() as u64,
        body_truncated: false,
        body_sha256: format!("body:{body}"),
        // Stands in for the structure: everything before the first space.
        shape_sha256: format!("shape:{}", body.split(' ').next().unwrap_or_default()),
        title: None,
    }
}

pub fn exchange(url: &str, address: &str, response: Response) -> Exchange {
    Exchange {
        url: url.to_string(),
        address: Some(ip(address)),
        outcome: ExchangeOutcome::Response(response),
    }
}

/// A probe that connected in `ms`, with certificate `a` over HTTPS, and
/// got a 200 with the body `page one`.
pub fn probe(address: &str, scheme: Scheme, ms: u64) -> AddressProbe {
    let url = format!("{}://www.example.org/", scheme.as_str());
    AddressProbe {
        family: Family::of(&ip(address)),
        address: ip(address),
        port: scheme.default_port(),
        scheme,
        connect: Connect::Connected { ms },
        tls: (scheme == Scheme::Https).then(|| Tls::Ok {
            ms: 20,
            certificate: certificate("a"),
        }),
        exchanges: vec![exchange(&url, address, response(200, None, "page one"))],
    }
}

/// A probe whose connection did not open.
pub fn dead(address: &str, scheme: Scheme, connect: Connect) -> AddressProbe {
    AddressProbe {
        connect,
        tls: None,
        exchanges: vec![],
        ..probe(address, scheme, 0)
    }
}

/// A host with one address of each family, served alike over both, on
/// both ports. The addresses are from the documentation ranges.
pub fn healthy() -> Observation {
    Observation {
        host: "www.example.org.".to_string(),
        target: "www.example.org".to_string(),
        started_at_unix: 1_700_000_000,
        vantage: Vantage {
            ipv4: true,
            ipv6: true,
        },
        lookup: HostLookup {
            name: "www.example.org.".to_string(),
            source: LookupSource::Root,
            cname_chain: vec![],
            a: family(LookupStatus::Answer, &[V4]),
            // A test address that is not from a special range, so that
            // ADR-02 stays quiet.
            aaaa: family(LookupStatus::Answer, &["2606:4700::10"]),
        },
        ipv6_walks: vec![Ipv6Walk {
            name: "www.example.org.".to_string(),
            path: vec![],
            failed_at: None,
            unfinished: None,
        }],
        probes: vec![
            probe(V4, Scheme::Https, 20),
            probe(V6, Scheme::Https, 22),
            probe(V4, Scheme::Http, 20),
            probe(V6, Scheme::Http, 22),
        ],
    }
}

/// [`healthy`], by another name where the test is about the lookup.
pub fn public() -> Observation {
    healthy()
}

/// The probe of `address` over `scheme`, to change it.
pub fn at<'a>(obs: &'a mut Observation, address: &str, scheme: Scheme) -> &'a mut AddressProbe {
    let address = ip(address);
    obs.probes
        .iter_mut()
        .find(|p| p.address == address && p.scheme == scheme)
        .expect("the probe exists")
}
