//! The recorded observations of one run: plain data, no I/O.
//!
//! The resolver and the prober fill these types in; the checks read them.
//! Everything here serialises, so a whole run can be saved as a fixture
//! and checked again offline.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// An address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Ipv4,
    Ipv6,
}

impl Family {
    pub fn of(address: &IpAddr) -> Family {
        match address {
            IpAddr::V4(_) => Family::Ipv4,
            IpAddr::V6(_) => Family::Ipv6,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Family::Ipv4 => "IPv4",
            Family::Ipv6 => "IPv6",
        }
    }
}

/// How a DNS query was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Udp,
    Tcp,
}

/// The record types v6blick asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum QType {
    Ns,
    A,
    Aaaa,
    Cname,
}

impl QType {
    pub fn as_str(self) -> &'static str {
        match self {
            QType::Ns => "NS",
            QType::A => "A",
            QType::Aaaa => "AAAA",
            QType::Cname => "CNAME",
        }
    }
}

/// Which address families work from the machine the run was made on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vantage {
    pub ipv4: bool,
    pub ipv6: bool,
}

impl Vantage {
    pub fn can_reach(&self, addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(_) => self.ipv4,
            IpAddr::V6(_) => self.ipv6,
        }
    }
}

/// An address record handed out by a parent alongside a referral.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Glue {
    pub name: String,
    pub address: IpAddr,
}

/// One referral followed on the way from the root to a name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferralStep {
    /// The zone whose server was asked.
    pub from_zone: String,
    /// The zone the referral delegates to.
    pub to_zone: String,
    /// The server that gave the referral.
    pub server_name: Option<String>,
    pub server_address: IpAddr,
    /// The NS set in the referral, sorted.
    pub ns: Vec<String>,
    /// The glue in the referral, sorted.
    pub glue: Vec<Glue>,
}

/// How a lookup of one record type ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LookupStatus {
    /// At least one address came back.
    Answer,
    /// The name exists and has no record of this type.
    Nodata,
    /// The name does not exist.
    Nxdomain,
    /// No usable answer; `error` says why.
    Failed,
}

/// The addresses of one family that a host's name led to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyLookup {
    pub status: LookupStatus,
    /// Sorted, without duplicates.
    pub addresses: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Where the addresses of a host came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LookupSource {
    /// Resolved from the root servers, asking no recursive resolver.
    Root,
    /// The operating system's resolver: only for a name the public DNS
    /// does not know, and only with `--allow-private`.
    System,
}

/// The A and AAAA records of the host, after following CNAMEs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostLookup {
    /// The name that was asked for. Lowercase, with a trailing dot.
    pub name: String,
    pub source: LookupSource,
    /// Each alias target on the way, in order. Empty when the host is not
    /// an alias. The addresses belong to the last name.
    pub cname_chain: Vec<String>,
    pub a: FamilyLookup,
    pub aaaa: FamilyLookup,
}

impl HostLookup {
    /// The name the addresses belong to: the last alias target, or the
    /// host itself.
    pub fn canonical_name(&self) -> &str {
        self.cname_chain.last().unwrap_or(&self.name)
    }
}

/// Where the IPv6-only walk stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalkFailure {
    /// The zone none of whose nameservers could be asked over IPv6.
    pub zone: String,
    pub detail: String,
}

/// A walk from the root towards one name, reaching every nameserver over
/// IPv6 only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv6Walk {
    pub name: String,
    /// The referrals that were followed, from the root down.
    pub path: Vec<ReferralStep>,
    /// Set when the walk could not go on. `None` means the name's own
    /// nameservers answered over IPv6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_at: Option<WalkFailure>,
}

/// `http` or `https`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Https,
    Http,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Https => "https",
            Scheme::Http => "http",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Https => 443,
            Scheme::Http => 80,
        }
    }
}

/// How the attempt to open a TCP connection ended. Times are in
/// milliseconds from the start of the attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Connect {
    Connected {
        ms: u64,
    },
    /// The other side answered and refused.
    Refused {
        ms: u64,
    },
    /// Nothing answered before the timeout.
    TimedOut {
        ms: u64,
    },
    /// Any other error, for example "no route to host".
    Failed {
        ms: u64,
        message: String,
    },
    /// No connection was attempted, and why.
    NotProbed {
        reason: String,
    },
}

impl Connect {
    pub fn connected_ms(&self) -> Option<u64> {
        match self {
            Connect::Connected { ms } => Some(*ms),
            _ => None,
        }
    }

    /// True when a connection was attempted and did not open.
    pub fn is_failure(&self) -> bool {
        matches!(
            self,
            Connect::Refused { .. } | Connect::TimedOut { .. } | Connect::Failed { .. }
        )
    }

    /// How long a failed attempt took, in milliseconds.
    pub fn failure_ms(&self) -> Option<u64> {
        match self {
            Connect::Refused { ms } | Connect::TimedOut { ms } | Connect::Failed { ms, .. } => {
                Some(*ms)
            }
            _ => None,
        }
    }

    /// A short description for people.
    pub fn label(&self) -> String {
        match self {
            Connect::Connected { ms } => format!("connected in {ms} ms"),
            Connect::Refused { ms } => format!("refused after {ms} ms"),
            Connect::TimedOut { ms } => format!("no answer after {ms} ms"),
            Connect::Failed { ms, message } => format!("failed after {ms} ms: {message}"),
            Connect::NotProbed { reason } => format!("not probed: {reason}"),
        }
    }
}

/// The certificate a server presented, as far as v6blick reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    /// SHA-256 of the certificate, lowercase hex.
    pub sha256: String,
    /// The DNS names it is for, sorted.
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after_unix: Option<u64>,
    /// Whether one of the names matches the host that was asked for.
    pub covers_host: bool,
}

/// How the TLS handshake ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Tls {
    Ok { ms: u64, certificate: Certificate },
    Failed { message: String },
}

impl Tls {
    pub fn certificate(&self) -> Option<&Certificate> {
        match self {
            Tls::Ok { certificate, .. } => Some(certificate),
            Tls::Failed { .. } => None,
        }
    }
}

/// An HTTP response, with the body reduced to its size and two hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub status: u16,
    /// The `Location` header, as sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Bytes of body that were read.
    pub body_bytes: u64,
    /// True when the body was longer than the limit and was cut off.
    pub body_truncated: bool,
    /// SHA-256 of the bytes that were read, lowercase hex.
    pub body_sha256: String,
    /// SHA-256 of the body's structure: the sequence of its HTML tag
    /// names, without text or attributes. Two loads of a dynamic page
    /// usually share it.
    pub shape_sha256: String,
}

/// What one HTTP request led to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ExchangeOutcome {
    Response(Response),
    /// The request got no response. `stage` is `resolve`, `refused`,
    /// `connect`, `tls` or `http`.
    Failed {
        stage: String,
        message: String,
    },
}

/// One HTTP request: the first to an address, or a redirect that was
/// followed from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exchange {
    pub url: String,
    /// The address the request went to, when one was found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<IpAddr>,
    #[serde(flatten)]
    pub outcome: ExchangeOutcome,
}

impl Exchange {
    pub fn response(&self) -> Option<&Response> {
        match &self.outcome {
            ExchangeOutcome::Response(r) => Some(r),
            ExchangeOutcome::Failed { .. } => None,
        }
    }
}

/// Everything recorded about one address on one port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressProbe {
    pub family: Family,
    pub address: IpAddr,
    pub port: u16,
    pub scheme: Scheme,
    pub connect: Connect,
    /// The handshake on this connection. `None` for plain HTTP, and when
    /// no connection opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
    /// The request to this address, then each redirect that was followed,
    /// in order. Empty when no request could be sent.
    pub exchanges: Vec<Exchange>,
}

impl AddressProbe {
    /// The response to the first request.
    pub fn first_response(&self) -> Option<&Response> {
        self.exchanges.first().and_then(Exchange::response)
    }

    /// The last exchange, when it is a response that is not itself a
    /// redirect: the page the chain ended at.
    pub fn final_response(&self) -> Option<(&Exchange, &Response)> {
        let last = self.exchanges.last()?;
        let response = last.response()?;
        (!(300..400).contains(&response.status)).then_some((last, response))
    }
}

/// Everything one `check` run recorded. The checks read only this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// The host that was checked. Lowercase, with a trailing dot.
    pub host: String,
    /// What was given on the command line.
    pub target: String,
    pub started_at_unix: u64,
    pub vantage: Vantage,
    pub lookup: HostLookup,
    /// One walk for the host and, when it is an alias, one for the name
    /// its addresses belong to. Empty when the name came from the
    /// system resolver.
    pub ipv6_walks: Vec<Ipv6Walk>,
    pub probes: Vec<AddressProbe>,
}

impl Observation {
    pub fn probes_of(&self, family: Family) -> impl Iterator<Item = &AddressProbe> {
        self.probes.iter().filter(move |p| p.family == family)
    }
}

/// Why an address is not an ordinary public one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecialUse {
    Loopback,
    Private,
    LinkLocal,
    Unspecified,
    Multicast,
    Documentation,
    Reserved,
    /// An IPv4 address written as IPv6 (`::ffff:192.0.2.1`).
    Ipv4Mapped,
    /// 6to4, Teredo, the 6bone, site-local and IPv4-compatible addresses.
    RetiredTransition,
    /// The well-known NAT64 prefix, which only means something inside a
    /// network that has a translator.
    Nat64,
}

impl SpecialUse {
    pub fn describe(self) -> &'static str {
        match self {
            SpecialUse::Loopback => "loopback",
            SpecialUse::Private => "private",
            SpecialUse::LinkLocal => "link-local",
            SpecialUse::Unspecified => "unspecified",
            SpecialUse::Multicast => "multicast",
            SpecialUse::Documentation => "documentation",
            SpecialUse::Reserved => "reserved",
            SpecialUse::Ipv4Mapped => "IPv4-mapped",
            SpecialUse::RetiredTransition => "retired transition",
            SpecialUse::Nat64 => "NAT64",
        }
    }

    /// The kinds `--allow-private` permits as a destination.
    pub fn is_local(self) -> bool {
        matches!(
            self,
            SpecialUse::Loopback | SpecialUse::Private | SpecialUse::LinkLocal
        )
    }
}

/// Say why an address is not an ordinary public address, if it is not.
pub fn special_use(address: IpAddr) -> Option<SpecialUse> {
    match address {
        IpAddr::V4(a) => {
            let o = a.octets();
            if a.is_loopback() {
                Some(SpecialUse::Loopback)
            } else if a.is_private() || (o[0] == 100 && o[1] & 0xc0 == 64) {
                // 100.64.0.0/10 is shared between a provider and its
                // customers; from outside it is as private as 10.0.0.0/8.
                Some(SpecialUse::Private)
            } else if a.is_link_local() {
                Some(SpecialUse::LinkLocal)
            } else if o[0] == 0 {
                Some(SpecialUse::Unspecified)
            } else if a.is_multicast() {
                Some(SpecialUse::Multicast)
            } else if a.is_documentation() {
                Some(SpecialUse::Documentation)
            } else if o[0] >= 240 || (o[0] == 198 && o[1] & 0xfe == 18) {
                Some(SpecialUse::Reserved)
            } else {
                None
            }
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            if a.is_loopback() {
                Some(SpecialUse::Loopback)
            } else if a.is_unspecified() {
                Some(SpecialUse::Unspecified)
            } else if a.to_ipv4_mapped().is_some() {
                Some(SpecialUse::Ipv4Mapped)
            } else if s[..6] == [0; 6] {
                // ::a.b.c.d, the IPv4-compatible form.
                Some(SpecialUse::RetiredTransition)
            } else if s[0] & 0xfe00 == 0xfc00 {
                Some(SpecialUse::Private)
            } else if s[0] & 0xffc0 == 0xfe80 {
                Some(SpecialUse::LinkLocal)
            } else if s[0] & 0xff00 == 0xff00 {
                Some(SpecialUse::Multicast)
            } else if s[0] == 0x2001 && s[1] == 0x0db8 {
                Some(SpecialUse::Documentation)
            } else if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0; 4] {
                Some(SpecialUse::Nat64)
            } else if s[0] == 0x2002
                || (s[0] == 0x2001 && s[1] == 0)
                || s[0] == 0x3ffe
                || s[0] & 0xffc0 == 0xfec0
            {
                // 6to4, Teredo, the 6bone, site-local.
                Some(SpecialUse::RetiredTransition)
            } else if s[0] == 0x0100 && s[1..4] == [0; 3] {
                // 100::/64, the discard prefix.
                Some(SpecialUse::Reserved)
            } else {
                None
            }
        }
    }
}

/// True when `ancestor` is `name` or a parent of it. Both normalised.
pub fn is_ancestor_or_equal(ancestor: &str, name: &str) -> bool {
    if ancestor == "." || ancestor == name {
        return true;
    }
    name.len() > ancestor.len()
        && name.ends_with(ancestor)
        && name.as_bytes()[name.len() - ancestor.len() - 1] == b'.'
}

/// The parent of a normalised name; the root is its own parent.
pub fn parent_name(name: &str) -> &str {
    if name == "." {
        return ".";
    }
    match name.find('.') {
        Some(i) if i + 1 < name.len() => &name[i + 1..],
        _ => ".",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancestry() {
        assert!(is_ancestor_or_equal(".", "example.com."));
        assert!(is_ancestor_or_equal("com.", "example.com."));
        assert!(is_ancestor_or_equal("example.com.", "example.com."));
        assert!(!is_ancestor_or_equal("ample.com.", "example.com."));
        assert!(!is_ancestor_or_equal("example.com.", "com."));
        assert!(!is_ancestor_or_equal("org.", "example.com."));
    }

    #[test]
    fn parents() {
        assert_eq!(parent_name("www.example.com."), "example.com.");
        assert_eq!(parent_name("com."), ".");
        assert_eq!(parent_name("."), ".");
    }

    #[test]
    fn special_addresses_are_named() {
        let kind = |s: &str| special_use(s.parse().unwrap());
        assert_eq!(kind("127.0.0.1"), Some(SpecialUse::Loopback));
        assert_eq!(kind("10.1.2.3"), Some(SpecialUse::Private));
        assert_eq!(kind("100.64.0.1"), Some(SpecialUse::Private));
        assert_eq!(kind("169.254.169.254"), Some(SpecialUse::LinkLocal));
        assert_eq!(kind("192.0.2.1"), Some(SpecialUse::Documentation));
        assert_eq!(kind("0.0.0.0"), Some(SpecialUse::Unspecified));
        assert_eq!(kind("93.184.215.14"), None);
        assert_eq!(kind("::1"), Some(SpecialUse::Loopback));
        assert_eq!(kind("::"), Some(SpecialUse::Unspecified));
        assert_eq!(kind("::ffff:192.0.2.1"), Some(SpecialUse::Ipv4Mapped));
        assert_eq!(kind("::192.0.2.1"), Some(SpecialUse::RetiredTransition));
        assert_eq!(kind("fd00::1"), Some(SpecialUse::Private));
        assert_eq!(kind("fe80::1"), Some(SpecialUse::LinkLocal));
        assert_eq!(kind("2001:db8::1"), Some(SpecialUse::Documentation));
        assert_eq!(kind("64:ff9b::c000:201"), Some(SpecialUse::Nat64));
        assert_eq!(
            kind("2002:c000:201::1"),
            Some(SpecialUse::RetiredTransition)
        );
        assert_eq!(kind("2001:0:53aa::1"), Some(SpecialUse::RetiredTransition));
        assert_eq!(kind("fec0::1"), Some(SpecialUse::RetiredTransition));
        assert_eq!(kind("2606:4700::6810:84e5"), None);
    }

    #[test]
    fn outcomes_are_tagged_in_json() {
        let json = serde_json::to_string(&Connect::Refused { ms: 3 }).unwrap();
        assert_eq!(json, r#"{"result":"refused","ms":3}"#);
        let exchange = Exchange {
            url: "https://example.org/".to_string(),
            address: None,
            outcome: ExchangeOutcome::Failed {
                stage: "resolve".to_string(),
                message: "no IPv6 address".to_string(),
            },
        };
        let json = serde_json::to_string(&exchange).unwrap();
        assert_eq!(
            json,
            r#"{"url":"https://example.org/","result":"failed","stage":"resolve","message":"no IPv6 address"}"#
        );
        assert_eq!(serde_json::from_str::<Exchange>(&json).unwrap(), exchange);
    }
}
