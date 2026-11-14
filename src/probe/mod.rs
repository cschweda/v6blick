//! The prober: all TCP, TLS and HTTP lives under this module.
//!
//! One probe is one address of one family on one port: open a TCP
//! connection, complete a TLS handshake when the scheme asks for one, send
//! one GET, and follow a few redirects, staying in the same address
//! family throughout. Nothing here decides whether what came back is
//! good; that is for the checks.
//!
//! - [`http`]: the URL, the one request and the response reader
//! - [`cert`]: the TLS settings and the certificate reader

pub mod cert;
pub mod http;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;

use crate::observe::{
    AddressProbe, Connect, Exchange, ExchangeOutcome, Family, HostLookup, Response, Scheme, Tls,
    special_use,
};
use crate::resolve::iterate::printable;
use http::{RawResponse, Url};

/// How the prober behaves on the network.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub connect_timeout: Duration,
    pub tls_timeout: Duration,
    /// For sending the request and reading the whole response.
    pub http_timeout: Duration,
    /// For one probe from its first connection to its last redirect. A
    /// server that answers each request just inside the timeouts above
    /// could otherwise hold a probe for the sum of them all.
    pub probe_deadline: Duration,
    /// For the whole run: DNS, the IPv6-only walks and every probe.
    pub run_deadline: Duration,
    /// Redirects followed from one address.
    pub max_redirects: usize,
    /// Bytes of a body that are read and hashed.
    pub body_limit: usize,
    /// Addresses of one family that are probed.
    pub max_addresses: usize,
    /// Probes in flight at once.
    pub concurrency: usize,
    /// Let loopback, private and link-local addresses be contacted.
    pub allow_private: bool,
    pub user_agent: String,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            tls_timeout: Duration::from_secs(5),
            http_timeout: Duration::from_secs(10),
            probe_deadline: Duration::from_secs(30),
            run_deadline: Duration::from_secs(120),
            max_redirects: 5,
            body_limit: 1024 * 1024,
            max_addresses: 4,
            concurrency: 4,
            allow_private: false,
            user_agent: concat!(
                "v6blick/",
                env!("CARGO_PKG_VERSION"),
                " (+https://github.com/cschweda/v6blick)"
            )
            .to_string(),
        }
    }
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Finds the addresses of a host that a redirect names. The prober does
/// no DNS itself.
pub trait Resolve: Send + Sync {
    fn addresses<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, String>>;
}

/// What to probe for what was given on the command line: a URL as it is,
/// or `https://host/` and `http://host/` for a bare host name. An address
/// in place of a name is refused, because there is nothing to compare.
pub fn targets(input: &str) -> Result<Vec<Url>, String> {
    let input = input.trim();
    if input.len() > http::MAX_URL {
        // Not quoted: it would fill the screen.
        return Err(format!(
            "what was given is longer than {} characters",
            http::MAX_URL
        ));
    }
    let urls = if input.contains("://") {
        vec![Url::parse(input)?]
    } else {
        if input.is_empty() || input.contains(['/', '?', '#', '@']) {
            return Err(format!(
                "'{input}' is not a host name; give a name such as example.org, or a full address such as https://example.org/path"
            ));
        }
        if input.parse::<IpAddr>().is_ok() {
            return Err(format!(
                "'{input}' is an address, not a host name; v6blick compares the IPv4 and IPv6 addresses of one name"
            ));
        }
        if let Some((host, port)) = input.rsplit_once(':')
            && !port.is_empty()
            && port.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(format!(
                "'{input}' names a port without a scheme; write http://{host}:{port}/ or https://{host}:{port}/"
            ));
        }
        vec![
            Url::parse(&format!("https://{input}/"))?,
            Url::parse(&format!("http://{input}/"))?,
        ]
    };
    if urls[0].host_ip().is_some() {
        return Err(format!(
            "'{}' is an address, not a host name; v6blick compares the IPv4 and IPv6 addresses of one name",
            urls[0].host
        ));
    }
    Ok(urls)
}

/// The addresses to probe: the first few of each family, IPv4 first.
pub fn select_addresses(lookup: &HostLookup, max_per_family: usize) -> Vec<IpAddr> {
    lookup
        .a
        .addresses
        .iter()
        .take(max_per_family)
        .chain(lookup.aaaa.addresses.iter().take(max_per_family))
        .copied()
        .collect()
}

/// Why an address is not contacted, if it is not. Addresses that are not
/// ordinary public ones are refused, so that a name or a redirect cannot
/// steer v6blick at a host inside the network it runs in. `allow_private`
/// permits loopback, private and link-local addresses.
pub fn refusal(address: IpAddr, allow_private: bool) -> Option<String> {
    let kind = special_use(address)?;
    if allow_private && kind.is_local() {
        return None;
    }
    Some(if kind.is_local() {
        format!(
            "{address} is a {} address; --allow-private permits it",
            kind.describe()
        )
    } else {
        format!("{address} is a {} address", kind.describe())
    })
}

/// One connection and one request.
struct Attempt {
    connect: Connect,
    tls: Option<Tls>,
    outcome: ExchangeOutcome,
    /// The `Location` header as the server sent it. What is stored in
    /// the outcome is made safe to print, and must not be what is
    /// followed.
    location: Option<String>,
}

/// At most this much of a header value is kept for printing.
const MAX_SHOWN: usize = 1024;

/// Text from the network, safe to print and of bounded length.
pub(crate) fn shown(text: &str) -> String {
    let safe = printable(text);
    if safe.chars().count() <= MAX_SHOWN {
        return safe;
    }
    let kept: String = safe.chars().take(MAX_SHOWN).collect();
    format!("{kept}... ({} characters in all)", safe.chars().count())
}

fn failed(stage: &str, message: impl Into<String>) -> ExchangeOutcome {
    ExchangeOutcome::Failed {
        stage: stage.to_string(),
        message: message.into(),
    }
}

fn ms(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

async fn attempt(
    url: &Url,
    address: IpAddr,
    config: &ProbeConfig,
    tls_config: &Arc<rustls::ClientConfig>,
) -> Attempt {
    if let Some(reason) = refusal(address, config.allow_private) {
        return Attempt {
            outcome: failed("refused", reason.clone()),
            connect: Connect::NotProbed { reason },
            tls: None,
            location: None,
        };
    }
    let started = Instant::now();
    let target = SocketAddr::new(address, url.port);
    let stream =
        match tokio::time::timeout(config.connect_timeout, TcpStream::connect(target)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                let connect = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    Connect::Refused { ms: ms(started) }
                } else {
                    Connect::Failed {
                        ms: ms(started),
                        message: e.to_string(),
                    }
                };
                return Attempt {
                    outcome: failed("connect", connect.label()),
                    connect,
                    tls: None,
                    location: None,
                };
            }
            Err(_) => {
                let connect = Connect::TimedOut { ms: ms(started) };
                return Attempt {
                    outcome: failed("connect", connect.label()),
                    connect,
                    tls: None,
                    location: None,
                };
            }
        };
    let connect = Connect::Connected { ms: ms(started) };
    let _ = stream.set_nodelay(true);

    match url.scheme {
        Scheme::Http => {
            let mut stream = stream;
            let (outcome, location) = exchange(&mut stream, url, config).await;
            Attempt {
                outcome,
                connect,
                tls: None,
                location,
            }
        }
        Scheme::Https => {
            let Ok(name) = ServerName::try_from(url.host.clone()) else {
                let message = "the host name cannot be used for TLS".to_string();
                return Attempt {
                    outcome: failed("tls", message.clone()),
                    connect,
                    tls: Some(Tls::Failed { message }),
                    location: None,
                };
            };
            let handshake = Instant::now();
            let connector = TlsConnector::from(tls_config.clone());
            let result =
                tokio::time::timeout(config.tls_timeout, connector.connect(name, stream)).await;
            let mut stream = match result {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    let message = shown(&e.to_string());
                    return Attempt {
                        outcome: failed("tls", message.clone()),
                        connect,
                        tls: Some(Tls::Failed { message }),
                        location: None,
                    };
                }
                Err(_) => {
                    let message = format!(
                        "the handshake did not finish in {} s",
                        config.tls_timeout.as_secs()
                    );
                    return Attempt {
                        outcome: failed("tls", message.clone()),
                        connect,
                        tls: Some(Tls::Failed { message }),
                        location: None,
                    };
                }
            };
            let leaf = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|der| cert::summarise(der.as_ref(), &url.host));
            let Some(certificate) = leaf else {
                let message = "the server presented no certificate".to_string();
                return Attempt {
                    outcome: failed("tls", message.clone()),
                    connect,
                    tls: Some(Tls::Failed { message }),
                    location: None,
                };
            };
            let tls = Tls::Ok {
                ms: ms(handshake),
                certificate,
            };
            let (outcome, location) = exchange(&mut stream, url, config).await;
            Attempt {
                outcome,
                connect,
                tls: Some(tls),
                location,
            }
        }
    }
}

/// Send the GET and read the response, within the time allowed. With
/// the outcome comes the `Location` of a response that asks to be
/// followed, as it was sent.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    url: &Url,
    config: &ProbeConfig,
) -> (ExchangeOutcome, Option<String>) {
    let work = async {
        stream
            .write_all(&url.request(&config.user_agent))
            .await
            .map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;
        http::read_response(stream, config.body_limit).await
    };
    match tokio::time::timeout(config.http_timeout, work).await {
        Ok(Ok(raw)) => {
            let follow = matches!(raw.status, 301 | 302 | 303 | 307 | 308)
                .then(|| raw.header("location").map(str::to_string))
                .flatten();
            (ExchangeOutcome::Response(summarise(&raw)), follow)
        }
        Ok(Err(message)) => (failed("http", shown(&message)), None),
        Err(_) => (
            failed(
                "http",
                format!(
                    "no complete response in {} s",
                    config.http_timeout.as_secs()
                ),
            ),
            None,
        ),
    }
}

fn summarise(raw: &RawResponse) -> Response {
    Response {
        status: raw.status,
        location: raw.header("location").map(shown),
        body_bytes: raw.body.len() as u64,
        body_truncated: raw.truncated,
        body_sha256: cert::sha256_hex(&raw.body),
        shape_sha256: cert::sha256_hex(&http::shape(&raw.body)),
        title: http::title(&raw.body).map(|t| shown(&t)),
    }
}

/// Probe one address for one URL, following redirects within the
/// address's family.
pub async fn probe_address(
    url: &Url,
    address: IpAddr,
    config: &ProbeConfig,
    resolver: &dyn Resolve,
    tls_config: &Arc<rustls::ClientConfig>,
) -> AddressProbe {
    let family = Family::of(&address);
    let started = Instant::now();
    let first = attempt(url, address, config, tls_config).await;
    let mut probe = AddressProbe {
        family,
        address,
        port: url.port,
        scheme: url.scheme,
        connect: first.connect,
        tls: first.tls,
        exchanges: Vec::new(),
    };
    // Only a request that was sent is an exchange; a connection that
    // never opened is told by `connect` and `tls`.
    let sent = match &first.outcome {
        ExchangeOutcome::Response(_) => true,
        ExchangeOutcome::Failed { stage, .. } => stage == "http",
    };
    if !sent {
        return probe;
    }
    probe.exchanges.push(Exchange {
        url: url.to_string(),
        address: Some(address),
        outcome: first.outcome,
    });

    let mut current = url.clone();
    let mut location = first.location;
    let mut seen = vec![url.to_string()];
    for _ in 0..config.max_redirects {
        let Some(sent) = location.take() else {
            break;
        };
        let next = match current.join(&sent) {
            Ok(next) => next,
            Err(why) => {
                probe.exchanges.push(Exchange {
                    url: shown(&sent),
                    address: None,
                    outcome: failed("http", format!("the redirect cannot be followed: {why}")),
                });
                break;
            }
        };
        if seen.contains(&next.to_string()) {
            probe.exchanges.push(Exchange {
                url: next.to_string(),
                address: None,
                outcome: failed("http", "the redirects form a loop"),
            });
            break;
        }
        seen.push(next.to_string());

        // Stay in the family: the same address for the same host, and
        // for another host an address of the same family or none.
        let found = if next.host == url.host {
            Ok(address)
        } else if let Some(literal) = next.host_ip() {
            if Family::of(&literal) == family {
                Ok(literal)
            } else {
                Err(format!(
                    "the redirect names the {} address {literal}, which cannot be reached over {}",
                    Family::of(&literal).as_str(),
                    family.as_str()
                ))
            }
        } else {
            match resolver.addresses(&next.host).await {
                Ok(list) => list
                    .into_iter()
                    .find(|a| Family::of(a) == family)
                    .ok_or_else(|| format!("{} has no {} address", next.host, family.as_str())),
                Err(why) => Err(format!("{} cannot be resolved: {}", next.host, shown(&why))),
            }
        };
        let to = match found {
            Ok(to) => to,
            Err(message) => {
                probe.exchanges.push(Exchange {
                    url: next.to_string(),
                    address: None,
                    outcome: failed("resolve", message),
                });
                break;
            }
        };
        // What is left of the time this probe may take.
        let left = config.probe_deadline.saturating_sub(started.elapsed());
        let hop = match tokio::time::timeout(left, attempt(&next, to, config, tls_config)).await {
            Ok(hop) => hop,
            Err(_) => {
                probe.exchanges.push(Exchange {
                    url: next.to_string(),
                    address: Some(to),
                    outcome: failed(
                        "deadline",
                        format!(
                            "the probe and its redirects did not finish in {} s",
                            config.probe_deadline.as_secs()
                        ),
                    ),
                });
                break;
            }
        };
        let ended = matches!(hop.outcome, ExchangeOutcome::Failed { .. });
        probe.exchanges.push(Exchange {
            url: next.to_string(),
            address: Some(to),
            outcome: hop.outcome,
        });
        if ended {
            break;
        }
        location = hop.location;
        current = next;
    }
    probe
}

/// Probe every address for every URL, a few at a time. The result is in
/// the order of `urls`, then of `addresses`.
pub async fn probe_all(
    urls: &[Url],
    addresses: &[IpAddr],
    config: Arc<ProbeConfig>,
    resolver: Arc<dyn Resolve>,
) -> Result<Vec<AddressProbe>, rustls::Error> {
    let tls_config = cert::client_config()?;
    let permits = Arc::new(Semaphore::new(config.concurrency.max(1)));
    let mut tasks = JoinSet::new();
    let mut order = 0usize;
    for url in urls {
        for address in addresses {
            let (url, address, index) = (url.clone(), *address, order);
            let (config, resolver, tls_config, permits) = (
                config.clone(),
                resolver.clone(),
                tls_config.clone(),
                permits.clone(),
            );
            order += 1;
            tasks.spawn(async move {
                let _permit = permits.acquire().await.expect("semaphore is never closed");
                let probe =
                    probe_address(&url, address, &config, resolver.as_ref(), &tls_config).await;
                (index, probe)
            });
        }
    }
    let mut done = Vec::with_capacity(order);
    while let Some(joined) = tasks.join_next().await {
        // A probe that panicked is a bug; let it show.
        done.push(joined.expect("a probe task panicked"));
    }
    done.sort_by_key(|(index, _)| *index);
    Ok(done.into_iter().map(|(_, probe)| probe).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_host_is_probed_on_both_ports() {
        let urls = targets("Example.ORG").unwrap();
        let text: Vec<String> = urls.iter().map(Url::to_string).collect();
        assert_eq!(text, ["https://example.org/", "http://example.org/"]);
        assert_eq!(targets("example.org.").unwrap()[0].host, "example.org");
    }

    #[test]
    fn a_url_is_probed_as_given() {
        let urls = targets("http://example.org:8080/health?x=1").unwrap();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].to_string(), "http://example.org:8080/health?x=1");
    }

    #[test]
    fn what_is_not_a_host_is_refused_with_a_reason() {
        for bad in [
            "192.0.2.1",
            "2001:db8::1",
            "https://192.0.2.1/",
            "https://[2001:db8::1]/",
            "example.org/path",
            "example.org:8443",
            "ftp://example.org/",
            "",
        ] {
            assert!(targets(bad).is_err(), "{bad}");
        }
        let why = targets("example.org:8443").unwrap_err();
        assert!(why.contains("https://example.org:8443/"), "{why}");
    }

    #[test]
    fn private_destinations_need_the_flag() {
        let refused = |s: &str, allow| refusal(s.parse().unwrap(), allow);
        assert!(refused("127.0.0.1", false).is_some());
        assert!(refused("::1", false).is_some());
        assert!(refused("10.0.0.8", false).is_some());
        assert!(refused("169.254.169.254", false).is_some());
        assert!(refused("fd00::8", false).is_some());
        assert!(refused("127.0.0.1", true).is_none());
        assert!(refused("::1", true).is_none());
        assert!(refused("fd00::8", true).is_none());
        // Never, flag or no flag.
        assert!(refused("0.0.0.0", true).is_some());
        assert!(refused("224.0.0.1", true).is_some());
        assert!(refused("::ffff:127.0.0.1", true).is_some());
        // Ordinary addresses are not refused.
        assert!(refused("93.184.215.14", false).is_none());
        assert!(refused("2606:4700::6810:84e5", false).is_none());
    }
}
