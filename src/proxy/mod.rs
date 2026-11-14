//! The mode proxy: a forward proxy on `127.0.0.1` that lives for one page
//! load and decides, connection by connection, what the network being
//! simulated would allow.
//!
//! The browser sends it every request by host name. The proxy resolves
//! the name itself, applies the rule of the mode, connects or refuses,
//! and records what it did. After that it only carries bytes: an HTTPS
//! connection is a tunnel it cannot read, and the browser does its own
//! TLS.
//!
//! It is not a general proxy. It listens on the loopback address only,
//! on a port the system picks, for as long as one page load takes, and
//! it applies the same address rule as the prober: a page cannot steer
//! it at a host inside the network it runs in.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::observe::{Family, Mode, ProxiedConnection, ProxyOutcome, RefusalReason};
use crate::probe::http::Url;
use crate::probe::{Resolve, refusal};
use crate::resolve::iterate::printable;

/// The head of a request to the proxy may be at most this large.
const MAX_HEAD: usize = 64 * 1024;
/// At most this many addresses of a host are tried.
const MAX_ADDRESSES: usize = 4;

/// How the proxy behaves.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub mode: Mode,
    /// Let loopback, private and link-local addresses be connected to.
    pub allow_private: bool,
    pub connect_timeout: Duration,
    /// In `dual`, how long IPv6 gets before IPv4 is tried, as a browser
    /// that prefers IPv6 would fall back.
    pub fallback_after: Duration,
    /// For the browser to send the head of its request.
    pub head_timeout: Duration,
    /// Connections carried at once. More than this wait.
    pub max_connections: usize,
}

impl ProxyConfig {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            allow_private: false,
            connect_timeout: Duration::from_secs(5),
            fallback_after: Duration::from_secs(2),
            head_timeout: Duration::from_secs(10),
            max_connections: 64,
        }
    }
}

/// A running proxy. Dropping it stops it.
pub struct Proxy {
    address: SocketAddr,
    records: Arc<Mutex<Vec<ProxiedConnection>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Proxy {
    /// Start listening on a loopback port of the system's choosing.
    pub async fn start(config: ProxyConfig, resolver: Arc<dyn Resolve>) -> std::io::Result<Proxy> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let records = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::new(Shared {
            config,
            resolver,
            records: records.clone(),
            slots: Semaphore::new(0),
        });
        shared
            .slots
            .add_permits(shared.config.max_connections.max(1));
        let task = tokio::spawn(async move {
            // Connections live in this set, so that they end with it.
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, peer)) = accepted else {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        };
                        // Bound to loopback, so this cannot be otherwise;
                        // checked all the same.
                        if !peer.ip().is_loopback() {
                            continue;
                        }
                        let shared = shared.clone();
                        connections.spawn(async move {
                            let Ok(_slot) = shared.slots.acquire().await else {
                                return;
                            };
                            serve(stream, &shared).await;
                        });
                    }
                    Some(_) = connections.join_next() => {}
                }
            }
        });
        Ok(Proxy {
            address,
            records,
            task,
        })
    }

    /// Where the browser is to send its requests.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// What has been recorded so far, in the order connections were
    /// decided.
    pub fn records(&self) -> Vec<ProxiedConnection> {
        self.records.lock().expect("lock").clone()
    }

    /// Stop the proxy, closing every connection, and return the record.
    pub fn finish(self) -> Vec<ProxiedConnection> {
        self.records()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Shared {
    config: ProxyConfig,
    resolver: Arc<dyn Resolve>,
    records: Arc<Mutex<Vec<ProxiedConnection>>>,
    slots: Semaphore,
}

/// What the browser asked for.
struct Asked {
    host: String,
    port: u16,
    tunnel: bool,
    /// For plain HTTP: the request as it goes to the server.
    forward: Vec<u8>,
}

/// Read the head of the browser's request and say where it wants to go.
fn parse(head: &[u8], rest: &[u8]) -> Result<Asked, String> {
    let text = std::str::from_utf8(head).map_err(|_| "the request is not text".to_string())?;
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or_default();
    let mut parts = first.split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err("the request line is malformed".to_string());
    };
    if !version.starts_with("HTTP/1.") || parts.next().is_some() {
        return Err("the request line is malformed".to_string());
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        // `host:port`, the host in brackets when it is an IPv6 address.
        let url = Url::parse(&format!("https://{target}/"))?;
        return Ok(Asked {
            host: url.host,
            port: url.port,
            tunnel: true,
            forward: Vec::new(),
        });
    }
    if !method.bytes().all(|b| b.is_ascii_uppercase()) || method.is_empty() {
        return Err("the method is malformed".to_string());
    }
    let url = Url::parse(target)?;
    if url.scheme != crate::observe::Scheme::Http {
        return Err("only plain http is forwarded; https comes as CONNECT".to_string());
    }
    // To the server goes the path only, and the connection carries this
    // one request: a browser reuses a proxy connection for other hosts,
    // which must each be decided for themselves.
    let mut forward = format!("{method} {} {version}\r\n", url.path).into_bytes();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let name = line.split(':').next().unwrap_or_default().trim();
        if name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("proxy-authorization")
        {
            continue;
        }
        forward.extend_from_slice(line.as_bytes());
        forward.extend_from_slice(b"\r\n");
    }
    forward.extend_from_slice(b"Connection: close\r\n\r\n");
    forward.extend_from_slice(rest);
    Ok(Asked {
        host: url.host,
        port: url.port,
        tunnel: false,
        forward,
    })
}

fn ms(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Decide what the mode allows for this destination, and open the
/// connection when it allows one.
async fn route(host: &str, port: u16, shared: &Shared) -> (ProxyOutcome, Option<TcpStream>) {
    let config = &shared.config;
    let only_v6 = config.mode == Mode::V6only;
    let refused = |reason, message: String| (ProxyOutcome::Refused { reason, message }, None);

    // A destination written as an address is never looked up.
    let candidates: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(literal) => {
            if only_v6 && literal.is_ipv4() {
                return refused(
                    RefusalReason::LiteralIpv4,
                    format!("{literal} is an IPv4 address, and this network has no IPv4"),
                );
            }
            vec![literal]
        }
        Err(_) => {
            let found = match shared.resolver.addresses(host).await {
                Ok(found) => found,
                Err(why) => {
                    return (
                        ProxyOutcome::Failed {
                            stage: "resolve".to_string(),
                            message: printable(&why),
                            addresses: Vec::new(),
                        },
                        None,
                    );
                }
            };
            let (v6, v4): (Vec<IpAddr>, Vec<IpAddr>) = found.iter().partition(|a| a.is_ipv6());
            if only_v6 && v6.is_empty() {
                return refused(
                    RefusalReason::NoIpv6Address,
                    format!("{host} has no IPv6 address"),
                );
            }
            // IPv6 first, as a client that has both prefers it.
            let v4 = if only_v6 { Vec::new() } else { v4 };
            v6.into_iter()
                .take(MAX_ADDRESSES)
                .chain(v4.into_iter().take(MAX_ADDRESSES))
                .collect()
        }
    };

    let mut tried = Vec::new();
    let mut last_error = String::new();
    let mut not_public = None;
    for address in candidates {
        if let Some(why) = refusal(address, config.allow_private) {
            not_public = Some(why);
            continue;
        }
        tried.push(address);
        // In `dual`, a slow IPv6 address gives way to IPv4 sooner.
        let patience = if !only_v6 && address.is_ipv6() {
            config.fallback_after.min(config.connect_timeout)
        } else {
            config.connect_timeout
        };
        let started = Instant::now();
        let target = SocketAddr::new(address, port);
        match tokio::time::timeout(patience, TcpStream::connect(target)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return (
                    ProxyOutcome::Connected {
                        address,
                        family: Family::of(&address),
                        ms: ms(started),
                    },
                    Some(stream),
                );
            }
            Ok(Err(e)) => last_error = format!("{address}: {e}"),
            Err(_) => last_error = format!("{address}: no answer in {} ms", patience.as_millis()),
        }
    }
    match (tried.is_empty(), not_public) {
        (true, Some(why)) => refused(RefusalReason::NotPublic, why),
        _ => (
            ProxyOutcome::Failed {
                stage: "connect".to_string(),
                message: last_error,
                addresses: tried,
            },
            None,
        ),
    }
}

async fn reply(stream: &mut TcpStream, status: &str, why: &str) {
    // The reason is for a person looking at the browser's network log.
    let why: String = printable(why).chars().take(200).collect();
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\nX-V6blick: {why}\r\n\r\n"
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.shutdown().await;
}

async fn serve(mut browser: TcpStream, shared: &Shared) {
    // The head of the request, and whatever came with it.
    let mut buf = Vec::new();
    let head_end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if buf.len() > MAX_HEAD {
            return reply(
                &mut browser,
                "431 Request Header Fields Too Large",
                "head too large",
            )
            .await;
        }
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(shared.config.head_timeout, browser.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => return,
        }
    };
    let asked = match parse(&buf[..head_end], &buf[head_end..]) {
        Ok(asked) => asked,
        Err(why) => return reply(&mut browser, "400 Bad Request", &why).await,
    };

    let (outcome, server) = route(&asked.host, asked.port, shared).await;
    let said = match &outcome {
        ProxyOutcome::Connected { .. } => String::new(),
        ProxyOutcome::Refused { message, .. } | ProxyOutcome::Failed { message, .. } => {
            message.clone()
        }
    };
    shared
        .records
        .lock()
        .expect("lock")
        .push(ProxiedConnection {
            host: asked.host.clone(),
            port: asked.port,
            tunnel: asked.tunnel,
            outcome,
        });
    let Some(mut server) = server else {
        return reply(&mut browser, "502 Bad Gateway", &said).await;
    };

    if asked.tunnel {
        if browser
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        // Anything the browser sent after its CONNECT belongs to the tunnel.
        if server.write_all(&buf[head_end..]).await.is_err() {
            return;
        }
    } else if server.write_all(&asked.forward).await.is_err() {
        return reply(
            &mut browser,
            "502 Bad Gateway",
            "the server closed the connection",
        )
        .await;
    }
    let _ = tokio::io::copy_bidirectional(&mut browser, &mut server).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connect_names_host_and_port() {
        let asked = parse(
            b"CONNECT Example.ORG:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n",
            b"",
        )
        .unwrap();
        assert_eq!(
            (asked.host.as_str(), asked.port, asked.tunnel),
            ("example.org", 443, true)
        );
        let asked = parse(b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n", b"").unwrap();
        assert_eq!((asked.host.as_str(), asked.port), ("2001:db8::1", 8443));
        let asked = parse(b"CONNECT 192.0.2.7:443 HTTP/1.1\r\n\r\n", b"").unwrap();
        assert_eq!(asked.host, "192.0.2.7");
    }

    #[test]
    fn a_plain_request_is_rewritten_for_the_server() {
        let head = b"GET http://example.org:8080/a?b=1 HTTP/1.1\r\nHost: example.org:8080\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n";
        let asked = parse(head, b"").unwrap();
        assert_eq!(
            (asked.host.as_str(), asked.port, asked.tunnel),
            ("example.org", 8080, false)
        );
        assert_eq!(
            String::from_utf8(asked.forward).unwrap(),
            "GET /a?b=1 HTTP/1.1\r\nHost: example.org:8080\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        // What came after the head goes along.
        let asked = parse(
            b"POST http://example.org/x HTTP/1.1\r\nContent-Length: 2\r\n\r\n",
            b"hi",
        )
        .unwrap();
        assert!(asked.forward.ends_with(b"\r\n\r\nhi"));
    }

    #[test]
    fn what_is_not_a_proxy_request_is_refused() {
        for bad in [
            &b"GET / HTTP/1.1\r\n\r\n"[..],
            b"GET https://example.org/ HTTP/1.1\r\n\r\n",
            b"CONNECT example.org HTTP/1.1 extra\r\n\r\n",
            b"CONNECT user@example.org:443 HTTP/1.1\r\n\r\n",
            b"get http://example.org/ HTTP/1.1\r\n\r\n",
            b"GET http://example.org/ SPDY/3\r\n\r\n",
            b"\xff\xfe\r\n\r\n",
            b"\r\n\r\n",
        ] {
            assert!(
                parse(bad, b"").is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
