//! Red team: the prober against hostile web servers written on raw
//! sockets. Nothing here leaves this machine: the servers listen on
//! loopback, or, for the tests of the private-address rule, on this
//! machine's own public IPv6 address (those tests skip themselves when it
//! has none).
//!
//! Every test asserts the SAFE behaviour. The ones marked `DEFECT` fail
//! at commit 595371b; the ones marked `HELD` pass.

mod common;

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::server::{Hosts, V4, V6};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use v6blick::observe::{AddressProbe, ExchangeOutcome, special_use};
use v6blick::probe::http::Url;
use v6blick::probe::{BoxFuture, ProbeConfig, Resolve, probe_all};

type Handler =
    Arc<dyn Fn(TcpStream, String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Read a request head and return its path.
async fn request_path(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut chunk = [0u8; 2048];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") && request.len() < 64 * 1024 {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => request.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&request)
        .split(' ')
        .nth(1)
        .unwrap_or("/")
        .to_string()
}

/// Listen on `addresses` (one port for all of them) and hand every
/// connection, with the path it asked for, to `handler`.
async fn hostile(addresses: &[IpAddr], handler: Handler) -> u16 {
    'ports: for _ in 0..50 {
        let first = TcpListener::bind(SocketAddr::new(addresses[0], 0))
            .await
            .unwrap();
        let port = first.local_addr().unwrap().port();
        let mut listeners = vec![first];
        for address in &addresses[1..] {
            match TcpListener::bind(SocketAddr::new(*address, port)).await {
                Ok(listener) => listeners.push(listener),
                Err(_) => continue 'ports,
            }
        }
        for listener in listeners {
            let handler = handler.clone();
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        let path = request_path(&mut stream).await;
                        handler(stream, path).await;
                    });
                }
            });
        }
        return port;
    }
    panic!("no free port");
}

fn handler<F, Fut>(f: F) -> Handler
where
    F: Fn(TcpStream, String) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    Arc::new(move |stream, path| Box::pin(f(stream, path)))
}

/// A listener on every address of this machine that counts connections:
/// what a redirect must never reach.
async fn canary() -> (u16, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let v4 = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .await
        .unwrap();
    let port = v4.local_addr().unwrap().port();
    // An IPv6 wildcard may or may not also take IPv4; either is fine.
    let v6 = TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)).await;
    for listener in [Some(v4), v6.ok()].into_iter().flatten() {
        let hits = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                hits.fetch_add(1, Ordering::SeqCst);
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecret")
                    .await;
            }
        });
    }
    (port, hits)
}

fn quick(allow_private: bool) -> ProbeConfig {
    ProbeConfig {
        allow_private,
        connect_timeout: Duration::from_secs(1),
        tls_timeout: Duration::from_secs(1),
        http_timeout: Duration::from_secs(1),
        ..ProbeConfig::default()
    }
}

async fn probe_one(
    url: &str,
    address: IpAddr,
    config: ProbeConfig,
    hosts: Arc<dyn Resolve>,
) -> AddressProbe {
    let url = Url::parse(url).unwrap();
    probe_all(&[url], &[address], Arc::new(config), hosts)
        .await
        .unwrap()
        .pop()
        .unwrap()
}

fn last_failure(probe: &AddressProbe) -> (String, String) {
    match &probe.exchanges.last().expect("an exchange").outcome {
        ExchangeOutcome::Failed { stage, message } => (stage.clone(), message.clone()),
        ExchangeOutcome::Response(r) => panic!("the chain ended in a response: {r:?}"),
    }
}

/// A resolver that answers from a table and remembers what it was asked.
#[derive(Default)]
struct Asked {
    table: Hosts,
    asked: Mutex<Vec<String>>,
}

impl Resolve for Asked {
    fn addresses<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, String>> {
        self.asked.lock().unwrap().push(host.to_string());
        self.table.addresses(host)
    }
}

/// This machine's own public IPv6 address, when it has one. A listener
/// there is reached without `--allow-private` and without leaving the
/// machine.
fn public_v6() -> Option<IpAddr> {
    let root: IpAddr = "2001:503:ba3e::2:30".parse().unwrap();
    // Nothing is sent: connecting a UDP socket only asks for a route.
    let own = v6blick::doctor::source_address(root)?;
    (special_use(own).is_none() && std::net::TcpListener::bind(SocketAddr::new(own, 0)).is_ok())
        .then_some(own)
}

// ------------------------------------------------------------------ HELD

/// HELD. Without `--allow-private`, a public server cannot redirect the
/// prober to loopback, by literal address, by name, or by any spelling.
/// The canary listens on every address of this machine and sees nothing.
#[tokio::test]
async fn held_a_public_server_cannot_redirect_to_loopback() {
    let Some(own) = public_v6() else {
        eprintln!("SKIPPED: this machine has no public IPv6 address to listen on");
        return;
    };
    let (secret, hits) = canary().await;
    let locations = [
        format!("http://127.0.0.1:{secret}/"),
        format!("http://[::1]:{secret}/"),
        format!("http://[0:0:0:0:0:0:0:1]:{secret}/"),
        format!("http://[::ffff:127.0.0.1]:{secret}/"),
        format!("http://[::ffff:7f00:1]:{secret}/"),
        format!("http://[::127.0.0.1]:{secret}/"),
        format!("http://[::]:{secret}/"),
        format!("http://0.0.0.0:{secret}/"),
        format!("http://0:{secret}/"),
        format!("http://2130706433:{secret}/"),
        format!("http://0x7f.1:{secret}/"),
        format!("http://127.1:{secret}/"),
        format!("http://localhost:{secret}/"),
        format!("http://LOCALHOST.:{secret}/"),
        format!("http://rebind.test:{secret}/"),
        format!("http://mapped.test:{secret}/"),
        format!("http://linklocal.test:{secret}/"),
        format!("http://ula.test:{secret}/"),
        format!("http://[fe80::1]:{secret}/"),
        format!("http://[fe80::1%25lo0]:{secret}/"),
        format!("http://169.254.169.254:{secret}/latest/meta-data/"),
        format!("//[::1]:{secret}/"),
        format!("http://[64:ff9b::7f00:1]:{secret}/"),
        format!("http://[2002:7f00:1::1]:{secret}/"),
    ];
    for location in locations {
        let to = location.clone();
        let port = hostile(
            &[own],
            handler(move |mut stream, _| {
                let to = to.clone();
                async move {
                    let head = format!(
                        "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\n\r\n"
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                }
            }),
        )
        .await;
        let resolver = Arc::new(Asked {
            table: Hosts::default()
                .with("localhost", &[V6, V4])
                .with("rebind.test", &[V6, V4])
                .with("mapped.test", &["::ffff:127.0.0.1".parse().unwrap()])
                .with("linklocal.test", &["fe80::1".parse().unwrap()])
                .with("ula.test", &["fd00::1".parse().unwrap()]),
            asked: Mutex::default(),
        });
        let probe = probe_one(
            &format!("http://site.test:{port}/"),
            own,
            quick(false),
            resolver.clone(),
        )
        .await;
        assert_eq!(probe.exchanges.len(), 2, "{location}: {probe:?}");
        assert_eq!(probe.exchanges[0].response().unwrap().status, 302);
        let (stage, message) = last_failure(&probe);
        assert!(
            ["refused", "resolve", "http"].contains(&stage.as_str()),
            "{location}: {stage}: {message}"
        );
        // An address is never handed to the resolver.
        for name in resolver.asked.lock().unwrap().iter() {
            assert!(
                name.parse::<IpAddr>().is_err(),
                "{location}: asked for {name}"
            );
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "a redirect reached loopback"
    );
}

/// HELD. Even with `--allow-private`, a redirect cannot reach this
/// machine through the unspecified address or an IPv4 address written as
/// IPv6, which the operating system would deliver to loopback.
#[tokio::test]
async fn held_never_allowed_spellings_stay_refused_with_the_flag() {
    let (secret, hits) = canary().await;
    for (address, location) in [
        (V4, format!("http://0.0.0.0:{secret}/")),
        (V6, format!("http://[::]:{secret}/")),
        (V6, format!("http://[::ffff:127.0.0.1]:{secret}/")),
        (V6, format!("http://[::127.0.0.1]:{secret}/")),
        (V6, format!("http://unspecified.test:{secret}/")),
        (V4, format!("http://unspecified.test:{secret}/")),
    ] {
        let to = location.clone();
        let port = hostile(
            &[V4, V6],
            handler(move |mut stream, _| {
                let to = to.clone();
                async move {
                    let head = format!(
                        "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\n\r\n"
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                }
            }),
        )
        .await;
        let hosts = Hosts::default().with(
            "unspecified.test",
            &["0.0.0.0".parse().unwrap(), "::".parse().unwrap()],
        );
        let probe = probe_one(
            &format!("http://site.test:{port}/"),
            address,
            quick(true),
            Arc::new(hosts),
        )
        .await;
        let (stage, message) = last_failure(&probe);
        assert_eq!(stage, "refused", "{location}: {message}");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// HELD. One request is bounded in time and memory whatever the server
/// sends: each of these ends within the response timeout (1 s here), and
/// no more than the body limit is kept.
#[tokio::test]
async fn held_one_request_is_bounded_in_time_and_memory() {
    type Case = (&'static str, Handler);
    let cases: Vec<Case> = vec![
        (
            "an endless header",
            handler(|mut s, _| async move {
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nX: ").await;
                while s.write_all(&[b'a'; 8192]).await.is_ok() {}
            }),
        ),
        (
            "endless interim responses",
            handler(|mut s, _| async move {
                while s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await.is_ok() {}
            }),
        ),
        (
            "an endless chunk-size line",
            handler(|mut s, _| async move {
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                    .await;
                while s.write_all(&[b'0'; 8192]).await.is_ok() {}
            }),
        ),
        (
            "tiny chunks for ever",
            handler(|mut s, _| async move {
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                    .await;
                while s.write_all(&b"1\r\nx\r\n".repeat(1024)).await.is_ok() {}
            }),
        ),
        (
            "an endless body",
            handler(|mut s, _| async move {
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
                while s.write_all(&[b'a'; 8192]).await.is_ok() {}
            }),
        ),
        (
            "a huge Content-Length",
            handler(|mut s, _| async move {
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n")
                    .await;
                while s.write_all(&[b'a'; 8192]).await.is_ok() {}
            }),
        ),
        (
            "a chunk near the top of u64",
            handler(|mut s, _| async move {
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nfffffffffffffffe\r\n")
                    .await;
                while s.write_all(&[b'a'; 8192]).await.is_ok() {}
            }),
        ),
        (
            "a body that trickles",
            handler(|mut s, _| async move {
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
                    .await;
                while s.write_all(b"a").await.is_ok() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }),
        ),
        (
            "a head that trickles",
            handler(|mut s, _| async move {
                while s.write_all(b"H").await.is_ok() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }),
        ),
        (
            "silence",
            handler(|s, _| async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(s);
            }),
        ),
    ];
    let limit = 64 * 1024;
    for (what, serve) in cases {
        let port = hostile(&[V4], serve).await;
        let config = ProbeConfig {
            body_limit: limit,
            ..quick(true)
        };
        let started = Instant::now();
        let probe = probe_one(
            &format!("http://localhost:{port}/"),
            V4,
            config,
            Arc::new(Hosts::default()),
        )
        .await;
        let took = started.elapsed();
        assert!(took < Duration::from_millis(1800), "{what} took {took:?}");
        assert_eq!(probe.exchanges.len(), 1, "{what}");
        if let Some(response) = probe.exchanges[0].response() {
            assert!(response.body_bytes <= limit as u64, "{what}");
            assert!(response.body_truncated, "{what}: {response:?}");
        }
    }
}

/// The paths a server on loopback is asked for when every answer is a
/// redirect to `location(n)`.
async fn paths_requested(
    location: impl Fn(usize) -> String + Send + Sync + 'static,
) -> Vec<String> {
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let log = seen.clone();
    let location = Arc::new(location);
    let port = hostile(
        &[V4],
        handler(move |mut s, path| {
            let (log, location) = (log.clone(), location.clone());
            async move {
                let n = log.lock().unwrap().len();
                log.lock().unwrap().push(path);
                let head = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\n\r\n",
                    location(n)
                );
                let _ = s.write_all(head.as_bytes()).await;
            }
        }),
    )
    .await;
    let probe = probe_one(
        &format!("http://localhost:{port}/"),
        V4,
        quick(true),
        Arc::new(Hosts::default()),
    )
    .await;
    let seen = seen.lock().unwrap().clone();
    assert_eq!(probe.exchanges.len(), seen.len());
    seen
}

/// HELD. At most five redirects are followed, and the request each hop
/// sends is a plain GET for the path the server named, percent-encoded:
/// a header written as percent-escapes stays in the path.
#[tokio::test]
async fn held_redirects_are_counted_and_requests_stay_plain() {
    let seen = paths_requested(|n| format!("/hop{n}/\u{e9}%0d%0aX-Injected:1?q=1")).await;
    assert_eq!(seen.len(), 6);
    assert_eq!(seen[0], "/");
    for (n, path) in seen.iter().enumerate().skip(1) {
        assert_eq!(path, &format!("/hop{}/%C3%A9%0d%0aX-Injected:1?q=1", n - 1));
    }
}

// ---------------------------------------------------------------- DEFECT

/// DEFECT (medium, time). There is no deadline over a probe or a run,
/// only one per step. A server that answers each request with a redirect
/// just inside the response timeout holds one probe for six times that
/// timeout. With the shipped settings (5 s TLS, 10 s response, six
/// requests a probe, sixteen probes four at a time) one hostile host
/// holds `check` for about six minutes, before any DNS time is counted.
///
/// The bound asserted here, connect + TLS + response timeout for one
/// probe, is the red team's suggestion; any overall deadline will do.
#[tokio::test]
async fn fixed_one_probe_is_held_for_six_response_timeouts() {
    let port = hostile(
        &[V4],
        handler(|mut s, path| async move {
            tokio::time::sleep(Duration::from_millis(800)).await;
            let head =
                format!("HTTP/1.1 302 Found\r\nLocation: {path}x\r\nContent-Length: 0\r\n\r\n");
            let _ = s.write_all(head.as_bytes()).await;
        }),
    )
    .await;
    let started = Instant::now();
    // Since the audit a probe has a deadline of its own, here 2 s.
    let config = ProbeConfig {
        probe_deadline: Duration::from_secs(2),
        ..quick(true)
    };
    let probe = probe_one(
        &format!("http://localhost:{port}/"),
        V4,
        config,
        Arc::new(Hosts::default()),
    )
    .await;
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(3),
        "the probe has 2 s and took {took:?}"
    );
    // The redirect that was under way when the time ran out says so.
    match &probe.exchanges.last().unwrap().outcome {
        v6blick::observe::ExchangeOutcome::Failed { stage, message } => {
            assert_eq!(stage, "deadline");
            assert!(message.contains("did not finish in 2 s"), "{message}");
        }
        other => panic!("{other:?}"),
    }
}

/// DEFECT (low to medium, false result). `Location` is made printable
/// BEFORE it is resolved, so the escape that is meant for the terminal
/// ends up in the request. A zero-width non-joiner, which Persian and
/// Indic URLs really carry, is requested as the literal text
/// `\u{200c}`; a C1 control as `\155`. The prober then asks for a page
/// the server never named, and reports where that led.
#[tokio::test]
async fn fixed_the_redirect_that_is_followed_is_the_one_the_server_sent() {
    let seen = paths_requested(|n| format!("/hop{n}/\u{200c}/\u{9b}")).await;
    assert!(seen.len() > 1);
    assert_eq!(seen[1], "/hop0/%E2%80%8C/%C2%9B", "asked for {:?}", seen[1]);
}
