//! The mode proxy, between a hand-written client and a local server with
//! one IPv4 and one IPv6 listener. Nothing here leaves this machine.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::server::{Hosts, Site, V4, V6, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use v6blick::observe::{Family, Mode, ProxiedConnection, ProxyOutcome, RefusalReason};
use v6blick::proxy::{Proxy, ProxyConfig};

const PAGE: &str = "<html><body><h1>Hello</h1></body></html>";

fn hosts() -> Hosts {
    Hosts::default()
        .with("both.v6blick.test", &[V4, V6])
        .with("old.v6blick.test", &[V4])
}

async fn proxy(mode: Mode, allow_private: bool) -> Proxy {
    let config = ProxyConfig {
        allow_private,
        connect_timeout: Duration::from_secs(2),
        fallback_after: Duration::from_millis(500),
        ..ProxyConfig::new(mode)
    };
    Proxy::start(config, Arc::new(hosts())).await.unwrap()
}

/// Send `request` to the proxy and read until it closes.
async fn exchange(proxy: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).to_string()
}

async fn get(proxy: &Proxy, host: &str, port: u16) -> String {
    let request = format!("GET http://{host}:{port}/ HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    exchange(proxy.address(), &request).await
}

fn only(records: Vec<ProxiedConnection>) -> ProxiedConnection {
    assert_eq!(records.len(), 1, "{records:?}");
    records.into_iter().next().unwrap()
}

#[tokio::test]
async fn dual_prefers_ipv6_and_carries_the_request() {
    let site = Site::page(None, 200, PAGE);
    let port = serve(|_| (Some(site.clone()), Some(site))).await;
    let proxy = proxy(Mode::Dual, true).await;
    let response = get(&proxy, "both.v6blick.test", port).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with(PAGE));
    let record = only(proxy.finish());
    assert_eq!(
        (record.host.as_str(), record.port, record.tunnel),
        ("both.v6blick.test", port, false)
    );
    assert!(
        matches!(
            record.outcome,
            ProxyOutcome::Connected {
                family: Family::Ipv6,
                ..
            }
        ),
        "{:?}",
        record.outcome
    );
}

#[tokio::test]
async fn dual_falls_back_to_ipv4_when_ipv6_is_dead() {
    let port = serve(|_| (Some(Site::page(None, 200, PAGE)), None)).await;
    let proxy = proxy(Mode::Dual, true).await;
    let response = get(&proxy, "both.v6blick.test", port).await;
    assert!(response.ends_with(PAGE), "{response}");
    let record = only(proxy.finish());
    assert!(matches!(
        record.outcome,
        ProxyOutcome::Connected {
            family: Family::Ipv4,
            ..
        }
    ));
}

#[tokio::test]
async fn v6only_does_not_fall_back() {
    // The same site: fine in dual, unreachable without IPv4.
    let port = serve(|_| (Some(Site::page(None, 200, PAGE)), None)).await;
    let proxy = proxy(Mode::V6only, true).await;
    let response = get(&proxy, "both.v6blick.test", port).await;
    assert!(
        response.is_empty(),
        "a plain request is dropped: {response}"
    );
    match only(proxy.finish()).outcome {
        ProxyOutcome::Failed {
            stage, addresses, ..
        } => {
            assert_eq!(stage, "connect");
            assert_eq!(addresses, [V6]);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn v6only_refuses_a_host_without_an_ipv6_address() {
    let site = Site::page(None, 200, PAGE);
    let port = serve(|_| (Some(site.clone()), Some(site))).await;
    let proxy = proxy(Mode::V6only, true).await;
    let response = get(&proxy, "old.v6blick.test", port).await;
    assert!(
        response.is_empty(),
        "a plain request is dropped: {response}"
    );
    // A tunnel is refused with an answer that says why.
    let connect = format!("CONNECT old.v6blick.test:{port} HTTP/1.1\r\n\r\n");
    let refused = exchange(proxy.address(), &connect).await;
    assert!(refused.starts_with("HTTP/1.1 502"), "{refused}");
    assert!(
        refused.contains("X-V6blick: old.v6blick.test has no IPv6 address"),
        "{refused}"
    );
    for record in proxy.finish() {
        assert!(matches!(
            record.outcome,
            ProxyOutcome::Refused {
                reason: RefusalReason::NoIpv6Address,
                ..
            }
        ));
    }

    // In dual the same host is served over IPv4.
    let dual = self::proxy(Mode::Dual, true).await;
    assert!(get(&dual, "old.v6blick.test", port).await.ends_with(PAGE));
}

#[tokio::test]
async fn v6only_refuses_a_literal_ipv4_address_and_allows_a_literal_ipv6_one() {
    let site = Site::page(None, 200, PAGE);
    let port = serve(|_| (Some(site.clone()), Some(site))).await;
    let proxy = proxy(Mode::V6only, true).await;
    let response = get(&proxy, "127.0.0.1", port).await;
    assert!(
        response.is_empty(),
        "a plain request is dropped: {response}"
    );
    let response = get(&proxy, "[::1]", port).await;
    assert!(response.ends_with(PAGE), "{response}");
    let records = proxy.finish();
    assert!(matches!(
        records[0].outcome,
        ProxyOutcome::Refused {
            reason: RefusalReason::LiteralIpv4,
            ..
        }
    ));
    assert!(matches!(records[1].outcome, ProxyOutcome::Connected { .. }));
    assert_eq!(records[1].host, "::1");
}

#[tokio::test]
async fn private_destinations_need_the_flag() {
    let site = Site::page(None, 200, PAGE);
    let port = serve(|_| (Some(site.clone()), Some(site))).await;
    let proxy = proxy(Mode::Dual, false).await;
    for host in ["both.v6blick.test", "127.0.0.1", "[::1]"] {
        let response = get(&proxy, host, port).await;
        assert!(response.is_empty(), "{host}: {response}");
    }
    for record in proxy.finish() {
        match record.outcome {
            ProxyOutcome::Refused { reason, message } => {
                assert_eq!(reason, RefusalReason::NotPublic);
                assert!(message.contains("--allow-private"), "{message}");
            }
            other => panic!("{other:?}"),
        }
    }
}

#[tokio::test]
async fn a_name_that_does_not_resolve_is_a_failed_lookup() {
    let proxy = proxy(Mode::Dual, true).await;
    let response = get(&proxy, "nowhere.v6blick.test", 80).await;
    assert!(
        response.is_empty(),
        "a plain request is dropped: {response}"
    );
    match only(proxy.finish()).outcome {
        ProxyOutcome::Failed {
            stage, addresses, ..
        } => {
            assert_eq!(stage, "resolve");
            assert!(addresses.is_empty());
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_tunnel_carries_whatever_is_sent_through_it() {
    let site = Site::page(None, 200, PAGE);
    let port = serve(|_| (Some(site.clone()), Some(site))).await;
    let proxy = proxy(Mode::V6only, true).await;
    let mut stream = TcpStream::connect(proxy.address()).await.unwrap();
    let connect = format!(
        "CONNECT both.v6blick.test:{port} HTTP/1.1\r\nHost: both.v6blick.test:{port}\r\n\r\n"
    );
    stream.write_all(connect.as_bytes()).await.unwrap();
    let mut head = [0u8; 39];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(&head[..], b"HTTP/1.1 200 Connection Established\r\n\r\n");
    // Inside the tunnel the proxy reads nothing; here it is plain HTTP.
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out)).await;
    assert!(String::from_utf8_lossy(&out).ends_with(PAGE));
    let record = only(proxy.finish());
    assert!(record.tunnel);
    assert!(matches!(
        record.outcome,
        ProxyOutcome::Connected {
            family: Family::Ipv6,
            ..
        }
    ));
}

#[tokio::test]
async fn only_what_the_page_asked_for_is_carried() {
    use v6blick::proxy::Announced;
    let site = Site::page(None, 200, PAGE);
    let port = serve(|_| (Some(site.clone()), Some(site))).await;
    let announced = Arc::new(Announced::default());
    let config = ProxyConfig {
        allow_private: true,
        only: Some(announced.clone()),
        announce_wait: Duration::from_millis(300),
        ..ProxyConfig::new(Mode::Dual)
    };
    let proxy = Proxy::start(config, Arc::new(hosts())).await.unwrap();

    // Nobody announced the host: the browser wants it for itself.
    let response = get(&proxy, "both.v6blick.test", port).await;
    assert!(
        response.is_empty(),
        "a plain request is dropped: {response}"
    );

    // Announced a moment after the connection arrives: it waits for it.
    let later = announced.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        later.add("old.v6blick.test");
    });
    assert!(get(&proxy, "old.v6blick.test", port).await.ends_with(PAGE));
    // Announced already: no wait.
    assert!(get(&proxy, "old.v6blick.test", port).await.ends_with(PAGE));

    let records = proxy.finish();
    assert!(matches!(
        records[0].outcome,
        ProxyOutcome::Refused {
            reason: RefusalReason::NotAskedByPage,
            ..
        }
    ));
    assert!(matches!(records[1].outcome, ProxyOutcome::Connected { .. }));
}

#[tokio::test]
async fn what_is_not_a_proxy_request_gets_a_400_and_no_record() {
    let proxy = proxy(Mode::Dual, true).await;
    let response = exchange(proxy.address(), "GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(proxy.finish().is_empty());
}

#[tokio::test]
async fn the_proxy_stops_when_it_is_dropped() {
    let proxy = proxy(Mode::Dual, true).await;
    let address = proxy.address();
    drop(proxy);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(TcpStream::connect(address).await.is_err());
}
