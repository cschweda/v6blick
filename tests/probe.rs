//! The prober, against a local server with one IPv4 and one IPv6
//! listener. Nothing here leaves this machine.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::server::{Hosts, Site, V4, V6, serve};
use v6blick::observe::{AddressProbe, Connect, ExchangeOutcome, Family, Tls};
use v6blick::probe::http::Url;
use v6blick::probe::{ProbeConfig, probe_all};

fn local() -> ProbeConfig {
    ProbeConfig {
        allow_private: true,
        connect_timeout: Duration::from_secs(2),
        tls_timeout: Duration::from_secs(2),
        http_timeout: Duration::from_secs(2),
        ..ProbeConfig::default()
    }
}

async fn probe_with(url: &str, config: ProbeConfig, hosts: Hosts) -> (AddressProbe, AddressProbe) {
    let url = Url::parse(url).unwrap();
    let mut probes = probe_all(&[url], &[V4, V6], Arc::new(config), Arc::new(hosts))
        .await
        .unwrap();
    assert_eq!(probes.len(), 2);
    let v6 = probes.pop().unwrap();
    let v4 = probes.pop().unwrap();
    assert_eq!((v4.family, v6.family), (Family::Ipv4, Family::Ipv6));
    (v4, v6)
}

async fn probe(url: &str) -> (AddressProbe, AddressProbe) {
    probe_with(url, local(), Hosts::default()).await
}

const PAGE: &str = "<html><body><h1>Hello</h1></body></html>";

#[tokio::test]
async fn the_same_site_over_both_families_looks_the_same() {
    let site = Site::page(Some('a'), 200, PAGE);
    let port = serve(|_| (Some(site.clone()), Some(site))).await;
    let (v4, v6) = probe(&format!("https://localhost:{port}/")).await;

    for p in [&v4, &v6] {
        assert!(
            matches!(p.connect, Connect::Connected { .. }),
            "{:?}",
            p.connect
        );
        assert_eq!(p.port, port);
        let r = p.first_response().expect("a response");
        assert_eq!(
            (r.status, r.body_bytes, r.body_truncated),
            (200, PAGE.len() as u64, false)
        );
        assert_eq!(p.exchanges.len(), 1);
    }
    let cert4 = v4.tls.as_ref().unwrap().certificate().unwrap();
    let cert6 = v6.tls.as_ref().unwrap().certificate().unwrap();
    assert_eq!(cert4, cert6);
    assert_eq!(cert4.sha256.len(), 64);
    assert_eq!(cert4.names, ["*.v6blick.test", "localhost", "v6blick.test"]);
    assert!(cert4.covers_host);
    // The test certificates run until 2126.
    assert!(cert4.not_after_unix.unwrap() > 4_900_000_000);
    let (r4, r6) = (v4.first_response().unwrap(), v6.first_response().unwrap());
    assert_eq!(r4.body_sha256, r6.body_sha256);
    assert_eq!(r4.shape_sha256, r6.shape_sha256);
}

#[tokio::test]
async fn a_different_ipv6_listener_is_recorded_as_different() {
    let port = serve(|port| {
        (
            Some(Site::page(Some('a'), 200, PAGE)),
            Some(Site::page(Some('b'), 200, "unused").redirect(
                "/",
                301,
                &format!("https://localhost:{port}/old"),
            )),
        )
    })
    .await;
    let (v4, v6) = probe(&format!("https://localhost:{port}/")).await;
    let cert4 = v4.tls.as_ref().unwrap().certificate().unwrap();
    let cert6 = v6.tls.as_ref().unwrap().certificate().unwrap();
    assert_ne!(cert4.sha256, cert6.sha256);
    assert_eq!(v4.first_response().unwrap().status, 200);
    let first6 = v6.first_response().unwrap();
    assert_eq!(first6.status, 301);
    assert_eq!(
        first6.location.as_deref(),
        Some(format!("https://localhost:{port}/old").as_str())
    );
    // The redirect was followed on the IPv6 side, to a page that is not there.
    assert_eq!(v6.exchanges.len(), 2);
    assert_eq!(v6.exchanges[1].address, Some(V6));
    assert_eq!(v6.exchanges[1].response().unwrap().status, 404);
}

#[tokio::test]
async fn a_dead_ipv6_listener_is_a_refused_connection() {
    let port = serve(|_| (Some(Site::page(None, 200, PAGE)), None)).await;
    let (v4, v6) = probe(&format!("http://localhost:{port}/")).await;
    assert!(matches!(v4.connect, Connect::Connected { .. }));
    assert!(v4.tls.is_none());
    assert_eq!(v4.first_response().unwrap().status, 200);
    assert!(
        matches!(v6.connect, Connect::Refused { .. }),
        "{:?}",
        v6.connect
    );
    assert!(v6.connect.is_failure());
    assert!(v6.tls.is_none() && v6.exchanges.is_empty());
}

#[tokio::test]
async fn a_listener_that_does_not_speak_tls_is_a_failed_handshake() {
    let port = serve(|_| {
        (
            Some(Site::page(Some('a'), 200, PAGE)),
            Some(Site::page(None, 200, PAGE)),
        )
    })
    .await;
    let (v4, v6) = probe(&format!("https://localhost:{port}/")).await;
    assert!(matches!(v4.tls, Some(Tls::Ok { .. })));
    assert!(matches!(v6.connect, Connect::Connected { .. }));
    assert!(matches!(v6.tls, Some(Tls::Failed { .. })), "{:?}", v6.tls);
    assert!(v6.exchanges.is_empty());
}

#[tokio::test]
async fn a_silent_listener_ends_at_the_timeout() {
    let port = serve(|_| (Some(Site::page(None, 200, PAGE)), Some(Site::Silent))).await;
    let config = ProbeConfig {
        http_timeout: Duration::from_millis(300),
        ..local()
    };
    let url = format!("http://localhost:{port}/");
    let (_, v6) = probe_with(&url, config, Hosts::default()).await;
    assert!(matches!(v6.connect, Connect::Connected { .. }));
    match &v6.exchanges[0].outcome {
        ExchangeOutcome::Failed { stage, message } => {
            assert_eq!(stage, "http");
            assert!(message.contains("no complete response"), "{message}");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn private_addresses_are_not_contacted_without_the_flag() {
    let site = Site::page(None, 200, PAGE);
    let port = serve(|_| (Some(site.clone()), Some(site))).await;
    let url = format!("http://localhost:{port}/");
    let (v4, v6) = probe_with(&url, ProbeConfig::default(), Hosts::default()).await;
    for p in [&v4, &v6] {
        match &p.connect {
            Connect::NotProbed { reason } => {
                assert!(reason.contains("loopback") && reason.contains("--allow-private"))
            }
            other => panic!("{other:?}"),
        }
        assert!(p.exchanges.is_empty());
    }
}

#[tokio::test]
async fn redirects_are_followed_and_each_one_is_recorded() {
    let port = serve(|port| {
        let site = Site::page(None, 200, "unused")
            .redirect("/", 302, "/a")
            .redirect("/a", 301, &format!("http://localhost:{port}/b"))
            .route("/b", 200, &[], PAGE);
        (Some(site.clone()), Some(site))
    })
    .await;
    let (v4, v6) = probe(&format!("http://localhost:{port}/")).await;
    for p in [&v4, &v6] {
        let urls: Vec<&str> = p.exchanges.iter().map(|e| e.url.as_str()).collect();
        let base = format!("http://localhost:{port}");
        assert_eq!(
            urls,
            [format!("{base}/"), format!("{base}/a"), format!("{base}/b")]
        );
        // Every hop stayed on the address the probe started with.
        assert!(p.exchanges.iter().all(|e| e.address == Some(p.address)));
        let (last, response) = p.final_response().unwrap();
        assert_eq!((last.url.as_str(), response.status), (urls[2], 200));
    }
}

#[tokio::test]
async fn a_redirect_loop_and_too_many_redirects_both_end() {
    let port = serve(|_| {
        let mut site = Site::page(None, 200, "unused")
            .redirect("/", 302, "/loop")
            .redirect("/loop", 302, "/");
        for n in 0..10 {
            site = site.redirect(&format!("/n{n}"), 302, &format!("/n{}", n + 1));
        }
        (Some(site.clone()), Some(site))
    })
    .await;
    let (v4, _) = probe(&format!("http://localhost:{port}/")).await;
    assert_eq!(v4.exchanges.len(), 3);
    assert!(v4.final_response().is_none());
    match &v4.exchanges[2].outcome {
        ExchangeOutcome::Failed { message, .. } => assert!(message.contains("loop")),
        other => panic!("{other:?}"),
    }

    let (v4, _) = probe(&format!("http://localhost:{port}/n0")).await;
    // The first request and five redirects, and it stops there.
    assert_eq!(v4.exchanges.len(), 6);
    assert_eq!(v4.exchanges[5].response().unwrap().status, 302);
    assert!(v4.final_response().is_none());
}

#[tokio::test]
async fn a_redirect_to_another_host_stays_in_the_family() {
    // `both.v6blick.test` has both kinds of address, `old.v6blick.test`
    // only an IPv4 one.
    let port = serve(|port| {
        let site = Site::page(None, 200, "unused")
            .redirect("/", 302, &format!("http://both.v6blick.test:{port}/landed"))
            .redirect(
                "/old",
                302,
                &format!("http://old.v6blick.test:{port}/landed"),
            )
            .redirect("/gone", 302, &format!("http://gone.v6blick.test:{port}/"))
            .redirect("/literal", 302, &format!("http://127.0.0.1:{port}/landed"))
            .route("/landed", 200, &[], PAGE);
        (Some(site.clone()), Some(site))
    })
    .await;
    let hosts = || {
        Hosts::default()
            .with("both.v6blick.test", &[V4, V6])
            .with("old.v6blick.test", &[V4])
    };
    let base = format!("http://localhost:{port}");

    let (v4, v6) = probe_with(&format!("{base}/"), local(), hosts()).await;
    assert_eq!(v4.exchanges[1].address, Some(V4));
    assert_eq!(v6.exchanges[1].address, Some(V6));
    assert_eq!(v6.final_response().unwrap().1.status, 200);

    let failure = |p: &AddressProbe| match &p.exchanges.last().unwrap().outcome {
        ExchangeOutcome::Failed { stage, message } => (stage.clone(), message.clone()),
        other => panic!("{other:?}"),
    };
    let (v4, v6) = probe_with(&format!("{base}/old"), local(), hosts()).await;
    assert_eq!(v4.final_response().unwrap().1.status, 200);
    let (stage, message) = failure(&v6);
    assert_eq!(stage, "resolve");
    assert_eq!(message, "old.v6blick.test has no IPv6 address");

    let (_, v6) = probe_with(&format!("{base}/gone"), local(), hosts()).await;
    assert!(failure(&v6).1.contains("cannot be resolved"));

    let (v4, v6) = probe_with(&format!("{base}/literal"), local(), hosts()).await;
    assert_eq!(v4.final_response().unwrap().1.status, 200);
    assert!(failure(&v6).1.contains("cannot be reached over IPv6"));
}

#[tokio::test]
async fn the_destination_rule_also_holds_for_redirects() {
    // A local test server can only be reached with private destinations
    // allowed, so this uses a kind of address that is refused either
    // way: one from a documentation range. Nothing is sent to it.
    let port = serve(|port| {
        let site = Site::page(None, 200, "unused").redirect(
            "/",
            302,
            &format!("http://elsewhere.v6blick.test:{port}/admin"),
        );
        (Some(site.clone()), Some(site))
    })
    .await;
    let hosts = Hosts::default().with("elsewhere.v6blick.test", &["192.0.2.7".parse().unwrap()]);
    let url = format!("http://localhost:{port}/");
    let (v4, _) = probe_with(&url, local(), hosts).await;
    assert_eq!(v4.exchanges.len(), 2);
    match &v4.exchanges[1].outcome {
        ExchangeOutcome::Failed { stage, message } => {
            assert_eq!(stage, "refused");
            assert!(message.contains("documentation"), "{message}");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_long_body_is_cut_at_the_limit() {
    let long = "x".repeat(5000);
    let site = Site::page(None, 200, &long);
    let port = serve(|_| (Some(site.clone()), Some(site))).await;
    let config = ProbeConfig {
        body_limit: 1000,
        ..local()
    };
    let url = format!("http://localhost:{port}/");
    let (v4, _) = probe_with(&url, config, Hosts::default()).await;
    let r = v4.first_response().unwrap();
    assert_eq!((r.body_bytes, r.body_truncated), (1000, true));
}

#[tokio::test]
async fn the_request_is_a_get_that_names_v6blick() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind((V4, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await;
        String::from_utf8_lossy(&buf[..n]).to_string()
    });
    let url = Url::parse(&format!("http://localhost:{port}/x?y=1")).unwrap();
    probe_all(&[url], &[V4], Arc::new(local()), Arc::new(Hosts::default()))
        .await
        .unwrap();
    let request = seen.await.unwrap();
    assert!(request.starts_with("GET /x?y=1 HTTP/1.1\r\n"), "{request}");
    assert!(request.contains(&format!("\r\nHost: localhost:{port}\r\n")));
    assert!(request.contains("\r\nUser-Agent: v6blick/"), "{request}");
}
