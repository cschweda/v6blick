//! The page test. The checks are run again on recorded page loads; the
//! tests that start a browser are ignored by default.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use common::World;
use common::server::{Site, serve};
use v6blick::checks::pge;
use v6blick::cli::{RunError, report_page};
use v6blick::doctor::{chrome_candidates, find_chrome};
use v6blick::observe::{Mode, PageObservation, QType};
use v6blick::output::{PageReport, exit, json};
use v6blick::page::{PageSettings, observe_page};
use v6blick::resolve::{Client, NetConfig};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn chrome() -> PathBuf {
    let candidates = chrome_candidates(|name| std::env::var_os(name));
    find_chrome(&candidates)
        .cloned()
        .expect("these tests need Chrome or Chromium")
}

/// A saved `page --json` document holds both page loads, so the checks
/// can be run on it again, and must come to what was saved.
fn replay(name: &str) -> (serde_json::Value, serde_json::Value, String) {
    let text = std::fs::read_to_string(fixture(name)).unwrap();
    let saved: serde_json::Value = serde_json::from_str(&text).unwrap();
    let observation: PageObservation = serde_json::from_str(&text).unwrap();
    let out = report_page("replayed", Ok(observation.clone()), false, false);
    let findings = pge::check(&observation);
    let again = PageReport::new(observation, findings);
    let mut again: serde_json::Value = serde_json::from_str(&json::render(&again)).unwrap();
    again["version"] = saved["version"].clone();
    (saved, again, out.stdout)
}

#[test]
fn a_recorded_page_that_redirects_to_a_host_without_ipv6_is_pge_01() {
    // www.metaincognita.com answers over IPv6 and redirects to
    // metaincognita.com, which has no AAAA record. Recorded 2026-11-14.
    let (saved, again, text) = replay("www.metaincognita.com.page.json");
    assert_eq!(saved, again);
    let findings = again["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["check_id"], "PGE-01");
    assert_eq!(findings[0]["severity"], "critical");
    assert_eq!(findings[0]["name"], "metaincognita.com");
    assert_eq!(
        findings[0]["summary"],
        "the page cannot be loaded on an IPv6-only network: it redirects to https://metaincognita.com/, and metaincognita.com has no IPv6 address"
    );
    assert_eq!(again["exit_code"], 2);
    // The browser's own traffic was held back in both loads.
    for load in again["loads"].as_array().unwrap() {
        for c in load["connections"].as_array().unwrap() {
            let host = c["host"].as_str().unwrap();
            if host.ends_with("google.com") || host.ends_with("gstatic.com") {
                assert_eq!(c["reason"], "not_asked_by_page", "{host}");
            }
        }
    }

    assert!(
        text.starts_with("v6blick page https://www.metaincognita.com/\n"),
        "{text}"
    );
    assert!(text.contains("  dual   "), "{text}");
    assert!(text.contains("  v6only "), "{text}");
    assert!(text.contains("CRITICAL (1)  broken now for visitors who use IPv6"));
    assert!(text.contains("PGE-01  metaincognita.com"));
    assert!(text.contains("redirected from https://www.metaincognita.com/"));
    assert!(text.contains("Means: A visitor on an IPv6-only network"));
    assert!(text.ends_with("Summary: 1 critical, 0 warning, 0 notice, 0 info\n"));
}

#[test]
fn a_recorded_page_that_loads_alike_checks_clean_again() {
    let (saved, again, text) = replay("zoneblick.com.page.json");
    assert_eq!(saved, again);
    assert_eq!(again["findings"].as_array().unwrap().len(), 0);
    assert_eq!(again["exit_code"], 0);
    let loads = again["loads"].as_array().unwrap();
    assert_eq!(loads.len(), 2);
    assert_eq!(
        (loads[0]["mode"].as_str(), loads[1]["mode"].as_str()),
        (Some("dual"), Some("v6only"))
    );
    assert!(text.contains("None. All checks passed."), "{text}");
    assert!(text.contains("third party"), "{text}");
}

#[tokio::test]
async fn without_ipv6_on_this_machine_no_browser_is_started() {
    // The root answers over IPv4 only. The browser path does not exist,
    // so starting it would fail differently.
    let mut world = World::default();
    world.answer(
        common::ROOT_V4,
        ".",
        QType::Ns,
        &[common::ns(".", "a.root-servers.net.")],
    );
    let settings = PageSettings::new(PathBuf::from("/nonexistent/chrome"), Mode::V6only);
    let outcome = observe_page("https://example.org/", world.client(), settings).await;
    assert!(
        matches!(outcome, Err(RunError::NoIpv6 { .. })),
        "{outcome:?}"
    );
    let out = report_page("https://example.org/", outcome, true, false);
    assert_eq!(out.exit_code, exit::RUN_FAILED);
    let doc: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(doc["error"]["kind"], "no_ipv6");
}

#[tokio::test]
async fn a_browser_that_cannot_be_started_is_a_failed_run() {
    let settings = PageSettings {
        allow_private: true,
        ..PageSettings::new(PathBuf::from("/nonexistent/chrome"), Mode::V6only)
    };
    let outcome = observe_page("http://localhost:1/", World::new().client(), settings).await;
    match &outcome {
        Err(RunError::Browser(why)) => assert!(why.contains("cannot be started"), "{why}"),
        other => panic!("{other:?}"),
    }
}

/// A DNS world in which three names lead to this machine: the page's
/// host with both kinds of address, and two hosts with IPv4 only, one of
/// the page's own site and one of another.
fn local_world() -> World {
    let mut w = World::new();
    let glue = [("ns1.shop.example.", "192.0.2.53")];
    let other = [("ns1.widgets.example.", "192.0.2.54")];
    for (name, zone, glue, server, has_v6) in [
        (
            "www.shop.example.",
            "shop.example.",
            &glue,
            "192.0.2.53",
            true,
        ),
        (
            "static.shop.example.",
            "shop.example.",
            &glue,
            "192.0.2.53",
            false,
        ),
        (
            "cdn.widgets.example.",
            "widgets.example.",
            &other,
            "192.0.2.54",
            false,
        ),
    ] {
        for qtype in [QType::A, QType::Aaaa] {
            w.delegate(name, qtype, zone, glue);
        }
        w.answer(server, name, QType::A, &[common::addr(name, "127.0.0.1")]);
        if has_v6 {
            w.answer(server, name, QType::Aaaa, &[common::addr(name, "::1")]);
        } else {
            w.nodata(server, name, QType::Aaaa, zone);
        }
    }
    w
}

/// The whole thing, with a real browser and nothing beyond this machine:
/// a page whose stylesheet and script come from hosts without IPv6.
#[tokio::test]
#[ignore = "starts Chrome or Chromium"]
async fn a_page_with_ipv4_only_resources_gets_pge_02_for_each_host() {
    let port = serve(|port| {
        let page = format!(
            "<html><head><title>Shop</title>\
             <link rel=\"stylesheet\" href=\"http://static.shop.example:{port}/site.css\">\
             <script src=\"http://cdn.widgets.example:{port}/w.js\"></script>\
             </head><body><h1>Shop</h1><img src=\"/logo.png\"></body></html>"
        );
        let site = Site::page(None, 200, &page)
            .route(
                "/site.css",
                200,
                &[("Content-Type", "text/css")],
                "h1{color:red}",
            )
            .route(
                "/w.js",
                200,
                &[("Content-Type", "text/javascript")],
                "var w=1;",
            )
            .route("/logo.png", 200, &[("Content-Type", "image/png")], "png");
        (Some(site.clone()), Some(site))
    })
    .await;
    let settings = PageSettings {
        allow_private: true,
        ..PageSettings::new(chrome(), Mode::V6only)
    };
    let target = format!("http://www.shop.example:{port}/");
    let obs = observe_page(&target, local_world().client(), settings)
        .await
        .unwrap();

    let dual = obs.load(Mode::Dual).unwrap();
    // The page, its stylesheet, its script and its image. The browser
    // also asks for a favicon, which is not counted here.
    let asked = |r: &&v6blick::observe::PageRequest| !r.url.ends_with("/favicon.ico");
    assert_eq!(
        dual.requests
            .iter()
            .filter(asked)
            .filter(|r| r.answered())
            .count(),
        4,
        "{dual:?}"
    );
    let v6only = obs.load(Mode::V6only).unwrap();
    assert!(v6only.document().unwrap().answered());
    assert_eq!(
        v6only
            .requests
            .iter()
            .filter(|r| r.failed().is_some())
            .count(),
        2
    );

    let findings = pge::check(&obs);
    let found: Vec<(&str, &str, &str)> = findings
        .iter()
        .map(|f| (f.check_id.as_str(), f.severity.as_str(), f.name.as_str()))
        .collect();
    assert_eq!(
        found,
        [
            ("PGE-02", "warning", "static.shop.example"),
            ("PGE-02", "notice", "cdn.widgets.example"),
        ]
    );
    let out = report_page(&target, Ok(obs), false, false);
    assert_eq!(out.exit_code, exit::FINDINGS);
    assert!(
        out.stdout
            .contains("static.shop.example has no IPv6 address"),
        "{}",
        out.stdout
    );
}

/// Writes the two fixtures above again. Needs the network and a browser.
/// Run with `cargo test --test page record_page_fixtures -- --ignored`.
#[tokio::test]
#[ignore = "uses the live network, starts a browser and rewrites tests/fixtures"]
async fn record_page_fixtures() {
    for (host, file) in [
        ("www.metaincognita.com", "www.metaincognita.com.page.json"),
        ("zoneblick.com", "zoneblick.com.page.json"),
    ] {
        let live = Arc::new(Client::live(NetConfig {
            max_queries: 5000,
            ..NetConfig::default()
        }));
        let settings = PageSettings::new(chrome(), Mode::V6only);
        let outcome = observe_page(host, live, settings).await;
        let out = report_page(host, outcome, true, false);
        std::fs::write(fixture(file), out.stdout).unwrap();
    }
}
