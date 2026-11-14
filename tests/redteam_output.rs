//! Red team: what reaches the terminal, a CI log or the JSON document,
//! and whether a server can hide a difference from the checks. A whole
//! `check` run each time, offline: DNS from a hand-built world, the host
//! a raw-socket server on loopback.
//!
//! Every test asserts the SAFE behaviour. The ones marked `DEFECT` fail
//! at commit 595371b; the ones marked `HELD` pass.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::server::{V4, V6};
use common::{World, addr};
use hickory_proto::rr::rdata::CNAME;
use hickory_proto::rr::{Name, RData, Record};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use v6blick::checks::{self, Thresholds};
use v6blick::cli::{observe, report};
use v6blick::observe::QType;
use v6blick::probe::ProbeConfig;

fn local() -> ProbeConfig {
    ProbeConfig {
        allow_private: true,
        connect_timeout: Duration::from_secs(2),
        tls_timeout: Duration::from_secs(2),
        http_timeout: Duration::from_secs(2),
        ..ProbeConfig::default()
    }
}

/// Serve fixed bytes to every connection: `v4` on 127.0.0.1 and `v6` on
/// ::1, on one port.
async fn serve_bytes(v4: Vec<u8>, v6: Vec<u8>) -> u16 {
    for _ in 0..50 {
        let l4 = TcpListener::bind(SocketAddr::new(V4, 0)).await.unwrap();
        let port = l4.local_addr().unwrap().port();
        let Ok(l6) = TcpListener::bind(SocketAddr::new(V6, port)).await else {
            continue;
        };
        for (listener, bytes) in [(l4, v4), (l6, v6)] {
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let bytes = bytes.clone();
                    tokio::spawn(async move {
                        let mut request = Vec::new();
                        let mut chunk = [0u8; 2048];
                        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => request.extend_from_slice(&chunk[..n]),
                            }
                        }
                        let _ = stream.write_all(&bytes).await;
                        let _ = stream.shutdown().await;
                    });
                }
            });
        }
        return port;
    }
    panic!("no free port");
}

fn ok(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn redirect(location: &[u8]) -> Vec<u8> {
    [
        b"HTTP/1.1 302 Found\r\nLocation: ".as_slice(),
        location,
        b"\r\nContent-Length: 0\r\n\r\n",
    ]
    .concat()
}

/// Run `check` on a local server and return (text output, JSON output).
async fn outputs(target: &str) -> (String, String) {
    let text = report(
        target,
        observe(target, World::new().client(), local()).await,
        false,
        false,
    );
    let json = report(
        target,
        observe(target, World::new().client(), local()).await,
        true,
        false,
    );
    (text.stdout + &text.stderr, json.stdout + &json.stderr)
}

/// A character that moves the cursor, changes direction, or cannot be
/// seen: what must not reach a terminal from the network or from an
/// argument.
fn unsafe_char(c: char) -> bool {
    (c.is_control() && c != '\n')
        || matches!(
            c,
            '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{2060}'..='\u{2069}'
                | '\u{061c}'
                | '\u{feff}'
        )
}

fn assert_clean(what: &str, output: &str) {
    let bad: Vec<String> = output
        .chars()
        .filter(|c| unsafe_char(*c))
        .map(|c| format!("U+{:04X}", c as u32))
        .collect();
    assert!(bad.is_empty(), "{what} holds {bad:?}:\n{output:?}");
    // A line that starts with `::` or `##[` is a command to GitHub
    // Actions or Azure Pipelines.
    for line in output.lines() {
        let line = line.trim_start();
        assert!(
            !line.starts_with("::") && !line.starts_with("##"),
            "{what} has a line a CI runner reads as a command: {line:?}"
        );
    }
}

// ---------------------------------------------------------------- DEFECT

/// DEFECT (medium, output). The target is echoed as it was typed, on the
/// first line of the text output and as `target` in the JSON, without
/// passing through `printable`. `Url::parse` refuses bytes up to 0x20 and
/// 0x7f only, so a C1 control (U+009B is "CSI", the start of a terminal
/// control sequence, on terminals that honour C1) and direction
/// overrides get through whenever the run succeeds. In CI the target may
/// come from a pull request.
#[tokio::test]
async fn fixed_the_target_is_not_echoed_raw() {
    let page = ok("hello");
    let port = serve_bytes(page.clone(), page).await;
    let target = format!("http://localhost:{port}/\u{9b}2J\u{9b}31m\u{202e}gro.elpmaxe\u{85}");
    let (text, json) = outputs(&target).await;
    assert!(text.contains("Summary:"), "the run did not finish:\n{text}");
    assert_clean("the text output", &text);
    let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_clean("the JSON target", doc["target"].as_str().unwrap());
}

/// DEFECT (low, output). `printable` escapes control characters and the
/// direction overrides, and lets other invisible characters through:
/// the soft hyphen, the Hangul fillers, the Mongolian vowel separator,
/// variation selectors, interlinear annotation marks and the "tag"
/// characters. A `Location` can carry text that is in the log and
/// cannot be seen.
#[tokio::test]
async fn fixed_invisible_characters_from_a_server_are_escaped() {
    let hidden = [
        '\u{00ad}',
        '\u{034f}',
        '\u{115f}',
        '\u{1160}',
        '\u{17b4}',
        '\u{180e}',
        '\u{3164}',
        '\u{fe0f}',
        '\u{ffa0}',
        '\u{fff9}',
        '\u{e0001}',
        '\u{e0041}',
    ];
    let location: String = format!("/a{}b", hidden.iter().collect::<String>());
    // Only IPv6 redirects, so that the Location is printed as evidence.
    let port = serve_bytes(ok("hello"), redirect(location.as_bytes())).await;
    let (text, _) = outputs(&format!("http://localhost:{port}/")).await;
    assert!(text.contains("EQV-02"), "{text}");
    let leaked: Vec<String> = text
        .chars()
        .filter(|c| hidden.contains(c))
        .map(|c| format!("U+{:04X}", c as u32))
        .collect();
    assert!(leaked.is_empty(), "printed as they came: {leaked:?}");
}

/// DEFECT (low, output). A header value may be as long as the whole head
/// (64 KiB) and is printed in full, once per address in the evidence and
/// again in the JSON. One hostile `Location` makes one line of the log
/// tens of thousands of characters long.
#[tokio::test]
async fn fixed_a_long_location_does_not_flood_the_output() {
    let long = format!("/{}", "A".repeat(60_000));
    let page = ok("hello");
    let port = serve_bytes(page, redirect(long.as_bytes())).await;
    let (text, _) = outputs(&format!("http://localhost:{port}/")).await;
    assert!(text.contains("EQV-02"), "{}", &text[..text.len().min(2000)]);
    let longest = text.lines().map(str::len).max().unwrap_or(0);
    assert!(
        longest <= 4096,
        "the longest line has {longest} characters; the whole output {}",
        text.len()
    );
}

/// DEFECT (medium, false result: a real difference is hidden). EQV-03
/// compares the sequence of HTML tag names and the size. A body with no
/// tags has an empty sequence, so any two bodies that are not HTML and
/// are about the same size count as the same page: JSON, plain text, or
/// an error page from the same template. Here IPv4 says the service is
/// up and IPv6 says it is down, in the same number of bytes, and the run
/// is clean with exit code 0.
#[tokio::test]
async fn fixed_a_different_body_without_tags_is_a_finding() {
    let up = r#"{"status":"ok","database":"up","message":"all systems are working"}"#;
    let down = r#"{"status":"error","database":"down","message":"connection refused"}"#;
    assert_eq!(up.len(), down.len());
    let port = serve_bytes(ok(up), ok(down)).await;
    let target = format!("http://localhost:{port}/");
    let obs = observe(&target, World::new().client(), local())
        .await
        .unwrap();
    let ids: Vec<String> = checks::run_all(&obs, &Thresholds::default())
        .iter()
        .map(|f| f.check_id.clone())
        .collect();
    assert!(
        ids.contains(&"EQV-03".to_string()),
        "IPv4 served {up} and IPv6 served {down}; findings: {ids:?}"
    );
}

/// DEFECT (medium, false result: a real difference is hidden). The same
/// for HTML: only tag names count, so the IPv6 side can serve another
/// site built from the same few tags.
#[tokio::test]
async fn fixed_a_different_page_with_the_same_tags_is_a_finding() {
    let real = "<html><head><title>Example Bank</title></head><body><h1>Welcome back</h1><p>Sign in to your account at example.org.</p></body></html>";
    let fake = "<html><head><title>Site suspended</title></head><body><h1>Error 503</h1><p>This account has been disabled by the host</p></body></html>";
    assert!(real.len().abs_diff(fake.len()) < 20);
    let port = serve_bytes(ok(real), ok(fake)).await;
    let target = format!("http://localhost:{port}/");
    let obs = observe(&target, World::new().client(), local())
        .await
        .unwrap();
    let ids: Vec<String> = checks::run_all(&obs, &Thresholds::default())
        .iter()
        .map(|f| f.check_id.clone())
        .collect();
    assert!(ids.contains(&"EQV-03".to_string()), "findings: {ids:?}");
}

// ------------------------------------------------------------------ HELD

/// HELD. Control characters, escape sequences, C1 controls, direction
/// overrides, line separators and bytes that are not UTF-8 in a
/// `Location`, in a status line and in other headers do not reach the
/// text output or break the JSON.
#[tokio::test]
async fn held_hostile_header_bytes_do_not_reach_the_output() {
    let locations: Vec<Vec<u8>> = vec![
        b"/a\x1b[2J\x1b]0;owned\x07\x08\x08\x00b".to_vec(),
        "/a\u{9b}31m\u{85}\u{202e}\u{2028}\u{2029}\u{200b}\u{feff}b"
            .as_bytes()
            .to_vec(),
        b"/a\xff\xfe\xc0\x80b".to_vec(),
        b"http://exa\x1bmple.test/".to_vec(),
        "http://e\u{202e}vil.test/".as_bytes().to_vec(),
        b"/a\rb".to_vec(),
        b"/a\tb\x0bc\x0cd".to_vec(),
        b"ftp://\x1b[31m/".to_vec(),
        b"//\x1b[31m:99999/".to_vec(),
        b"/x\x1b[1A\x1b[2K::error::forged".to_vec(),
    ];
    for location in locations {
        let page = ok("hello");
        let port = serve_bytes(page, redirect(&location)).await;
        let (text, json) = outputs(&format!("http://localhost:{port}/")).await;
        assert!(text.contains("EQV-02"), "{text}");
        assert_clean("the text output", &text);
        let doc: serde_json::Value = serde_json::from_str(&json).expect("the JSON parses");
        assert_clean("the JSON, written out again", &doc.to_string());
    }
    // A status line and a header name with the same in them.
    for head in [
        &b"HTTP/1.1 200 \x1b[2J\r\nX-\x1b[31m: \x1b[2J\r\nContent-Length: 0\r\n\r\n"[..],
        b"HTTP/1.1 \x1b[2J\r\n\r\n",
        b"\x1b[2J\x1b[31mnot http at all\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\x1b[2J\r\n",
    ] {
        let port = serve_bytes(ok("hello"), head.to_vec()).await;
        let (text, json) = outputs(&format!("http://localhost:{port}/")).await;
        assert_clean("the text output", &text);
        serde_json::from_str::<serde_json::Value>(&json).expect("the JSON parses");
    }
}

/// HELD. A failed run quotes the target on one line, without control
/// characters, in text and in JSON.
#[tokio::test]
async fn held_a_refused_target_is_quoted_safely() {
    for target in [
        "exa\x1b[2Jmple.org",
        "http://exa\u{9b}mple.org/",
        "ftp://\x1b[31m/\nforged line",
        "example.org\n::error::forged",
        "http://[\x1b[2J]/",
        "http://example.org:\x1b[2J/",
    ] {
        for as_json in [false, true] {
            let outcome = observe(target, World::new().client(), local()).await;
            assert!(outcome.is_err(), "{target:?}");
            let out = report(target, outcome, as_json, false);
            let all = out.stdout + &out.stderr;
            if as_json {
                let doc: serde_json::Value = serde_json::from_str(&all).unwrap();
                assert_clean("the JSON error", doc["error"]["message"].as_str().unwrap());
                assert_clean("the JSON target", doc["target"].as_str().unwrap());
            } else {
                assert_eq!(all.lines().count(), 1, "{all:?}");
                assert_clean("the error line", &all);
            }
        }
    }
}

/// HELD. Names from the DNS are printed in presentation form: an alias
/// target whose labels hold an escape sequence, a newline, a C1 control
/// and a CI command comes out as backslash escapes.
#[tokio::test]
async fn held_hostile_dns_names_do_not_reach_the_output() {
    let labels: [&[u8]; 4] = [
        b"\x1b[2J\x1b[31m",
        b"a\nb\r::error::forged",
        "\u{9b}31m\u{202e}".as_bytes(),
        b"##vso[task.setvariable variable=x]y",
    ];
    for label in labels {
        let target = Name::from_labels(vec![label, b"evil".as_ref(), b"example".as_ref()]).unwrap();
        let mut world = World::new();
        let glue = [
            ("ns1.evil.example.", "192.0.2.53"),
            ("ns1.evil.example.", "2001:db8::53"),
        ];
        // The name leads to a local server, so that the run completes
        // and the names are printed. (Since the audit, a run in which no
        // address is contacted fails instead.)
        let site = common::server::Site::page(None, 200, "hello");
        let port = common::server::serve(|_| (Some(site.clone()), Some(site))).await;
        for (qtype, ip) in [(QType::A, "127.0.0.1"), (QType::Aaaa, "::1")] {
            world.delegate("www.evil.example.", qtype, "evil.example.", &glue);
            let alias = Record::from_rdata(
                common::name("www.evil.example."),
                60,
                RData::CNAME(CNAME(target.clone())),
            );
            let mut address = addr("www.evil.example.", ip);
            address.name = target.clone();
            for server in ["192.0.2.53", "2001:db8::53"] {
                world.answer(
                    server,
                    "www.evil.example.",
                    qtype,
                    &[alias.clone(), address.clone()],
                );
            }
        }
        let config = local();
        let target = format!("http://www.evil.example:{port}/");
        for as_json in [false, true] {
            let outcome = observe(&target, Arc::clone(&world.client()), config.clone()).await;
            let obs = outcome.as_ref().expect("the run completes");
            assert_eq!(obs.lookup.cname_chain.len(), 1);
            let out = report(&target, outcome, as_json, false);
            if as_json {
                let doc: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
                assert_clean("the JSON, written out again", &doc.to_string());
            } else {
                assert!(out.stdout.contains("is an alias for"), "{}", out.stdout);
                assert_clean("the text output", &out.stdout);
            }
        }
    }
}
