//! Red team: the URL parser, `join`, the request builder, the response
//! reader, `shape` and the certificate reader, fed hostile bytes. Nothing
//! here touches the network.
//!
//! Every test asserts the SAFE behaviour. The ones marked `DEFECT` fail
//! at commit 595371b; the ones marked `HELD` pass.

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use v6blick::probe::cert;
use v6blick::probe::http::{Url, read_response, shape};
use v6blick::probe::targets;

/// A small deterministic generator, so that a failure can be replayed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

async fn read(wire: &[u8], limit: usize) -> Result<v6blick::probe::http::RawResponse, String> {
    let mut stream = wire;
    read_response(&mut stream, limit).await
}

// ---------------------------------------------------------------- DEFECT

/// DEFECT (medium, false result). A relative redirect whose query holds
/// an absolute URL is the usual shape of a login redirect
/// (`/login?next=https://example.org/account`). `join` refuses every
/// Location that contains `://` anywhere, so the chain ends in "the
/// redirect cannot be followed" on both families.
#[test]
fn fixed_a_relative_redirect_with_a_url_in_its_query_is_followed() {
    let base = Url::parse("https://example.org/a/b").unwrap();
    for (location, want) in [
        (
            "/login?next=https://example.org/account",
            "https://example.org/login?next=https://example.org/account",
        ),
        (
            "sso?return=http://example.org/",
            "https://example.org/a/sso?return=http://example.org/",
        ),
        (
            "?u=https://example.org/",
            "https://example.org/a/b?u=https://example.org/",
        ),
    ] {
        let joined = base.join(location).map(|u| u.to_string());
        assert_eq!(joined.as_deref(), Ok(want), "Location: {location}");
    }
}

/// DEFECT (low, false result). The 64 KiB head budget is reused for all
/// chunk-size lines of a body, so a chunked body of more than about 8000
/// chunks fails with "the response head is too large", well inside the
/// 1 MiB body limit.
#[tokio::test]
async fn fixed_a_chunked_body_in_many_small_chunks_is_read() {
    let mut wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for _ in 0..20_000 {
        wire.extend_from_slice(b"10\r\n0123456789abcdef\r\n");
    }
    wire.extend_from_slice(b"0\r\n\r\n");
    let response = read(&wire, 1024 * 1024).await;
    assert_eq!(response.map(|r| r.body.len()), Ok(320_000));
}

/// DEFECT (low, false result). A body that ends before its
/// `Content-Length`, or in the middle of a chunk, is recorded as a
/// complete response: no error, `truncated` false. The page a visitor
/// would see as broken is hashed and compared as if it were whole.
#[tokio::test]
async fn fixed_a_body_cut_short_is_not_a_complete_response() {
    let short = read(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort", 1024).await;
    assert!(
        short.is_err(),
        "5 of 100 bytes arrived and it was accepted: {short:?}"
    );
    let chunk = read(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n64\r\nabc",
        1024,
    )
    .await;
    assert!(
        chunk.is_err(),
        "3 of 100 chunk bytes arrived and it was accepted: {chunk:?}"
    );
    let no_last_chunk = read(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
        1024,
    )
    .await;
    assert!(
        no_last_chunk.is_err(),
        "the closing chunk never came: {no_last_chunk:?}"
    );
}

/// DEFECT (low, lax parsing). Authorities that no browser would read the
/// way `Url::parse` does. None reaches a private address (the address
/// check still runs), but they end up in the `Host` header and in the
/// output, and the junk after `]` is silently dropped.
#[test]
fn fixed_odd_authorities_are_refused() {
    for odd in [
        // host becomes "example.org:80", sent as `Host: [example.org:80]`
        "http://example.org:80:80/",
        // parsed as host ::1, "evil" dropped
        "http://[::1]evil/",
        "http://[2001:db8::1]evil.example:8080/",
        // an unbracketed IPv6 address
        "http://::1:80/",
        // u16::from_str takes a sign
        "http://example.org:+80/",
        // empty labels
        "http://a..b/",
    ] {
        assert!(
            Url::parse(odd).is_err(),
            "{odd} parsed as {:?}",
            Url::parse(odd)
        );
    }
}

// ------------------------------------------------------------------ HELD

/// HELD. Whatever `Url::parse` or `join` accepts, the request is one
/// plain GET: six lines, nothing but printable ASCII, two spaces in the
/// request line, and a `Host` that is the parsed host.
#[test]
fn held_no_url_or_location_puts_anything_into_the_request() {
    let pieces: &[&str] = &[
        "http://",
        "https://",
        "HTTP://",
        "//",
        "/",
        "\\",
        "?",
        "#",
        "@",
        ":",
        "[",
        "]",
        ".",
        "..",
        "%0d%0a",
        "%20",
        "%",
        "\r\n",
        "\r",
        "\n",
        "\t",
        " ",
        "\0",
        "\u{7f}",
        "\u{85}",
        "\u{9b}",
        "\u{202e}",
        "\u{2028}",
        "\u{a0}",
        "é",
        "example.org",
        "evil.example",
        "localhost",
        "127.0.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "0",
        "80",
        "65536",
        "a",
        "Host: evil.example",
        "X-Injected: 1",
        " HTTP/1.1",
        "GET ",
        "-",
        "_",
        "javascript:",
        "data:",
    ];
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let base = Url::parse("https://example.org/a/b?c=d").unwrap();
    let mut accepted = 0usize;
    for _ in 0..400_000 {
        let mut text = String::new();
        for _ in 0..1 + rng.below(8) {
            text.push_str(rng.pick(pieces));
        }
        let mut urls = Vec::new();
        urls.extend(Url::parse(&text).ok());
        urls.extend(base.join(&text).ok());
        urls.extend(targets(&text).ok().into_iter().flatten());
        for url in urls {
            accepted += 1;
            let request = url.request("v6blick/test");
            assert!(
                request
                    .iter()
                    .all(|b| (0x20..0x7f).contains(b) || *b == b'\r' || *b == b'\n'),
                "{text:?} put a raw byte into the request"
            );
            let request = String::from_utf8(request).unwrap();
            let lines: Vec<&str> = request.split("\r\n").collect();
            assert_eq!(lines.len(), 8, "{text:?} -> {request:?}");
            assert!(!request.replace("\r\n", "").contains(['\r', '\n']));
            assert_eq!(lines[0].matches(' ').count(), 2, "{text:?} -> {request:?}");
            assert!(lines[0].starts_with("GET /") && lines[0].ends_with(" HTTP/1.1"));
            assert_eq!(lines[1], format!("Host: {}", url.host_header()));
            assert!(!url.host_header().contains([' ', '/', '@', '\\', '%']));
            assert_eq!(
                &lines[2..],
                [
                    "User-Agent: v6blick/test",
                    "Accept: */*",
                    "Accept-Encoding: identity",
                    "Connection: close",
                    "",
                    ""
                ]
            );
            // What is printed for a URL is printable ASCII too.
            assert!(url.to_string().bytes().all(|b| (0x21..0x7f).contains(&b)));
        }
    }
    assert!(accepted > 10_000, "only {accepted} inputs were accepted");
}

/// HELD. Addresses written in ways only `inet_aton` reads are host names
/// to `Url::parse`, never addresses; an address is always seen as one
/// (so that the private-address rule sees it); a zone id is refused.
#[test]
fn held_address_spellings() {
    for name in [
        "http://2130706433/",
        "http://0x7f.1/",
        "http://127.1/",
        "http://0177.0.0.1/",
        "http://0/",
    ] {
        let url = Url::parse(name).unwrap();
        assert_eq!(url.host_ip(), None, "{name}");
    }
    for (literal, ip) in [
        ("http://127.0.0.1/", "127.0.0.1"),
        ("http://0.0.0.0/", "0.0.0.0"),
        ("http://[::1]/", "::1"),
        ("http://[::ffff:127.0.0.1]/", "::ffff:127.0.0.1"),
        ("http://[::FFFF:7F00:1]/", "::ffff:127.0.0.1"),
        ("http://[0:0:0:0:0:0:0:1]/", "::1"),
        (
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254",
        ),
    ] {
        let url = Url::parse(literal).unwrap();
        assert_eq!(url.host_ip(), Some(ip.parse().unwrap()), "{literal}");
        // And the command line refuses an address outright.
        assert!(targets(literal).is_err());
    }
    for refused in [
        "http://[fe80::1%25en0]/",
        "http://[fe80::1%en0]/",
        "http://[::1/",
        "http://user@127.0.0.1/",
        "http://example.org\\@127.0.0.1/",
        "http://exam%70le.org/",
        "http://example.org:0/",
    ] {
        assert!(Url::parse(refused).is_err(), "{refused}");
    }
    assert_eq!(Url::parse("http://LOCALHOST./").unwrap().host, "localhost");
}

/// HELD. A host of 10 kB, and a target of 1 MB, are refused or handled
/// without a panic.
#[test]
fn held_a_very_long_host_is_handled() {
    let long = "a".repeat(10_000);
    let _ = targets(&long);
    let _ = targets(&format!("https://{long}/"));
    let labels = vec!["a"; 5_000].join(".");
    let _ = targets(&labels);
    let _ = Url::parse(&format!("https://example.org/{}", "../".repeat(300_000)));
    let base = Url::parse("https://example.org/").unwrap();
    // Since the audit, an address over 2048 characters is not followed.
    assert!(base.join(&"../".repeat(300_000)).is_err());
    let joined = base.join(&"../".repeat(300)).unwrap();
    assert_eq!(joined.path, "/");
}

/// HELD. The response reader never panics and never keeps more than the
/// body limit, whatever the bytes.
#[tokio::test]
async fn held_fuzz_the_response_reader() {
    let seeds: &[&[u8]] = &[
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A: b\r\n\r\nhelloEXTRA",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
        b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 301 Moved\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.0 200 OK\r\n\r\nall of it",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nabc",
        b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\nabc",
    ];
    let tokens: &[&[u8]] = &[
        b"\r\n",
        b"\n",
        b"\r",
        b":",
        b"0",
        b"f",
        b"ffffffffffffffff",
        b"10000000000000000",
        b"-1",
        b"+5",
        b" ",
        b";",
        b"HTTP/1.1 100 Continue\r\n\r\n",
        b"HTTP/1.1 ",
        b"Transfer-Encoding: chunked\r\n",
        b"Content-Length: ",
        b"\xff",
        b"\0",
    ];
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for round in 0..150_000 {
        let mut wire = rng.pick(seeds).to_vec();
        for _ in 0..1 + rng.below(4) {
            let at = rng.below(wire.len() + 1);
            match rng.below(4) {
                0 => wire
                    .splice(at..at, rng.pick(tokens).iter().copied())
                    .for_each(drop),
                1 if at < wire.len() => wire[at] = rng.next() as u8,
                2 => wire.truncate(at),
                _ if at < wire.len() => drop(wire.remove(at)),
                _ => {}
            }
        }
        let limit = [0, 1, 3, 8, 1024][rng.below(5)];
        if let Ok(response) = read(&wire, limit).await {
            assert!(response.body.len() <= limit, "round {round}");
            assert!((100..600).contains(&response.status));
            assert!(response.headers.len() <= 200);
        }
    }
}

/// HELD. A head of any shape is bounded: endless interim responses, an
/// endless header, an endless chunk-size line, a header count over the
/// limit. The reader stops with an error before it has buffered much.
#[tokio::test]
async fn held_endless_heads_are_cut_off() {
    let endless_interim = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(100_000);
    assert!(read(&endless_interim, 1024).await.is_err());

    let mut endless_header = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
    endless_header.extend(std::iter::repeat_n(b'a', 4 * 1024 * 1024));
    assert!(read(&endless_header, 1024).await.is_err());

    let mut endless_status = b"HTTP/1.1 200 ".to_vec();
    endless_status.extend(std::iter::repeat_n(b'a', 4 * 1024 * 1024));
    assert!(read(&endless_status, 1024).await.is_err());

    let mut many_headers = b"HTTP/1.1 200 OK\r\n".to_vec();
    many_headers.extend(b"A: b\r\n".repeat(201));
    many_headers.extend(b"\r\n");
    assert!(read(&many_headers, 1024).await.is_err());

    let mut endless_size = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    endless_size.extend(std::iter::repeat_n(b'0', 4 * 1024 * 1024));
    assert!(read(&endless_size, 1024).await.is_err());

    // A chunk size near the top of u64, and a Content-Length there.
    let r = read(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nfffffffffffffffe\r\nabcdef",
        4,
    )
    .await
    .unwrap();
    assert_eq!((r.body.as_slice(), r.truncated), (&b"abcd"[..], true));
    let r = read(
        b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\nabcdef",
        4,
    )
    .await
    .unwrap();
    assert_eq!((r.body.as_slice(), r.truncated), (&b"abcd"[..], true));
}

/// HELD. `shape` does not panic on any bytes and stays linear on the
/// bodies built to make it rescan: 1 MiB each, well under a second apiece
/// even in a debug build.
#[test]
fn held_shape_is_bounded() {
    let mut rng = Rng(0xfeed_face_cafe_beef);
    let tokens: &[&[u8]] = &[
        b"<",
        b">",
        b"/",
        b"<!--",
        b"-->",
        b"<script",
        b"</script",
        b"<style",
        b"</STYLE>",
        b"a",
        b"-",
        b"1",
        b" ",
        b"\xff",
        b"<!",
        b"</",
        b"<a-b",
        b"\0",
    ];
    for _ in 0..200_000 {
        let mut body = Vec::new();
        for _ in 0..rng.below(24) {
            body.extend_from_slice(rng.pick(tokens));
        }
        let out = shape(&body);
        assert!(out.len() <= body.len() * 2 + 2);
    }
    let size = 1024 * 1024;
    let hostile: Vec<Vec<u8>> = vec![
        vec![b'<'; size],
        b"<!--".repeat(size / 4),
        b"<script".repeat(size / 7),
        b"<script></scrip".repeat(size / 15),
        b"<style><".repeat(size / 8),
        b"<a".repeat(size / 2),
        b"</".repeat(size / 2),
        b"<script></script>".repeat(size / 17),
        b"<!----><".repeat(size / 8),
    ];
    for body in hostile {
        let started = std::time::Instant::now();
        let _ = shape(&body);
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_secs(2),
            "{:?}... took {took:?}",
            String::from_utf8_lossy(&body[..16])
        );
    }
}

/// HELD. The certificate reader takes any bytes: a real certificate with
/// random damage, random lengths, and plain noise. It never panics and
/// only ever returns names made of name characters.
#[test]
fn held_fuzz_the_certificate_reader() {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-cert-a.pem");
    let real: Vec<u8> = CertificateDer::pem_file_iter(path)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .to_vec();
    let whole = cert::summarise(&real, "localhost");
    assert!(whole.covers_host && whole.not_after_unix.is_some());

    let mut rng = Rng(0x000d_dba1_10dd_ba11);
    let lengths: &[u8] = &[0x00, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x88, 0xff];
    for _ in 0..300_000 {
        let mut der = real.clone();
        for _ in 0..1 + rng.below(6) {
            let at = rng.below(der.len());
            match rng.below(5) {
                0 => der[at] = rng.next() as u8,
                1 => der[at] = *rng.pick(lengths),
                2 => der.truncate(at),
                3 => {
                    // A four-byte length that claims the top of usize.
                    let claim = [0x84, 0xff, 0xff, 0xff, 0xff];
                    der.splice(at..at, claim).for_each(drop);
                }
                _ => {
                    der.remove(at);
                }
            }
            if der.is_empty() {
                break;
            }
        }
        let got = cert::summarise(&der, "localhost");
        assert!(got.names.len() <= 100);
        for name in &got.names {
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._*".contains(&b)),
                "{name:?}"
            );
        }
    }
    for _ in 0..100_000 {
        let noise: Vec<u8> = (0..rng.below(64)).map(|_| rng.next() as u8).collect();
        let _ = cert::summarise(&noise, "localhost");
    }
    // Times at the edges of what the two time types can say.
    for (tag, text) in [
        (0x17u8, &b"000101000000Z"[..]),
        (0x17, b"991231235959Z"),
        (0x17, b"999999999999Z"),
        (0x18, b"00000101000000Z"),
        (0x18, b"99991231235959Z"),
        (0x18, b"99999999999999Z"),
        (0x18, b"00000000000000Z"),
    ] {
        // Put the time in place of the real notAfter and read it again.
        let marker = real
            .windows(2)
            .rposition(|w| w == [0x17, 0x0d] || w == [0x18, 0x0f]);
        if let Some(at) = marker {
            let old_len = real[at + 1] as usize;
            let mut der = real.clone();
            der.splice(
                at..at + 2 + old_len,
                [&[tag, text.len() as u8][..], text].concat(),
            )
            .for_each(drop);
            let _ = cert::summarise(&der, "localhost");
        }
    }
}
