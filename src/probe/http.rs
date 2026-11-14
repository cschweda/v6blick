//! One plain HTTP/1.1 GET, written by hand.
//!
//! The prober chooses the address itself and keeps the connection's
//! timings and certificate, which a general HTTP client hides. What is
//! left to do here is small: build one request, read one response, and
//! stop at a size limit. Nothing but GET is ever sent.

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::observe::Scheme;

/// The head of a response may be at most this large.
const MAX_HEAD: usize = 64 * 1024;
/// A response may carry at most this many header lines.
const MAX_HEADERS: usize = 200;

/// An absolute `http` or `https` URL, as far as a GET needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub scheme: Scheme,
    /// Lowercase, without a trailing dot. An IPv6 address has no brackets.
    pub host: String,
    pub port: u16,
    /// Path and query. Starts with `/`.
    pub path: String,
}

impl Url {
    /// Parse an absolute URL. A fragment is dropped. A URL with a user
    /// name, an empty host or anything that is not printable is refused.
    pub fn parse(input: &str) -> Result<Url, String> {
        let input = input.trim();
        if input.bytes().any(|b| b <= 0x20 || b == 0x7f) {
            return Err("the address holds a space or a control character".to_string());
        }
        let (scheme, rest) = input
            .split_once("://")
            .ok_or_else(|| "the address has no scheme".to_string())?;
        let scheme = match scheme.to_ascii_lowercase().as_str() {
            "https" => Scheme::Https,
            "http" => Scheme::Http,
            other => return Err(format!("the scheme '{other}' is not http or https")),
        };
        let rest = rest.split('#').next().unwrap_or_default();
        let cut = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(cut);
        if authority.contains('@') {
            return Err("the address carries a user name".to_string());
        }
        let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
            let (host, after) = inner
                .split_once(']')
                .ok_or_else(|| "the address has an unclosed '['".to_string())?;
            if host.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(format!("'{host}' is not an IPv6 address"));
            }
            (host, after.strip_prefix(':'))
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            }
        };
        let port = match port {
            Some(text) => text
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("'{text}' is not a port"))?,
            None => scheme.default_port(),
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let plain = |b: u8| b.is_ascii_alphanumeric() || b"-._:".contains(&b);
        if host.is_empty() || !host.bytes().all(plain) {
            return Err(format!("'{host}' is not a host name"));
        }
        let path = match path.as_bytes().first() {
            None => "/".to_string(),
            Some(b'?') => format!("/{}", escape(path)),
            Some(_) => escape(path),
        };
        Ok(Url {
            scheme,
            host,
            port,
            path,
        })
    }

    /// The URL a `Location` header leads to from this one.
    pub fn join(&self, location: &str) -> Result<Url, String> {
        let location = location.trim();
        if location.is_empty() {
            return Err("the Location header is empty".to_string());
        }
        let lower = location.to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            return Url::parse(location);
        }
        if let Some(rest) = location.strip_prefix("//") {
            return Url::parse(&format!("{}://{rest}", self.scheme.as_str()));
        }
        if location.contains("://")
            || lower.starts_with("javascript:")
            || lower.starts_with("data:")
        {
            return Err("the Location header is not an http or https address".to_string());
        }
        let location = location.split('#').next().unwrap_or_default();
        let own_path = self.path.split('?').next().unwrap_or("/");
        let path = if location.starts_with('/') {
            location.to_string()
        } else if location.starts_with('?') || location.is_empty() {
            format!("{own_path}{location}")
        } else {
            let dir = &own_path[..=own_path.rfind('/').unwrap_or(0)];
            format!("{dir}{location}")
        };
        if path.bytes().any(|b| b <= 0x20 || b == 0x7f) {
            return Err("the Location header holds a space or a control character".to_string());
        }
        let (path, query) = match path.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path.as_str(), None),
        };
        let mut joined = remove_dot_segments(path);
        if let Some(query) = query {
            joined.push('?');
            joined.push_str(query);
        }
        Ok(Url {
            path: escape(&joined),
            ..self.clone()
        })
    }

    /// The host as an address, when it is written as one.
    pub fn host_ip(&self) -> Option<std::net::IpAddr> {
        self.host.parse().ok()
    }

    /// The value of the `Host` header: the port is named only when it is
    /// not the scheme's own.
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == self.scheme.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// The one request v6blick sends: a GET that asks for the body as it
    /// is, on a connection that is closed afterwards.
    pub fn request(&self, user_agent: &str) -> Vec<u8> {
        format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {user_agent}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            self.path,
            self.host_header()
        )
        .into_bytes()
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}://{}{}",
            self.scheme.as_str(),
            self.host_header(),
            self.path
        )
    }
}

/// Percent-encode what may not go into a request line as it is.
fn escape(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        if b > 0x20 && b < 0x7f {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Resolve `.` and `..` in a path.
fn remove_dot_segments(path: &str) -> String {
    let mut kept: Vec<&str> = Vec::new();
    let segments: Vec<&str> = path.split('/').collect();
    let last = segments.len() - 1;
    for (i, segment) in segments.iter().enumerate() {
        match *segment {
            "." | ".." => {
                if *segment == ".." && kept.len() > 1 {
                    kept.pop();
                }
                // A dot segment at the end leaves a directory behind.
                if i == last {
                    kept.push("");
                }
            }
            other => kept.push(other),
        }
    }
    let joined = kept.join("/");
    if joined.starts_with('/') {
        joined
    } else {
        format!("/{joined}")
    }
}

/// A response as it was read: the status, the headers with lowercase
/// names, and the body up to the limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// True when the body was longer than the limit and was cut off.
    pub truncated: bool,
}

impl RawResponse {
    /// The first header of this name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// How an attempt to take a number of body bytes ended.
#[derive(PartialEq)]
enum Took {
    All,
    /// The size limit was reached first.
    Limit,
    /// The other side closed the connection first.
    Eof,
}

struct Buffered<'a, S> {
    stream: &'a mut S,
    buf: Vec<u8>,
    start: usize,
}

impl<S: AsyncRead + Unpin> Buffered<'_, S> {
    /// Read more from the stream. False when it has ended.
    async fn fill(&mut self) -> Result<bool, String> {
        if self.start > MAX_HEAD {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let mut chunk = [0u8; 8192];
        match self.stream.read(&mut chunk).await {
            Ok(0) => Ok(false),
            Ok(n) => {
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(true)
            }
            // A TLS server that closes without saying so first. Common,
            // and the same as an ordinary close for a response whose
            // length is known.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }

    /// One line, without its line ending. `None` when the stream ended
    /// before any line did.
    async fn line(&mut self, budget: &mut usize) -> Result<Option<Vec<u8>>, String> {
        loop {
            if let Some(at) = self.buf[self.start..].iter().position(|b| *b == b'\n') {
                let mut line = self.buf[self.start..self.start + at].to_vec();
                self.start += at + 1;
                *budget = budget
                    .checked_sub(at + 1)
                    .ok_or_else(|| "the response head is too large".to_string())?;
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(line));
            }
            if self.buf.len() - self.start > *budget {
                return Err("the response head is too large".to_string());
            }
            if !self.fill().await? {
                return Ok(None);
            }
        }
    }

    /// Move up to `wanted` bytes of body into `out`, which may grow to
    /// `limit` bytes.
    async fn take(
        &mut self,
        mut wanted: u64,
        out: &mut Vec<u8>,
        limit: usize,
    ) -> Result<Took, String> {
        while wanted > 0 {
            if self.start == self.buf.len() && !self.fill().await? {
                return Ok(Took::Eof);
            }
            let available = (self.buf.len() - self.start) as u64;
            let step = available.min(wanted) as usize;
            let room = limit - out.len();
            out.extend_from_slice(&self.buf[self.start..self.start + step.min(room)]);
            if step > room {
                return Ok(Took::Limit);
            }
            self.start += step;
            wanted -= step as u64;
        }
        Ok(Took::All)
    }
}

/// Read one response from `stream`, keeping at most `body_limit` bytes of
/// its body.
pub async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut S,
    body_limit: usize,
) -> Result<RawResponse, String> {
    let mut reader = Buffered {
        stream,
        buf: Vec::new(),
        start: 0,
    };
    let mut budget = MAX_HEAD;
    let (status, headers) = loop {
        let line = reader
            .line(&mut budget)
            .await?
            .ok_or_else(|| "the connection closed before any response".to_string())?;
        let status = parse_status_line(&line)?;
        let mut headers = Vec::new();
        loop {
            let line = reader
                .line(&mut budget)
                .await?
                .ok_or_else(|| "the connection closed inside the response head".to_string())?;
            if line.is_empty() {
                break;
            }
            if headers.len() == MAX_HEADERS {
                return Err("the response has too many headers".to_string());
            }
            let text = String::from_utf8_lossy(&line);
            if let Some((name, value)) = text.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        // 100 Continue and 103 Early Hints come before the real response.
        if !(100..200).contains(&status) || status == 101 {
            break (status, headers);
        }
    };

    let mut response = RawResponse {
        status,
        headers,
        body: Vec::new(),
        truncated: false,
    };
    if status == 204 || status == 304 || status == 101 {
        return Ok(response);
    }
    let chunked = response
        .header("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let length = response
        .header("content-length")
        .and_then(|v| v.parse::<u64>().ok());
    let mut body = Vec::new();
    let ended = if chunked {
        let mut budget = MAX_HEAD;
        loop {
            let Some(line) = reader.line(&mut budget).await? else {
                break Took::Eof;
            };
            let text = String::from_utf8_lossy(&line);
            let size = text.split(';').next().unwrap_or_default().trim();
            if size.is_empty() {
                continue;
            }
            let size = u64::from_str_radix(size, 16)
                .map_err(|_| "the chunked body is malformed".to_string())?;
            if size == 0 {
                break Took::All;
            }
            let took = reader.take(size, &mut body, body_limit).await?;
            if took != Took::All {
                break took;
            }
        }
    } else {
        reader
            .take(length.unwrap_or(u64::MAX), &mut body, body_limit)
            .await?
    };
    response.truncated = ended == Took::Limit;
    response.body = body;
    Ok(response)
}

fn parse_status_line(line: &[u8]) -> Result<u16, String> {
    let bad = || "the response does not start with an HTTP status line".to_string();
    let text = std::str::from_utf8(line).map_err(|_| bad())?;
    let rest = text.strip_prefix("HTTP/1.").ok_or_else(bad)?;
    let mut parts = rest.splitn(3, ' ');
    let _minor = parts.next().ok_or_else(bad)?;
    let code = parts.next().ok_or_else(bad)?;
    if code.len() != 3 {
        return Err(bad());
    }
    code.parse::<u16>()
        .ok()
        .filter(|c| (100..600).contains(c))
        .ok_or_else(bad)
}

/// The structure of a body: its HTML tag names in order, lowercase, with
/// no text, no attributes and no comments. What is inside a script or a
/// style element is skipped. Two loads of a page that differ only in
/// per-request content (a timestamp, a token, a rotated advert) give the
/// same result; a different page does not. A body with no tags gives an
/// empty result.
pub fn shape(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        if body[i] != b'<' {
            i += 1;
            continue;
        }
        if body[i..].starts_with(b"<!--") {
            i = find(body, i + 4, b"-->").map_or(body.len(), |end| end + 3);
            continue;
        }
        let mut j = i + 1;
        let closing = body.get(j) == Some(&b'/');
        if closing {
            j += 1;
        }
        let start = j;
        while j < body.len() && (body[j].is_ascii_alphanumeric() || body[j] == b'-') {
            j += 1;
        }
        if j == start || !body[start].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let name = body[start..j].to_ascii_lowercase();
        if closing {
            out.push(b'/');
        }
        out.extend_from_slice(&name);
        out.push(b' ');
        i = j;
        if !closing && (name == b"script" || name == b"style") {
            let close = [b"</".as_slice(), name.as_slice()].concat();
            i = find(body, i, &close).unwrap_or(body.len());
        }
    }
    out
}

/// The first place at or after `from` where `needle` is found, ignoring
/// the case of ASCII letters.
fn find(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
        .map(|at| at + from)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read(wire: &[u8], limit: usize) -> Result<RawResponse, String> {
        let mut stream = wire;
        read_response(&mut stream, limit).await
    }

    #[test]
    fn urls_are_parsed() {
        let url = Url::parse("https://Example.ORG").unwrap();
        assert_eq!(
            (url.scheme, url.host.as_str(), url.port, url.path.as_str()),
            (Scheme::Https, "example.org", 443, "/")
        );
        let url = Url::parse("http://example.org:8080/a/b?c=d#frag").unwrap();
        assert_eq!((url.port, url.path.as_str()), (8080, "/a/b?c=d"));
        assert_eq!(url.host_header(), "example.org:8080");
        assert_eq!(url.to_string(), "http://example.org:8080/a/b?c=d");
        let url = Url::parse("https://example.org?x=1").unwrap();
        assert_eq!(url.path, "/?x=1");
        let url = Url::parse("http://[2001:db8::1]:8080/").unwrap();
        assert_eq!(url.host, "2001:db8::1");
        assert_eq!(url.host_header(), "[2001:db8::1]:8080");
        assert!(url.host_ip().is_some());
        assert_eq!(
            Url::parse("https://example.org./").unwrap().host,
            "example.org"
        );
    }

    #[test]
    fn unusable_urls_are_refused() {
        for bad in [
            "example.org",
            "ftp://example.org/",
            "https://user@example.org/",
            "https:///path",
            "https://example.org:0/",
            "https://example.org:99999/",
            "https://exa mple.org/",
            "https://example.org/a\r\nX-Injected: 1",
            "https://[::1/",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn locations_are_joined() {
        let base = Url::parse("https://example.org/a/b/c?x=1").unwrap();
        let to = |location: &str| base.join(location).unwrap().to_string();
        assert_eq!(to("http://other.example/z"), "http://other.example/z");
        assert_eq!(to("//other.example/z"), "https://other.example/z");
        assert_eq!(to("/z?y=2"), "https://example.org/z?y=2");
        assert_eq!(to("d"), "https://example.org/a/b/d");
        assert_eq!(to("../d"), "https://example.org/a/d");
        assert_eq!(to("../../../../d"), "https://example.org/d");
        assert_eq!(to("./"), "https://example.org/a/b/");
        assert_eq!(to("?y=2"), "https://example.org/a/b/c?y=2");
        assert_eq!(to("/caf\u{e9}"), "https://example.org/caf%C3%A9");
        assert!(base.join("").is_err());
        assert!(base.join("javascript:alert(1)").is_err());
        assert!(base.join("ftp://example.org/").is_err());
        assert!(base.join("/a\r\nHost: evil.example").is_err());
    }

    #[test]
    fn the_request_is_a_plain_get() {
        let url = Url::parse("https://example.org/path?q=1").unwrap();
        let text = String::from_utf8(url.request("v6blick/test")).unwrap();
        assert!(text.starts_with("GET /path?q=1 HTTP/1.1\r\nHost: example.org\r\n"));
        assert!(text.contains("\r\nUser-Agent: v6blick/test\r\n"));
        assert!(text.contains("\r\nConnection: close\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[tokio::test]
    async fn reads_a_body_with_a_length() {
        let r = read(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A: b\r\n\r\nhelloEXTRA",
            100,
        )
        .await
        .unwrap();
        assert_eq!(
            (r.status, r.body.as_slice(), r.truncated),
            (200, &b"hello"[..], false)
        );
        assert_eq!(r.header("x-a"), Some("b"));
    }

    #[tokio::test]
    async fn reads_a_chunked_body() {
        let r = read(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
            100,
        )
        .await
        .unwrap();
        assert_eq!(r.body, b"Wikipedia");
        assert!(!r.truncated);
    }

    #[tokio::test]
    async fn reads_to_the_end_without_a_length() {
        let r = read(b"HTTP/1.0 200 OK\r\n\r\nall of it", 100)
            .await
            .unwrap();
        assert_eq!(r.body, b"all of it");
    }

    #[tokio::test]
    async fn stops_at_the_size_limit() {
        let r = read(
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789",
            4,
        )
        .await
        .unwrap();
        assert_eq!((r.body.as_slice(), r.truncated), (&b"0123"[..], true));
        let r = read(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n",
            4,
        )
        .await
        .unwrap();
        assert_eq!((r.body.as_slice(), r.truncated), (&b"abcd"[..], true));
    }

    #[tokio::test]
    async fn a_redirect_keeps_its_location() {
        let r = read(
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://www.example.org/\r\nContent-Length: 0\r\n\r\n",
            100,
        )
        .await
        .unwrap();
        assert_eq!(r.status, 301);
        assert_eq!(r.header("location"), Some("https://www.example.org/"));
    }

    #[tokio::test]
    async fn interim_responses_are_skipped() {
        let r = read(
            b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            100,
        )
        .await
        .unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]));
    }

    #[tokio::test]
    async fn responses_without_a_body_end_at_the_head() {
        let r = read(b"HTTP/1.1 204 No Content\r\n\r\n", 100).await.unwrap();
        assert!(r.body.is_empty());
    }

    #[tokio::test]
    async fn what_is_not_http_is_an_error() {
        assert!(read(b"", 100).await.is_err());
        assert!(read(b"SSH-2.0-OpenSSH_9.6\r\n", 100).await.is_err());
        assert!(
            read(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n", 100)
                .await
                .is_err()
        );
        assert!(read(b"HTTP/1.1 20 OK\r\n\r\n", 100).await.is_err());
        let huge = [
            b"HTTP/1.1 200 OK\r\nX: ".to_vec(),
            vec![b'a'; MAX_HEAD + 10],
        ]
        .concat();
        assert!(read(&huge, 100).await.is_err());
    }

    #[test]
    fn the_shape_ignores_text_attributes_and_scripts() {
        let a = shape(
            b"<!DOCTYPE html><html><head><title>One</title><script>if (a<b) {x='</p>'}</script></head>\
              <body class=\"x\"><!-- <b>12:01</b> --><p>Hello <b>Ann</b></p><br/></body></html>",
        );
        let b = shape(
            b"<!doctype html><HTML><head><title>Two, quite different</title><script>var t=99</script></head>\
              <body class=\"y\" data-token=\"abc\"><p>Goodbye <b>Bob</b></p><br></body></html>",
        );
        assert_eq!(a, b);
        assert_eq!(
            String::from_utf8(a).unwrap(),
            "html head title /title script /script /head body p b /b /p br /body /html "
        );
        let other = shape(b"<html><body><h1>Maintenance</h1></body></html>");
        assert_ne!(other, b);
        assert!(shape(b"{\"plain\": \"json\", \"a\": 1 < 2}").is_empty());
    }
}
