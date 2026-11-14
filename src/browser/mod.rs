//! The browser driver: starts an installed Chrome or Chromium, loads one
//! page through the mode proxy, and collects every request the page
//! made.
//!
//! The browser is a tool here, not a thing to trust. It runs headless
//! with a fresh profile in a temporary directory, which is deleted
//! afterwards: no saved logins, no extensions, no history. QUIC is off,
//! because HTTP/3 does not pass through an ordinary proxy. v6blick talks
//! to it over the DevTools port on the loopback address, using a few
//! calls only: open a tab, switch on network and page events, navigate,
//! and close.
//!
//! - [`ws`]: the WebSocket the DevTools port speaks
//! - [`cdp`]: commands and events over it

pub mod cdp;
pub mod ws;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};

use crate::observe::{PageRequest, RequestOutcome};
use crate::probe::http::Url;
use crate::probe::shown;
use crate::proxy::Announced;
use cdp::{Cdp, Event};
use ws::WebSocket;

/// How a page is loaded.
#[derive(Debug, Clone)]
pub struct BrowserConfig {
    /// The Chrome or Chromium binary.
    pub chrome: PathBuf,
    /// The mode proxy every request goes through.
    pub proxy: SocketAddr,
    /// For the browser to start and open its DevTools port.
    pub launch_timeout: Duration,
    /// For the page, from navigation to the end of the load.
    pub page_timeout: Duration,
    /// After the load event: this long without any network event, and
    /// the page counts as settled.
    pub quiet: Duration,
    /// At most this many requests are kept.
    pub max_requests: usize,
    /// Where each host the page asks for is announced, for a proxy that
    /// carries the page's traffic only.
    pub announce: Option<std::sync::Arc<Announced>>,
}

impl BrowserConfig {
    pub fn new(chrome: PathBuf, proxy: SocketAddr) -> Self {
        Self {
            chrome,
            proxy,
            launch_timeout: Duration::from_secs(20),
            page_timeout: Duration::from_secs(30),
            quiet: Duration::from_millis(1500),
            max_requests: 2000,
            announce: None,
        }
    }
}

/// What a page load gave.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub requests: Vec<PageRequest>,
    /// `settled` or `timeout`.
    pub ended: String,
    /// The browser's own name and version.
    pub browser: Option<String>,
}

/// A directory that is removed when this goes out of scope.
struct Scratch(PathBuf);

impl Scratch {
    /// A new, empty directory that only this user can read.
    fn new() -> std::io::Result<Scratch> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("v6blick-profile-{}-{nonce:x}", std::process::id()));
        // Fails if it exists: nobody else can have made it for us.
        std::fs::create_dir(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Scratch(dir))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The arguments the browser is started with.
pub fn arguments(profile: &Path, proxy: SocketAddr) -> Vec<String> {
    vec![
        "--headless=new".to_string(),
        // A port of the system's choosing, on the loopback address.
        "--remote-debugging-port=0".to_string(),
        format!("--user-data-dir={}", profile.display()),
        format!("--proxy-server=http://{proxy}"),
        // By default a browser goes around its proxy for this machine's
        // own names; a local build must go through it like any other.
        "--proxy-bypass-list=<-loopback>".to_string(),
        // HTTP/3 does not pass through an ordinary proxy.
        "--disable-quic".to_string(),
        // No traffic of the browser's own.
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--disable-background-networking".to_string(),
        "--disable-component-update".to_string(),
        "--disable-default-apps".to_string(),
        "--disable-sync".to_string(),
        "--disable-extensions".to_string(),
        "--disable-domain-reliability".to_string(),
        "--disable-client-side-phishing-detection".to_string(),
        "--no-pings".to_string(),
        "--metrics-recording-only".to_string(),
        "--disable-features=OptimizationHints,MediaRouter,Translate,InterestFeedContentSuggestions"
            .to_string(),
        "about:blank".to_string(),
    ]
}

/// Read the browser's messages until it says where its DevTools port is.
async fn devtools_address(child: &mut Child, wait: Duration) -> Result<(String, String), String> {
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "the browser's messages cannot be read".to_string())?;
    let mut lines = BufReader::new(stderr).lines();
    let found = async {
        while let Ok(Some(line)) = lines.next_line().await {
            // "DevTools listening on ws://127.0.0.1:53211/devtools/browser/<id>"
            if let Some(rest) = line.trim().strip_prefix("DevTools listening on ws://") {
                let (authority, path) = rest.split_once('/')?;
                return Some((authority.to_string(), format!("/{path}")));
            }
        }
        None
    };
    match tokio::time::timeout(wait, found).await {
        Ok(Some(address)) => {
            // Keep reading, so that the browser never blocks on a full pipe.
            tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
            Ok(address)
        }
        Ok(None) => Err("the browser ended before opening its DevTools port".to_string()),
        Err(_) => Err(format!(
            "the browser did not open its DevTools port in {} s",
            wait.as_secs()
        )),
    }
}

/// The requests of one page load, built up from the browser's events.
#[derive(Default)]
pub struct Requests {
    list: Vec<PageRequest>,
    /// The browser's request ID -> the place in `list` of its latest hop.
    current: HashMap<String, usize>,
    main_frame: String,
    loaded: bool,
    limit: usize,
    announce: Option<std::sync::Arc<Announced>>,
}

impl Requests {
    pub fn new(main_frame: &str, limit: usize) -> Self {
        Self {
            main_frame: main_frame.to_string(),
            limit,
            ..Default::default()
        }
    }

    /// Announce every host a request names, to this.
    pub fn announcing(mut self, to: Option<std::sync::Arc<Announced>>) -> Self {
        self.announce = to;
        self
    }

    fn announce(&self, host: &str) {
        if let Some(announced) = &self.announce {
            announced.add(host);
        }
    }

    /// True once the page's load event has fired.
    pub fn loaded(&self) -> bool {
        self.loaded
    }

    /// True when the page itself got no response.
    pub fn document_failed(&self) -> bool {
        self.list.iter().any(|r| r.document && r.failed().is_some())
    }

    /// Requests that have neither finished nor failed.
    pub fn under_way(&self) -> usize {
        self.list
            .iter()
            .filter(|r| r.outcome == RequestOutcome::Unfinished)
            .count()
    }

    pub fn into_list(self) -> Vec<PageRequest> {
        self.list
    }

    /// Take in one event. Everything in it comes from the page, so what
    /// is kept is made safe to print and bounded in length.
    pub fn take(&mut self, event: &Event) {
        let p = &event.params;
        let id = p["requestId"].as_str().unwrap_or_default().to_string();
        match event.method.as_str() {
            "Page.loadEventFired" => self.loaded = true,
            // A WebSocket is not a request in the list, and still a
            // connection the page asked for.
            "Network.webSocketCreated" => {
                let url = p["url"].as_str().unwrap_or_default();
                let as_http = url.replacen("ws", "http", 1);
                if let Ok(parsed) = Url::parse(&as_http) {
                    self.announce(&parsed.host);
                }
            }
            "Network.requestWillBeSent" => {
                let url = p["request"]["url"].as_str().unwrap_or_default();
                // Only what goes over the network: not `data:` or `blob:`.
                let Ok(parsed) = Url::parse(url) else {
                    return;
                };
                self.announce(&parsed.host);
                let kind = p["type"].as_str().unwrap_or("other").to_ascii_lowercase();
                // A redirect comes as a new request under the old ID.
                let mut redirected_from = None;
                let mut document =
                    kind == "document" && p["frameId"].as_str() == Some(self.main_frame.as_str());
                if let Some(before) = self.current.get(&id).copied() {
                    let status = p["redirectResponse"]["status"].as_u64().unwrap_or(0) as u16;
                    let earlier = &mut self.list[before];
                    earlier.outcome = RequestOutcome::Redirected { status };
                    redirected_from = Some(earlier.url.clone());
                    document = earlier.document;
                }
                if self.list.len() >= self.limit {
                    return;
                }
                self.current.insert(id, self.list.len());
                self.list.push(PageRequest {
                    url: shown(url),
                    host: parsed.host,
                    kind: shown(&kind),
                    document,
                    redirected_from,
                    outcome: RequestOutcome::Unfinished,
                });
            }
            "Network.responseReceived" => {
                if let Some(at) = self.current.get(&id) {
                    let status = p["response"]["status"].as_u64().unwrap_or(0) as u16;
                    self.list[*at].outcome = RequestOutcome::Loaded { status };
                }
            }
            "Network.loadingFailed" => {
                if let Some(at) = self.current.get(&id) {
                    self.list[*at].outcome = if p["canceled"].as_bool() == Some(true) {
                        RequestOutcome::Canceled
                    } else {
                        RequestOutcome::Failed {
                            error: shown(p["errorText"].as_str().unwrap_or("failed")),
                        }
                    };
                }
            }
            _ => {}
        }
    }
}

/// Load `url` in a browser started for the purpose, and return what the
/// page asked for. The browser and its profile are gone when this
/// returns, however it returns.
pub async fn load_page(config: &BrowserConfig, url: &str) -> Result<Loaded, String> {
    let profile = Scratch::new().map_err(|e| format!("no temporary profile directory: {e}"))?;
    let mut child = Command::new(&config.chrome)
        .args(arguments(&profile.0, config.proxy))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        // Whatever happens below, the browser does not outlive this call.
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("{} cannot be started: {e}", config.chrome.display()))?;

    let result = drive(config, url, &mut child).await;
    // Ask nicely first, then insist.
    if tokio::time::timeout(Duration::from_secs(3), child.wait())
        .await
        .is_err()
    {
        let _ = child.kill().await;
    }
    result
}

async fn drive(config: &BrowserConfig, url: &str, child: &mut Child) -> Result<Loaded, String> {
    let (authority, path) = devtools_address(child, config.launch_timeout).await?;
    let stream = TcpStream::connect(&authority)
        .await
        .map_err(|e| format!("the browser's DevTools port cannot be reached: {e}"))?;
    let ws = WebSocket::connect(stream, &authority, &path).await?;
    let mut cdp = Cdp::new(ws);

    let version = cdp.call("Browser.getVersion", json!({}), None).await.ok();
    let browser = version
        .as_ref()
        .and_then(|v| v["product"].as_str())
        .map(shown);

    // A tab of our own, and a session to talk to it.
    let target = cdp
        .call("Target.createTarget", json!({ "url": "about:blank" }), None)
        .await?;
    let target_id = target["targetId"]
        .as_str()
        .ok_or_else(|| "the browser opened no tab".to_string())?
        .to_string();
    let attached = cdp
        .call(
            "Target.attachToTarget",
            json!({ "targetId": target_id, "flatten": true }),
            None,
        )
        .await?;
    let session = attached["sessionId"]
        .as_str()
        .ok_or_else(|| "the browser gave no session for the tab".to_string())?
        .to_string();
    let session = Some(session.as_str());
    cdp.call("Network.enable", json!({}), session).await?;
    cdp.call("Page.enable", json!({}), session).await?;
    // Every request is held for a moment before it is sent, so that its
    // host is announced to the proxy before the browser connects. This
    // covers redirects too, which the network events report too late.
    let hold = json!({ "patterns": [{ "urlPattern": "*" }] });
    if config.announce.is_some() {
        cdp.call("Fetch.enable", hold.clone(), session).await?;
    }
    // Frames of other sites and workers are targets of their own. Each
    // is held at its start until its network events are switched on, so
    // that none of its requests is missed.
    let attach = json!({ "autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true });
    let _ = cdp
        .call("Target.setAutoAttach", attach.clone(), session)
        .await;
    // Nothing from an earlier visit, though the profile is new.
    let _ = cdp
        .call(
            "Network.setCacheDisabled",
            json!({ "cacheDisabled": true }),
            session,
        )
        .await;

    // The page's own host is asked for before any event says so.
    if let (Some(announced), Ok(parsed)) = (&config.announce, Url::parse(url)) {
        announced.add(&parsed.host);
    }
    // The tab's own frame, to tell the page from the frames inside it.
    let tree = cdp.call("Page.getFrameTree", json!({}), session).await?;
    let main_frame = tree["frameTree"]["frame"]["id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let mut requests =
        Requests::new(&main_frame, config.max_requests).announcing(config.announce.clone());
    let started = Instant::now();
    // Not waited for: the answer comes only once the page's first
    // request has been let go, which happens in the loop below.
    cdp.send("Page.navigate", json!({ "url": url }), session)
        .await?;

    let mut last_event = Instant::now();
    let ended = loop {
        let left = config.page_timeout.saturating_sub(started.elapsed());
        if left.is_zero() {
            break "timeout";
        }
        match cdp.event(left.min(Duration::from_millis(250))).await? {
            Some(event) => {
                if event.method.starts_with("Network.") || event.method.starts_with("Page.") {
                    last_event = Instant::now();
                }
                if event.method == "Target.attachedToTarget" {
                    // A frame or a worker: switch its events on, let it
                    // attach its own children, then let it run. Nothing
                    // here is waited for: while a request is held, the
                    // browser puts other commands off, and their answers
                    // would never come.
                    let child = event.params["sessionId"].as_str();
                    if child.is_some() && child != session {
                        cdp.send("Network.enable", json!({}), child).await?;
                        if config.announce.is_some() {
                            cdp.send("Fetch.enable", hold.clone(), child).await?;
                        }
                        cdp.send("Target.setAutoAttach", attach.clone(), child)
                            .await?;
                        cdp.send("Runtime.runIfWaitingForDebugger", json!({}), child)
                            .await?;
                    }
                    continue;
                }
                if event.method == "Fetch.requestPaused" {
                    // Announce the host, then let the request go.
                    let held = &event.params;
                    if let Ok(parsed) = Url::parse(held["request"]["url"].as_str().unwrap_or("")) {
                        requests.announce(&parsed.host);
                    }
                    let go = json!({ "requestId": held["requestId"] });
                    cdp.send("Fetch.continueRequest", go, event.session.as_deref())
                        .await?;
                    continue;
                }
                requests.take(&event);
            }
            None => {
                let quiet = last_event.elapsed();
                // A navigation that fails outright fires no load event.
                let done = requests.loaded() || requests.document_failed();
                // Settled: loaded, nothing under way, and quiet. A page
                // that keeps one request open for ever (a long poll)
                // settles after twice the quiet time.
                if done
                    && ((requests.under_way() == 0 && quiet >= config.quiet)
                        || quiet >= config.quiet * 2)
                {
                    break "settled";
                }
            }
        }
    };
    let _ = cdp.call("Browser.close", Value::Null, None).await;
    Ok(Loaded {
        requests: requests.into_list(),
        ended: ended.to_string(),
        browser,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(method: &str, params: Value) -> Event {
        Event {
            method: method.to_string(),
            params,
            session: None,
        }
    }

    fn sent(id: &str, url: &str, kind: &str, frame: &str) -> Event {
        event(
            "Network.requestWillBeSent",
            json!({"requestId": id, "request": {"url": url}, "type": kind, "frameId": frame}),
        )
    }

    #[test]
    fn requests_are_built_from_events() {
        let mut r = Requests::new("MAIN", 100);
        r.take(&sent("1", "https://example.org/", "Document", "MAIN"));
        r.take(&event(
            "Network.responseReceived",
            json!({"requestId": "1", "response": {"status": 200}}),
        ));
        r.take(&sent(
            "2",
            "https://static.example.org/a.css",
            "Stylesheet",
            "MAIN",
        ));
        r.take(&event(
            "Network.loadingFailed",
            json!({"requestId": "2", "errorText": "net::ERR_TUNNEL_CONNECTION_FAILED"}),
        ));
        r.take(&sent("3", "https://cdn.example/x.js", "Script", "MAIN"));
        r.take(&sent("4", "data:image/png;base64,AAAA", "Image", "MAIN"));
        r.take(&sent("5", "https://ads.example/frame", "Document", "CHILD"));
        r.take(&event(
            "Network.loadingFailed",
            json!({"requestId": "5", "canceled": true}),
        ));
        assert!(!r.loaded());
        r.take(&event("Page.loadEventFired", json!({})));
        assert!(r.loaded());
        assert_eq!(r.under_way(), 1);

        let list = r.into_list();
        // The data: address is not a request over the network.
        assert_eq!(list.len(), 4);
        assert!(list[0].document && list[0].kind == "document");
        assert_eq!(list[0].outcome, RequestOutcome::Loaded { status: 200 });
        assert_eq!(list[1].host, "static.example.org");
        assert_eq!(list[1].failed(), Some("net::ERR_TUNNEL_CONNECTION_FAILED"));
        assert_eq!(list[2].outcome, RequestOutcome::Unfinished);
        // A document in another frame is not the page.
        assert!(!list[3].document);
        assert_eq!(list[3].outcome, RequestOutcome::Canceled);
    }

    #[test]
    fn a_redirect_is_two_requests_and_the_second_says_where_from() {
        let mut r = Requests::new("MAIN", 100);
        r.take(&sent("1", "https://www.example.org/", "Document", "MAIN"));
        let mut follow = sent("1", "https://example.org/", "Document", "MAIN");
        follow.params["redirectResponse"] = json!({"status": 301});
        r.take(&follow);
        r.take(&event(
            "Network.loadingFailed",
            json!({"requestId": "1", "errorText": "net::ERR_TUNNEL_CONNECTION_FAILED"}),
        ));
        let list = r.into_list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].outcome, RequestOutcome::Redirected { status: 301 });
        assert!(list[0].answered());
        assert_eq!(
            list[1].redirected_from.as_deref(),
            Some("https://www.example.org/")
        );
        assert!(list[1].document, "the redirect target is still the page");
        assert!(list[1].failed().is_some());
    }

    #[test]
    fn what_a_page_sends_is_made_safe_and_bounded() {
        let mut r = Requests::new("MAIN", 2);
        r.take(&sent(
            "1",
            "https://example.org/\u{202e}x",
            "Document",
            "MAIN",
        ));
        r.take(&sent("2", "https://example.org/b", "Sc\u{1b}ript", "MAIN"));
        r.take(&sent("3", "https://example.org/c", "Image", "MAIN"));
        r.take(&event(
            "Network.loadingFailed",
            json!({"requestId": "2", "errorText": "bad\u{1b}[31m"}),
        ));
        let list = r.into_list();
        // The limit holds.
        assert_eq!(list.len(), 2);
        for text in [
            &list[0].url,
            &list[1].kind,
            &list[1].failed().unwrap().to_string(),
        ] {
            assert!(
                !text.contains('\u{1b}') && !text.contains('\u{202e}'),
                "{text:?}"
            );
        }
    }

    #[test]
    fn the_browser_gets_a_fresh_profile_the_proxy_and_no_quic() {
        let args = arguments(Path::new("/tmp/p"), "127.0.0.1:4321".parse().unwrap());
        for needed in [
            "--headless=new",
            "--user-data-dir=/tmp/p",
            "--proxy-server=http://127.0.0.1:4321",
            "--proxy-bypass-list=<-loopback>",
            "--disable-quic",
            "--disable-extensions",
            "--remote-debugging-port=0",
        ] {
            assert!(args.iter().any(|a| a == needed), "{needed}");
        }
    }

    #[test]
    fn the_profile_directory_is_private_and_removed() {
        let scratch = Scratch::new().unwrap();
        let dir = scratch.0.clone();
        assert!(dir.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        std::fs::write(dir.join("file"), b"x").unwrap();
        drop(scratch);
        assert!(!dir.exists());
    }
}
