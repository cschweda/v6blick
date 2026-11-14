//! A whole `page` run: load the page in `dual` as the baseline, then in
//! the mode under test, each time in a browser of its own behind a
//! proxy of its own.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::browser::{self, BrowserConfig};
use crate::cli::RunError;
use crate::observe::{LookupStatus, Mode, PageLoad, PageObservation};
use crate::probe::http::Url;
use crate::probe::{BoxFuture, Resolve};
use crate::proxy::{Proxy, ProxyConfig};
use crate::resolve::iterate::printable;
use crate::resolve::{self, Client, HostResolver};

/// How a page run behaves.
#[derive(Debug, Clone)]
pub struct PageSettings {
    /// The Chrome or Chromium binary.
    pub chrome: PathBuf,
    /// The mode to test, after the `dual` baseline.
    pub mode: Mode,
    pub allow_private: bool,
    /// For one load of the page.
    pub page_timeout: Duration,
    /// For the whole run.
    pub run_deadline: Duration,
}

impl PageSettings {
    pub fn new(chrome: PathBuf, mode: Mode) -> Self {
        Self {
            chrome,
            mode,
            allow_private: false,
            page_timeout: Duration::from_secs(30),
            run_deadline: Duration::from_secs(150),
        }
    }
}

/// Finds the addresses of the hosts a page names, for the proxy. One
/// resolver for the whole run, so that each host is looked up once.
pub struct PageHosts {
    hosts: HostResolver,
    allow_private: bool,
}

impl PageHosts {
    pub fn new(hosts: HostResolver, allow_private: bool) -> Self {
        Self {
            hosts,
            allow_private,
        }
    }
}

impl Resolve for PageHosts {
    fn addresses<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, String>> {
        Box::pin(async move {
            let name = resolve::normalise_host(host).map_err(|e| e.to_string())?;
            let mut lookup = self.hosts.lookup(&name).await;
            // As in `check`: only a definite "no such name" from the
            // public DNS, and only with private destinations allowed,
            // sends the question to this machine's resolver.
            let no_such_name = lookup.a.status == LookupStatus::Nxdomain
                && lookup.aaaa.status == LookupStatus::Nxdomain;
            if no_such_name && self.allow_private {
                lookup = resolve::lookup_host_system(&name).await;
            }
            let all: Vec<IpAddr> = lookup
                .a
                .addresses
                .iter()
                .chain(lookup.aaaa.addresses.iter())
                .copied()
                .collect();
            if !all.is_empty() {
                return Ok(all);
            }
            Err(
                match [&lookup.a, &lookup.aaaa]
                    .into_iter()
                    .find_map(|f| f.error.clone())
                {
                    Some(why) => why,
                    None if no_such_name => "the name does not exist".to_string(),
                    None => "the name has no address".to_string(),
                },
            )
        })
    }
}

/// The page address for what was given: a full address as it is, and
/// `https://` put before a bare host.
pub fn page_url(input: &str) -> Result<Url, String> {
    let input = input.trim();
    let url = if input.contains("://") {
        Url::parse(input)?
    } else {
        Url::parse(&format!("https://{input}"))?
    };
    if url.host_ip().is_some() {
        return Err(format!(
            "'{}' is an address, not a host name; give the page by name",
            url.host
        ));
    }
    Ok(url)
}

/// Load the page once, in one mode.
async fn load(
    url: &Url,
    mode: Mode,
    settings: &PageSettings,
    hosts: Arc<PageHosts>,
) -> Result<(PageLoad, Option<String>), RunError> {
    // The proxy carries what the page asks for and nothing else: the
    // driver announces each host as the page requests it.
    let announced = Arc::new(crate::proxy::Announced::default());
    let config = ProxyConfig {
        allow_private: settings.allow_private,
        only: Some(announced.clone()),
        ..ProxyConfig::new(mode)
    };
    let proxy = Proxy::start(config, hosts)
        .await
        .map_err(|e| RunError::Browser(format!("the proxy cannot be started: {e}")))?;
    let browser = BrowserConfig {
        page_timeout: settings.page_timeout,
        announce: Some(announced),
        ..BrowserConfig::new(settings.chrome.clone(), proxy.address())
    };
    let loaded = browser::load_page(&browser, &url.to_string())
        .await
        .map_err(|why| RunError::Browser(printable(&why)))?;
    Ok((
        PageLoad {
            mode,
            ended: loaded.ended,
            requests: loaded.requests,
            connections: proxy.finish(),
        },
        loaded.browser,
    ))
}

/// Everything a `page` run does: find out which address families work
/// here, then load the page in `dual` and in the mode under test.
pub async fn observe_page(
    target: &str,
    client: Arc<Client>,
    settings: PageSettings,
) -> Result<PageObservation, RunError> {
    let deadline = settings.run_deadline;
    match tokio::time::timeout(deadline, observe_within(target, client, settings)).await {
        Ok(outcome) => outcome,
        Err(_) => Err(RunError::Deadline {
            secs: deadline.as_secs(),
        }),
    }
}

async fn observe_within(
    target: &str,
    client: Arc<Client>,
    settings: PageSettings,
) -> Result<PageObservation, RunError> {
    let url = page_url(target).map_err(RunError::InvalidTarget)?;
    let started_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let vantage = resolve::detect_vantage(&client).await;
    match (vantage.ipv4, vantage.ipv6) {
        (false, false) => return Err(RunError::NoNetwork),
        (true, false) => {
            return Err(RunError::NoIpv6 {
                host: url.host.clone(),
            });
        }
        (false, true) => return Err(RunError::NoIpv4),
        (true, true) => {}
    }

    let hosts = Arc::new(PageHosts::new(
        HostResolver::new(client, vantage),
        settings.allow_private,
    ));
    // The baseline first. A page that does not load on an ordinary
    // connection has nothing to be compared with.
    let (dual, browser) = load(&url, Mode::Dual, &settings, hosts.clone()).await?;
    if !dual.document().is_some_and(|d| d.answered()) {
        let why = dual
            .document()
            .and_then(|d| d.failed())
            .unwrap_or("no response")
            .to_string();
        return Err(RunError::PageUnreachable {
            url: url.to_string(),
            why,
        });
    }
    let mut loads = vec![dual];
    if settings.mode != Mode::Dual {
        loads.push(load(&url, settings.mode, &settings, hosts).await?.0);
    }
    Ok(PageObservation {
        url: url.to_string(),
        host: url.host,
        started_at_unix,
        vantage,
        browser,
        loads,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_host_is_loaded_over_https() {
        assert_eq!(
            page_url("Example.ORG").unwrap().to_string(),
            "https://example.org/"
        );
        assert_eq!(
            page_url("http://example.org:8080/shop?x=1")
                .unwrap()
                .to_string(),
            "http://example.org:8080/shop?x=1"
        );
        for bad in [
            "",
            "192.0.2.1",
            "https://[2001:db8::1]/",
            "ftp://example.org/",
        ] {
            assert!(page_url(bad).is_err(), "{bad}");
        }
    }
}
