//! A local web server for tests, with one IPv4 and one IPv6 listener on
//! the same port that can be made to differ, or to be absent.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use v6blick::probe::{BoxFuture, Resolve};

pub const V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
pub const V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

/// A path's answer: status, headers and body.
pub type Routes = HashMap<String, (u16, Vec<(String, String)>, String)>;

/// What one listener does with a connection.
#[derive(Clone)]
pub enum Site {
    /// Answer every request this way. `cert` is `Some('a')` or
    /// `Some('b')` for HTTPS with that test certificate, `None` for
    /// plain HTTP. `routes` maps a path to (status, headers, body); any
    /// other path gets a 404.
    Serve { cert: Option<char>, routes: Routes },
    /// Accept the connection and never say anything.
    Silent,
}

impl Site {
    /// One page at `/`.
    pub fn page(cert: Option<char>, status: u16, body: &str) -> Site {
        Site::Serve {
            cert,
            routes: HashMap::new(),
        }
        .route("/", status, &[], body)
    }

    pub fn route(mut self, path: &str, status: u16, headers: &[(&str, &str)], body: &str) -> Site {
        if let Site::Serve { routes, .. } = &mut self {
            let headers = headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect();
            routes.insert(path.to_string(), (status, headers, body.to_string()));
        }
        self
    }

    /// A redirect at `path`.
    pub fn redirect(self, path: &str, status: u16, location: &str) -> Site {
        self.route(path, status, &[("Location", location)], "")
    }
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn acceptor(which: char) -> TlsAcceptor {
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(fixture(&format!("test-cert-{which}.pem")))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_file(fixture(&format!("test-key-{which}.pem"))).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

async fn respond<S>(mut stream: S, routes: &Routes)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut request = Vec::new();
    let mut chunk = [0u8; 2048];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") && request.len() < 16 * 1024 {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&request);
    let path = text.split(' ').nth(1).unwrap_or("/");
    let not_found = (404, Vec::new(), "not found".to_string());
    let (status, headers, body) = routes.get(path).unwrap_or(&not_found);
    let mut head = format!(
        "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn run(listener: TcpListener, site: Site) {
    tokio::spawn(async move {
        let tls = match &site {
            Site::Serve { cert: Some(c), .. } => Some(acceptor(*c)),
            _ => None,
        };
        let mut held = Vec::new();
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            match &site {
                Site::Silent => held.push(stream),
                Site::Serve { routes, .. } => {
                    let (routes, tls) = (routes.clone(), tls.clone());
                    tokio::spawn(async move {
                        match tls {
                            Some(tls) => {
                                if let Ok(stream) = tls.accept(stream).await {
                                    respond(stream, &routes).await;
                                }
                            }
                            None => respond(stream, &routes).await,
                        }
                    });
                }
            }
        }
    });
}

/// Start an IPv4 and an IPv6 listener on one port of this machine and
/// return the port. `sites` is told the port and says what each listener
/// does; `None` means nothing listens there, so a connection is refused.
pub async fn serve(sites: impl FnOnce(u16) -> (Option<Site>, Option<Site>)) -> u16 {
    for _ in 0..50 {
        let v4 = TcpListener::bind(SocketAddr::new(V4, 0)).await.unwrap();
        let port = v4.local_addr().unwrap().port();
        // The same port number must be free on the IPv6 side too.
        let Ok(v6) = TcpListener::bind(SocketAddr::new(V6, port)).await else {
            continue;
        };
        let (site4, site6) = sites(port);
        // A listener that is dropped leaves its port closed.
        if let Some(site) = site4 {
            run(v4, site);
        }
        if let Some(site) = site6 {
            run(v6, site);
        }
        return port;
    }
    panic!("no port is free on both 127.0.0.1 and ::1");
}

/// Answers from a fixed table. A host that is not in it does not exist.
#[derive(Default)]
pub struct Hosts(pub HashMap<String, Vec<IpAddr>>);

impl Hosts {
    pub fn with(mut self, host: &str, addresses: &[IpAddr]) -> Self {
        self.0.insert(host.to_string(), addresses.to_vec());
        self
    }
}

impl Resolve for Hosts {
    fn addresses<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, String>> {
        Box::pin(async move {
            self.0
                .get(host)
                .cloned()
                .ok_or_else(|| "no such name".to_string())
        })
    }
}
