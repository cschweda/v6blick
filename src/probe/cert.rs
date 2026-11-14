//! Reading the certificate a server presents.
//!
//! The verifier and the DER reader are copied from zoneblick
//! (`src/resolver/smtp.rs`); see `DECISIONS.md`.
//!
//! v6blick compares what a server presents over IPv4 with what it presents
//! over IPv6. It does not decide whether a browser would trust either, so
//! no list of trusted authorities is needed.

use std::sync::Arc;

use ring::digest;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

use crate::observe::Certificate;

/// Accepts any certificate, so that it can be read and compared.
/// Handshake signatures are still verified, so the server must hold the
/// key of the certificate it shows.
#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The TLS settings of every probe: any certificate, HTTP/1.1 only.
pub fn client_config() -> Result<Arc<rustls::ClientConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// SHA-256 of `data`, as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, data).as_ref())
}

/// What v6blick keeps of a certificate, given as DER, for a connection
/// that asked for `host`.
pub fn summarise(der: &[u8], host: &str) -> Certificate {
    let info = certificate_info(der);
    let names = info.as_ref().map(|i| i.names.clone()).unwrap_or_default();
    Certificate {
        sha256: sha256_hex(der),
        covers_host: certificate_covers(&names, host),
        not_after_unix: info.map(|i| i.not_after_unix),
        names,
    }
}

/// When a certificate runs out, and the DNS names it is for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CertificateInfo {
    pub not_after_unix: u64,
    pub names: Vec<String>,
}

/// At most this many names are read from one certificate.
const MAX_CERTIFICATE_NAMES: usize = 100;

/// A time in a certificate: `YYMMDDHHMMSSZ` (tag 0x17) or
/// `YYYYMMDDHHMMSSZ` (tag 0x18).
fn certificate_time(tag: u8, content: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(content).ok()?;
    let digits = text.strip_suffix('Z')?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (year, rest) = match (tag, digits.len()) {
        (0x17, 12) => {
            let yy: u32 = digits[..2].parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &digits[2..])
        }
        (0x18, 14) => (digits[..4].parse().ok()?, &digits[4..]),
        _ => return None,
    };
    let num = |from: usize, to: usize| rest.get(from..to)?.parse::<i64>().ok();
    let (month, day) = (num(0, 2)?, num(2, 4)?);
    let (hour, minute, second) = (num(4, 6)?, num(6, 8)?, num(8, 10)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    let secs =
        days_from_civil(i64::from(year), month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    u64::try_from(secs).ok()
}

/// Read the end of validity and the subject alternative names of a
/// certificate. The certificate comes from a server someone else runs, so
/// every length is checked and names are kept only when they look like
/// DNS names.
fn certificate_info(certificate: &[u8]) -> Option<CertificateInfo> {
    let (0x30, _, body, _) = der(certificate)? else {
        return None;
    };
    let (0x30, _, mut fields, _) = der(body)? else {
        return None;
    };
    let (tag, _, _, rest) = der(fields)?;
    if tag == 0xa0 {
        fields = rest;
    }
    // serial, signature algorithm, issuer
    for _ in 0..3 {
        fields = der(fields)?.3;
    }
    let (0x30, _, validity, mut fields) = der(fields)? else {
        return None;
    };
    let (_, _, _, after) = der(validity)?;
    let (tag, _, content, _) = der(after)?;
    let not_after_unix = certificate_time(tag, content)?;
    // subject, public key
    for _ in 0..2 {
        fields = der(fields)?.3;
    }
    let mut names = Vec::new();
    while let Some((tag, _, content, rest)) = der(fields) {
        fields = rest;
        // [3]: the extensions, a list inside a list.
        if tag != 0xa3 {
            continue;
        }
        let Some((0x30, _, mut extensions, _)) = der(content) else {
            break;
        };
        while let Some((0x30, _, extension, rest)) = der(extensions) {
            extensions = rest;
            let Some((0x06, _, oid, mut value)) = der(extension) else {
                continue;
            };
            // 2.5.29.17, subjectAltName
            if oid != [0x55, 0x1d, 0x11] {
                continue;
            }
            // An optional "critical" flag comes before the value.
            if let Some((0x01, _, _, rest)) = der(value) {
                value = rest;
            }
            let Some((0x04, _, inner, _)) = der(value) else {
                continue;
            };
            let Some((0x30, _, mut general, _)) = der(inner) else {
                continue;
            };
            while let Some((tag, _, name, rest)) = der(general) {
                general = rest;
                // [2]: a DNS name.
                if tag == 0x82
                    && names.len() < MAX_CERTIFICATE_NAMES
                    && !name.is_empty()
                    && name.len() <= 253
                    && name
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._*".contains(b))
                {
                    names.push(String::from_utf8_lossy(name).to_ascii_lowercase());
                }
            }
        }
    }
    names.sort();
    names.dedup();
    Some(CertificateInfo {
        not_after_unix,
        names,
    })
}

/// Whether a certificate with these names is good for `host`. A wildcard
/// stands for exactly one label, the leftmost.
pub(crate) fn certificate_covers(names: &[String], host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    names.iter().any(|name| {
        let name = name.trim_end_matches('.');
        match name.strip_prefix("*.") {
            Some(parent) => host
                .split_once('.')
                .is_some_and(|(label, rest)| !label.is_empty() && rest == parent),
            None => name == host,
        }
    })
}
/// One DER element: its tag, the whole element, its content, and what
/// follows it.
type Element<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

fn der(data: &[u8]) -> Option<Element<'_>> {
    let tag = *data.first()?;
    let first = *data.get(1)?;
    let (len, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let bytes = data.get(2..2 + count)?;
        (
            bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize),
            2 + count,
        )
    };
    let end = header.checked_add(len)?;
    let whole = data.get(..end)?;
    Some((tag, whole, &whole[header..], &data[end..]))
}

/// Days from 1970-01-01 to a date in the Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
