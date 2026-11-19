//! TLS certificate material for the LAN listener.
//!
//! Stage 1 serves plain HTTP on loopback (so local MCP clients keep working)
//! and TLS on every local LAN address (so a phone browser gets a secure context
//! and WebCrypto works). Certificates are self-signed, generated once, reused
//! while they still cover the current addresses, and regenerated when they
//! expire, fail to parse, or no longer include a current LAN IP.

use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{info, warn};

/// Certificate + key paths plus the facts the console and startup output show.
#[derive(Debug, Clone)]
pub struct TlsMaterial {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// SHA-256 of the certificate DER, lowercase, colon-separated.
    pub fingerprint: String,
    pub san_ips: Vec<IpAddr>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct CertMeta {
    san_ips: Vec<String>,
    not_after_unix: u64,
    fingerprint: String,
}

fn tls_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("tls")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Return usable certificate material, generating it on first use or when the
/// stored certificate no longer fits the current machine.
pub fn ensure_certificate(data_dir: &Path, san_ips: &[IpAddr]) -> anyhow::Result<TlsMaterial> {
    let dir = tls_dir(data_dir);
    std::fs::create_dir_all(&dir)?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    let meta_path = dir.join("cert-meta.json");

    if let Some(material) = reuse_existing(&cert_path, &key_path, &meta_path, san_ips) {
        return Ok(material);
    }

    generate(&cert_path, &key_path, &meta_path, san_ips)
}

fn reuse_existing(
    cert_path: &Path,
    key_path: &Path,
    meta_path: &Path,
    san_ips: &[IpAddr],
) -> Option<TlsMaterial> {
    let cert_pem = std::fs::read_to_string(cert_path).ok()?;
    let key_pem = std::fs::read_to_string(key_path).ok()?;
    if rcgen::KeyPair::from_pem(&key_pem).is_err() {
        warn!("tls: stored key is unparseable; regenerating the certificate");
        return None;
    }
    let der = match cert_der(&cert_pem) {
        Ok(der) => der,
        Err(e) => {
            warn!("tls: stored certificate is unparseable ({e}); regenerating");
            return None;
        }
    };
    let meta: CertMeta = match std::fs::read_to_string(meta_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(meta) => meta,
        None => {
            warn!("tls: certificate metadata missing; regenerating");
            return None;
        }
    };
    // Regenerate proactively a day before expiry rather than failing mid-use.
    if meta.not_after_unix <= now_unix() + 86_400 {
        warn!("tls: stored certificate is expired or about to expire; regenerating");
        return None;
    }
    let stored: Vec<IpAddr> = meta
        .san_ips
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    if san_ips.iter().any(|ip| !stored.contains(ip)) {
        warn!("tls: a current LAN address is missing from the certificate SANs; regenerating");
        return None;
    }

    Some(TlsMaterial {
        cert_path: cert_path.to_path_buf(),
        key_path: key_path.to_path_buf(),
        fingerprint: fingerprint_of(&der),
        san_ips: stored,
    })
}

fn generate(
    cert_path: &Path,
    key_path: &Path,
    meta_path: &Path,
    san_ips: &[IpAddr],
) -> anyhow::Result<TlsMaterial> {
    let mut names: Vec<String> = vec!["localhost".to_string(), "127.0.0.1".to_string(), "::1".to_string()];
    if let Ok(hostname) = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")) {
        if !hostname.trim().is_empty() {
            names.push(hostname);
        }
    }
    for ip in san_ips {
        names.push(ip.to_string());
    }

    let mut params = rcgen::CertificateParams::new(names)?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "YL Agent Runtime");
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    let not_after_unix = now_unix() + 10 * 365 * 24 * 60 * 60;
    params.not_after = rcgen::date_time_ymd(2034, 12, 31);

    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    std::fs::write(cert_path, &cert_pem)?;
    std::fs::write(key_path, &key_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
    }

    let der = cert_der(&cert_pem)?;
    let fingerprint = fingerprint_of(&der);
    let meta = CertMeta {
        san_ips: san_ips.iter().map(ToString::to_string).collect(),
        not_after_unix,
        fingerprint: fingerprint.clone(),
    };
    std::fs::write(meta_path, serde_json::to_vec_pretty(&meta)?)?;

    info!(
        "tls: generated a self-signed certificate at {} (SANs: {})",
        cert_path.display(),
        san_ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );

    Ok(TlsMaterial {
        cert_path: cert_path.to_path_buf(),
        key_path: key_path.to_path_buf(),
        fingerprint,
        san_ips: san_ips.to_vec(),
    })
}

/// Decode a PEM certificate to DER.
pub fn cert_der(cert_pem: &str) -> anyhow::Result<Vec<u8>> {
    let body: String = cert_pem
        .lines()
        .filter(|line| !line.contains("-----"))
        .collect::<Vec<_>>()
        .join("");
    if body.is_empty() {
        anyhow::bail!("empty certificate PEM");
    }
    Ok(base64::engine::general_purpose::STANDARD.decode(body)?)
}

/// `AA:BB:...` SHA-256 fingerprint, as browsers display it.
pub fn fingerprint_of(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Every local non-loopback IPv4 address. Empty when the OS reports none.
pub fn local_ipv4_addrs() -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            let ip = iface.ip();
            if ip.is_ipv4() && !ip.is_loopback() && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_is_generated_once_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let ips = vec!["192.168.1.5".parse().unwrap()];
        let a = ensure_certificate(dir.path(), &ips).unwrap();
        let b = ensure_certificate(dir.path(), &ips).unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.san_ips, ips);
        assert!(a.cert_path.exists() && a.key_path.exists());
    }

    #[test]
    fn cert_regenerates_when_a_new_ip_is_missing_from_sans() {
        let dir = tempfile::tempdir().unwrap();
        let a = ensure_certificate(dir.path(), &["192.168.1.5".parse().unwrap()]).unwrap();
        let b = ensure_certificate(dir.path(), &["192.168.1.9".parse().unwrap()]).unwrap();
        assert_ne!(a.fingerprint, b.fingerprint);
        assert_eq!(
            b.san_ips,
            vec!["192.168.1.9".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn cert_regenerates_when_files_are_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let a = ensure_certificate(dir.path(), &[]).unwrap();
        std::fs::write(&a.cert_path, b"not a pem").unwrap();
        let b = ensure_certificate(dir.path(), &[]).unwrap();
        assert_ne!(a.fingerprint, b.fingerprint);
        assert!(cert_der(&std::fs::read_to_string(&b.cert_path).unwrap()).is_ok());
    }

    #[test]
    fn fingerprint_is_colon_separated_sha256_hex() {
        let dir = tempfile::tempdir().unwrap();
        let m = ensure_certificate(dir.path(), &[]).unwrap();
        let parts: Vec<_> = m.fingerprint.split(':').collect();
        assert_eq!(parts.len(), 32);
        assert!(parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit())));
    }
}
