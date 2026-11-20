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
    // Chrome requires explicit key usage + serverAuth EKU on TLS server certs.
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

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

/// Which addresses get a listener, and with which transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerPlan {
    /// Plain HTTP listeners (loopback, plus LAN addresses only when explicitly
    /// allowed).
    pub plain: Vec<std::net::SocketAddr>,
    /// TLS listeners, one per local LAN address.
    pub tls: Vec<std::net::SocketAddr>,
    pub lan_ips: Vec<IpAddr>,
}

/// Plan the listeners for the current machine.
pub fn plan_listeners(
    host: &str,
    port: u16,
    allow_remote: bool,
    tls_off: bool,
    insecure: bool,
) -> anyhow::Result<ListenerPlan> {
    plan_listeners_with(host, port, allow_remote, tls_off, insecure, local_ipv4_addrs())
}

fn parse_addr(ip: &str, port: u16) -> anyhow::Result<std::net::SocketAddr> {
    format!("{ip}:{port}")
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid listen address {ip}:{port}: {e}"))
}

fn plan_listeners_with(
    host: &str,
    port: u16,
    allow_remote: bool,
    tls_off: bool,
    insecure: bool,
    lan_ips: Vec<IpAddr>,
) -> anyhow::Result<ListenerPlan> {
    let loopback = "127.0.0.1";
    let mut plain = Vec::new();
    let mut tls = Vec::new();

    if !allow_remote {
        let bind_host = if host == "0.0.0.0" || host == "::" {
            loopback
        } else {
            host
        };
        if bind_host == loopback || bind_host == "localhost" || bind_host == "::1" {
            plain.push(parse_addr(loopback, port)?);
        } else {
            // An explicit non-loopback --host is a LAN bind: it needs TLS.
            let ip: IpAddr = bind_host
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid --host {bind_host}: {e}"))?;
            if tls_off {
                if !insecure {
                    anyhow::bail!(
                        "refusing plaintext on a LAN interface ({bind_host}); \
                         pass --insecure-http or set remote.allow_plaintext_lan = true"
                    );
                }
                plain.push(parse_addr(bind_host, port)?);
            } else {
                tls.push(parse_addr(bind_host, port)?);
            }
            return Ok(ListenerPlan {
                plain,
                tls,
                lan_ips: vec![ip],
            });
        }
        return Ok(ListenerPlan {
            plain,
            tls,
            lan_ips: vec![],
        });
    }

    // Remote: loopback stays plain, every LAN address gets TLS (or plaintext
    // only with an explicit override).
    plain.push(parse_addr(loopback, port)?);
    if tls_off {
        if !insecure {
            anyhow::bail!(
                "refusing plaintext on a LAN interface; \
                 pass --insecure-http or set remote.allow_plaintext_lan = true"
            );
        }
        for ip in &lan_ips {
            plain.push(parse_addr(&ip.to_string(), port)?);
        }
    } else {
        for ip in &lan_ips {
            tls.push(parse_addr(&ip.to_string(), port)?);
        }
    }
    Ok(ListenerPlan {
        plain,
        tls,
        lan_ips,
    })
}

/// Install the rustls crypto provider once per process. `axum-server` is built
/// with `tls-rustls-no-provider`, so the provider choice stays ours (`ring`,
/// never `aws-lc`).
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Serve `app` over TLS on an already-bound listener.
pub async fn spawn_tls_listener(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    cert: &Path,
    key: &Path,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    install_crypto_provider();
    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;
    let std_listener = listener.into_std()?;
    std_listener.set_nonblocking(true)?;
    let server = axum_server::from_tcp_rustls(std_listener, config)?;
    Ok(tokio::spawn(async move {
        if let Err(e) = server
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
        {
            warn!("tls listener stopped: {e}");
        }
    }))
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

    #[test]
    fn listener_plan_is_plain_loopback_without_remote() {
        let p = plan_listeners_with("127.0.0.1", 8077, false, false, false, vec![]).unwrap();
        assert_eq!(p.plain, vec!["127.0.0.1:8077".parse().unwrap()]);
        assert!(p.tls.is_empty());
    }

    #[test]
    fn remote_plan_is_plain_loopback_plus_tls_on_each_lan_ip() {
        let p = plan_listeners_with(
            "127.0.0.1",
            8077,
            true,
            false,
            false,
            vec!["192.168.1.5".parse().unwrap(), "10.0.0.7".parse().unwrap()],
        )
        .unwrap();
        assert_eq!(p.plain, vec!["127.0.0.1:8077".parse().unwrap()]);
        assert_eq!(
            p.tls,
            vec![
                "192.168.1.5:8077".parse().unwrap(),
                "10.0.0.7:8077".parse().unwrap()
            ]
        );
    }

    #[test]
    fn plaintext_lan_requires_the_insecure_flag() {
        let err = plan_listeners_with(
            "192.168.1.5",
            8077,
            true,
            true,
            false,
            vec!["192.168.1.5".parse().unwrap()],
        )
        .unwrap_err();
        assert!(err.to_string().contains("insecure"), "{err}");
        let ok = plan_listeners_with(
            "192.168.1.5",
            8077,
            true,
            true,
            true,
            vec!["192.168.1.5".parse().unwrap()],
        )
        .unwrap();
        assert_eq!(ok.plain.len(), 2);
        assert!(ok.tls.is_empty());
    }

    #[test]
    fn plan_never_contains_the_wildcard_address() {
        let p = plan_listeners_with("0.0.0.0", 8077, true, false, false, vec![])
            .unwrap();
        assert!(p.plain.iter().all(|a| a.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)));
        assert!(p.tls.iter().all(|a| a.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)));
    }

    async fn test_app() -> axum::Router {
        axum::Router::new().route("/health", axum::routing::get(|| async { "ok" }))
    }

    fn pinned_connector(cert_pem: &str) -> tokio_rustls::TlsConnector {
        install_crypto_provider();
        let der = rustls::pki_types::CertificateDer::from(cert_der(cert_pem).unwrap());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
    }

    async fn send_health<S>(stream: &mut S, host: &str) -> String
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let request = format!(
            "GET /health HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf).to_string()
    }

    #[tokio::test]
    async fn https_get_with_pinned_cert_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let ip: IpAddr = "127.0.0.2".parse().unwrap();
        let m = ensure_certificate(dir.path(), &[ip]).unwrap();
        let listener = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = spawn_tls_listener(listener, test_app().await, &m.cert_path, &m.key_path)
            .await
            .unwrap();

        let pem = std::fs::read_to_string(&m.cert_path).unwrap();
        let connector = pinned_connector(&pem);
        let tcp = tokio::net::TcpStream::connect((ip, port)).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from(ip.to_string()).unwrap();
        let mut stream = connector.connect(server_name, tcp).await.unwrap();
        let response = send_health(&mut stream, &ip.to_string()).await;

        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        handle.abort();
    }

    #[tokio::test]
    async fn plain_http_to_the_tls_port_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let ip: IpAddr = "127.0.0.2".parse().unwrap();
        let m = ensure_certificate(dir.path(), &[ip]).unwrap();
        let listener = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = spawn_tls_listener(listener, test_app().await, &m.cert_path, &m.key_path)
            .await
            .unwrap();

        let mut tcp = tokio::net::TcpStream::connect((ip, port)).await.unwrap();
        let response = send_health(&mut tcp, &ip.to_string()).await;
        assert!(!response.starts_with("HTTP/1.1 200"), "{response}");
        handle.abort();
    }

    #[tokio::test]
    async fn plain_loopback_and_tls_share_the_same_port_number() {
        let dir = tempfile::tempdir().unwrap();
        let ip: IpAddr = "127.0.0.2".parse().unwrap();
        let m = ensure_certificate(dir.path(), &[ip]).unwrap();

        let plain = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = plain.local_addr().unwrap().port();
        let tls = tokio::net::TcpListener::bind((ip, port)).await.unwrap();

        let app = test_app().await;
        let plain_app = app.clone();
        let plain_task = tokio::spawn(async move {
            let _ = axum::serve(
                plain,
                plain_app
                    .into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await;
        });
        let tls_task = spawn_tls_listener(tls, app, &m.cert_path, &m.key_path)
            .await
            .unwrap();

        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let plain_response = send_health(&mut tcp, "127.0.0.1").await;
        assert!(plain_response.starts_with("HTTP/1.1 200"), "{plain_response}");

        let pem = std::fs::read_to_string(&m.cert_path).unwrap();
        let connector = pinned_connector(&pem);
        let tcp = tokio::net::TcpStream::connect((ip, port)).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from(ip.to_string()).unwrap();
        let mut stream = connector.connect(server_name, tcp).await.unwrap();
        let tls_response = send_health(&mut stream, &ip.to_string()).await;
        assert!(tls_response.starts_with("HTTP/1.1 200"), "{tls_response}");

        plain_task.abort();
        tls_task.abort();
    }
}
