//! TLS for the daemon-to-hub link, and the rule for when plaintext is allowed.
//!
//! On the tailnet, WireGuard already encrypts traffic between nodes. Plaintext is exposed on
//! any other path (a LAN address, a subnet router or exit node, a non-Tailscale network), so
//! the hub serves plaintext only on loopback or a Tailscale address, and the daemon sends
//! plaintext only to such an address or a `*.ts.net` name. Anything else needs TLS, which is
//! always verified; there is no option to skip verification.

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;

/// Certificate chain and private key, PEM files (as written by `tailscale cert`).
#[derive(Clone, Debug)]
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Loopback, Tailscale CGNAT (100.64.0.0/10) or Tailscale ULA (fd7a:115c:a1e0::/48).
pub fn plaintext_ok_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(a) => a.is_loopback() || (a.octets()[0] == 100 && a.octets()[1] & 0xC0 == 64),
        IpAddr::V6(a) => {
            let s = a.segments();
            a.is_loopback() || (s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0)
        }
    }
}

/// May the daemon use this `ws://` host without TLS? Loopback, `localhost`, a Tailscale
/// address, or a MagicDNS name under `.ts.net`.
pub fn plaintext_ok_host(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = h.parse::<IpAddr>() {
        return plaintext_ok_ip(ip);
    }
    let h = h.to_ascii_lowercase();
    h == "localhost" || (h.len() > ".ts.net".len() && h.ends_with(".ts.net"))
}

fn ring() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{}: no certificate found", path.display()));
    }
    Ok(certs)
}

fn read(files: &TlsFiles) -> Result<Arc<CertifiedKey>, String> {
    let certs = read_certs(&files.cert)?;
    let key = PrivateKeyDer::from_pem_file(&files.key)
        .map_err(|e| format!("{}: {e}", files.key.display()))?;
    let signer = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("{}: {e}", files.key.display()))?;
    Ok(Arc::new(CertifiedKey::new(certs, signer)))
}

/// The hub's server certificate, swappable at runtime (Tailscale certificates last 90 days).
pub struct ServerTls {
    files: TlsFiles,
    current: RwLock<Arc<CertifiedKey>>,
}

impl std::fmt::Debug for ServerTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerTls")
            .field("files", &self.files)
            .finish()
    }
}

impl ResolvesServerCert for ServerTls {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.read().unwrap().clone())
    }
}

impl ServerTls {
    pub fn load(files: TlsFiles) -> Result<ServerTls, String> {
        let current = RwLock::new(read(&files)?);
        Ok(ServerTls { files, current })
    }

    /// Re-read the files; on error the current certificate stays in use.
    pub fn reload(&self) -> Result<(), String> {
        let new = read(&self.files)?;
        *self.current.write().unwrap() = new;
        Ok(())
    }

    /// Is `host` (no port) a name or address the current certificate is valid for?
    pub fn host_matches(&self, host: &str) -> bool {
        let ck = self.current.read().unwrap().clone();
        let Some(leaf) = ck.cert.first() else {
            return false;
        };
        let Ok(ee) = webpki::EndEntityCert::try_from(leaf) else {
            return false;
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let Ok(name) = ServerName::try_from(host.to_string()) else {
            return false;
        };
        ee.verify_is_valid_for_subject_name(&name).is_ok()
    }

    /// Server config for HTTP/1.1 (the WebSocket upgrade needs it).
    pub fn server_config(self: &Arc<Self>) -> Result<Arc<rustls::ServerConfig>, String> {
        let mut c = rustls::ServerConfig::builder_with_provider(ring())
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_cert_resolver(self.clone());
        c.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(c))
    }
}

/// Client config for a wss:// hub: the system roots plus `extra_roots` (PEM files).
/// Certificates are always verified.
pub fn client_config(extra_roots: &[PathBuf]) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(c);
    }
    for p in extra_roots {
        for c in read_certs(p)? {
            roots.add(c).map_err(|e| format!("{}: {e}", p.display()))?;
        }
    }
    if roots.is_empty() {
        return Err("no trusted root certificates found".into());
    }
    let c = rustls::ClientConfig::builder_with_provider(ring())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(c))
}

/// A TLS listener for axum: handshakes run concurrently, each limited to 10 s, so a slow
/// client cannot hold up others.
pub(crate) struct TlsListener {
    rx: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    addr: SocketAddr,
}

impl TlsListener {
    pub(crate) fn new(
        tcp: TcpListener,
        config: Arc<rustls::ServerConfig>,
    ) -> (TlsListener, tokio::task::JoinHandle<()>) {
        let addr = tcp
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        let (tx, rx) = mpsc::channel(64);
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, peer)) = tcp.accept().await else {
                    continue;
                };
                if tx.is_closed() {
                    return;
                }
                let (tx, acceptor) = (tx.clone(), acceptor.clone());
                tokio::spawn(async move {
                    if let Ok(Ok(s)) =
                        tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await
                    {
                        let _ = tx.send((s, peer)).await;
                    }
                });
            }
        });
        (TlsListener { rx, addr }, task)
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(x) => x,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.addr)
    }
}

#[cfg(test)]
pub(crate) mod testcerts {
    //! Certificates for tests: a CA and leaves signed by it.
    use std::path::Path;

    pub struct Ca {
        pub params: rcgen::CertificateParams,
        pub key: rcgen::KeyPair,
    }

    pub fn ca() -> Ca {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "wormhole test CA");
        let key = rcgen::KeyPair::generate().unwrap();
        Ca { params: p, key }
    }

    /// A leaf for `names` signed by `ca`, written as cert.pem and key.pem in `dir`.
    pub fn leaf(ca: &Ca, names: &[&str], expired: bool, dir: &Path) -> super::TlsFiles {
        let mut p =
            rcgen::CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        if expired {
            p.not_before = rcgen::date_time_ymd(2020, 1, 1);
            p.not_after = rcgen::date_time_ymd(2021, 1, 1);
        }
        let key = rcgen::KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::new(ca.params.clone(), &ca.key);
        let cert = p.signed_by(&key, &issuer).unwrap();
        std::fs::create_dir_all(dir).unwrap();
        let files = super::TlsFiles {
            cert: dir.join("cert.pem"),
            key: dir.join("key.pem"),
        };
        std::fs::write(&files.cert, cert.pem()).unwrap();
        std::fs::write(&files.key, key.serialize_pem()).unwrap();
        files
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_only_on_loopback_and_tailscale_addresses() {
        for ok in [
            "127.0.0.1",
            "::1",
            "100.64.0.1",
            "100.127.255.254",
            "fd7a:115c:a1e0::1",
            "fd7a:115c:a1e0:ab12::99",
        ] {
            assert!(plaintext_ok_ip(ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "0.0.0.0",
            "::",
            "192.168.1.5",
            "10.0.0.2",
            "100.63.255.255",
            "100.128.0.1",
            "8.8.8.8",
            "fd7a:115c:a1e1::1",
            "fe80::1",
        ] {
            assert!(!plaintext_ok_ip(bad.parse().unwrap()), "{bad}");
        }
    }

    #[test]
    fn plaintext_hosts_for_the_daemon() {
        for ok in [
            "127.0.0.1",
            "localhost",
            "[::1]",
            "100.101.102.103",
            "hub.tail1234.ts.net",
            "HUB.Tail1234.TS.NET",
            "[fd7a:115c:a1e0::5]",
        ] {
            assert!(plaintext_ok_host(ok), "{ok}");
        }
        for bad in [
            "192.168.1.20",
            "hub.example.com",
            "ts.net.evil.com",
            "evilts.net",
            "10.1.2.3",
            "[fe80::1]",
            "",
        ] {
            assert!(!plaintext_ok_host(bad), "{bad}");
        }
    }

    #[test]
    fn host_check_uses_the_certificate_names() {
        let dir = std::env::temp_dir().join(format!("wh-tls-unit-{}", std::process::id()));
        let ca = testcerts::ca();
        let files = testcerts::leaf(&ca, &["hub.tail1234.ts.net"], false, &dir);
        let tls = ServerTls::load(files).unwrap();
        assert!(tls.host_matches("hub.tail1234.ts.net"));
        assert!(!tls.host_matches("evil.example"));
        assert!(!tls.host_matches("other.tail1234.ts.net"));
        // Reload picks up a new name; a broken file keeps the old certificate.
        testcerts::leaf(&ca, &["hub2.tail1234.ts.net"], false, &dir);
        tls.reload().unwrap();
        assert!(tls.host_matches("hub2.tail1234.ts.net"));
        std::fs::write(dir.join("cert.pem"), "garbage").unwrap();
        assert!(tls.reload().is_err());
        assert!(tls.host_matches("hub2.tail1234.ts.net"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
