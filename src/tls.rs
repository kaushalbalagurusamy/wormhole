//! TLS for the daemon-to-hub link, and the rule for when plaintext is allowed.
//!
//! On the tailnet, WireGuard already encrypts traffic between nodes. Plaintext is exposed on
//! any other path (a LAN address, a subnet router or exit node, a non-Tailscale network), so
//! the hub serves plaintext only on loopback or a Tailscale address, and the daemon sends
//! plaintext only to such an address or a `*.ts.net` name. Anything else needs TLS, which is
//! always verified; there is no option to skip verification.

use std::net::IpAddr;
use std::path::PathBuf;

/// Certificate chain and private key, PEM files (as written by `tailscale cert`).
#[derive(Clone, Debug)]
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Loopback, Tailscale CGNAT (100.64.0.0/10) or Tailscale ULA (fd7a:115c:a1e0::/48).
pub fn plaintext_ok_ip(ip: IpAddr) -> bool {
    let _ = ip;
    todo!()
}

/// May the daemon use this `ws://` host without TLS? Loopback, `localhost`, a Tailscale
/// address, or a MagicDNS name under `.ts.net`.
pub fn plaintext_ok_host(host: &str) -> bool {
    let _ = host;
    todo!()
}

/// The hub's server certificate, swappable at runtime (Tailscale certificates last 90 days).
pub struct ServerTls {}

impl ServerTls {
    pub fn load(files: TlsFiles) -> Result<ServerTls, String> {
        let _ = files;
        todo!()
    }

    /// Re-read the files; on error the current certificate stays in use.
    pub fn reload(&self) -> Result<(), String> {
        todo!()
    }

    /// Is `host` (no port) a name or address the current certificate is valid for?
    pub fn host_matches(&self, host: &str) -> bool {
        let _ = host;
        todo!()
    }
}

#[cfg(test)]
pub(crate) mod testcerts {
    //! Certificates for tests: a CA and leaves signed by it.
    use std::path::Path;

    pub struct Ca {
        pub params: rcgen::CertificateParams,
        pub cert: rcgen::Certificate,
        pub key: rcgen::KeyPair,
    }

    pub fn ca() -> Ca {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "wormhole test CA");
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = p.self_signed(&key).unwrap();
        Ca {
            params: p,
            cert,
            key,
        }
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
