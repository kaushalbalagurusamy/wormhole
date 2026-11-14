//! Who is on the other end of a connection. The hub never takes identity from a token or
//! from the payload: it asks the private network (Tailscale) about the peer address.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Peer {
    pub user: String,
    pub machine: String,
}

impl Peer {
    pub fn key(&self) -> String {
        format!("{}@{}", self.user, self.machine)
    }
}

#[derive(Clone, Debug)]
pub enum IdentityConfig {
    /// `tailscale whois --json <peer ip>`; connections it cannot identify are rejected.
    Tailscale { bin: PathBuf },
    /// For tests and single-machine use: the peer claims `user@machine` in a header. The
    /// hub refuses to start with this unless it listens on loopback, and rejects any peer
    /// that is not loopback.
    Static,
}

fn plausible(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && !s.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Parse `tailscale whois --json` output. Requires a node name and a login name.
pub fn parse_whois(json: &str) -> Option<Peer> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let node = v.get("Node")?;
    let machine = node
        .get("ComputedName")
        .and_then(|n| n.as_str())
        .filter(|n| !n.is_empty())
        .or_else(|| node.get("Name")?.as_str()?.split('.').next())?;
    let login = v.get("UserProfile")?.get("LoginName")?.as_str()?;
    // Tagged nodes have no user; the tag is the identity.
    let user = if login == "tagged-devices" {
        node.get("Tags")?.as_array()?.first()?.as_str()?
    } else {
        login
    };
    (plausible(user) && plausible(machine)).then(|| Peer {
        user: user.into(),
        machine: machine.into(),
    })
}

/// Parse a static claim `user@machine` (split at the last `@`).
pub fn parse_static(claim: &str) -> Option<Peer> {
    let (user, machine) = claim.rsplit_once('@')?;
    (plausible(user) && plausible(machine)).then(|| Peer {
        user: user.into(),
        machine: machine.into(),
    })
}

pub(crate) fn canonical_ip(addr: SocketAddr) -> IpAddr {
    addr.ip().to_canonical()
}

/// Resolves peers for the hub. whois runs once per new connection or request and is not
/// cached, so a reassigned tailnet address is never mapped to its previous owner.
pub struct Identifier {
    cfg: IdentityConfig,
}

impl Identifier {
    pub fn new(cfg: IdentityConfig) -> Identifier {
        Identifier { cfg }
    }

    /// `None` means reject the connection.
    pub async fn identify(&self, peer: SocketAddr, static_claim: Option<&str>) -> Option<Peer> {
        let ip = canonical_ip(peer);
        match &self.cfg {
            IdentityConfig::Static => {
                if !ip.is_loopback() {
                    return None;
                }
                parse_static(static_claim?)
            }
            IdentityConfig::Tailscale { bin } => {
                let out = tokio::time::timeout(
                    Duration::from_secs(3),
                    tokio::process::Command::new(bin)
                        .arg("whois")
                        .arg("--json")
                        .arg(ip.to_string())
                        .stdin(std::process::Stdio::null())
                        .kill_on_drop(true)
                        .output(),
                )
                .await
                .ok()?
                .ok()?;
                if !out.status.success() {
                    return None;
                }
                parse_whois(&String::from_utf8_lossy(&out.stdout))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WHOIS: &str = r#"{
      "Node": {"ID": 1, "Name": "laptop-a.example-tailnet.ts.net.", "ComputedName": "laptop-a", "Tags": null},
      "UserProfile": {"ID": 2, "LoginName": "alice@example.com", "DisplayName": "Alice"},
      "CapMap": null
    }"#;

    #[test]
    fn whois_gives_login_and_node() {
        assert_eq!(
            parse_whois(WHOIS),
            Some(Peer {
                user: "alice@example.com".into(),
                machine: "laptop-a".into()
            })
        );
    }

    #[test]
    fn tagged_node_uses_its_tag() {
        let j = r#"{"Node":{"Name":"ci.x.ts.net.","ComputedName":"ci","Tags":["tag:ci"]},
                   "UserProfile":{"LoginName":"tagged-devices"}}"#;
        assert_eq!(parse_whois(j).unwrap().user, "tag:ci");
    }

    #[test]
    fn whois_rejects_garbage_and_missing_fields() {
        assert_eq!(parse_whois("peer not found"), None);
        assert_eq!(parse_whois("{}"), None);
        assert_eq!(parse_whois(r#"{"Node":{"ComputedName":"a"},"UserProfile":{"LoginName":""}}"#), None);
        assert_eq!(parse_whois(r#"{"Node":{"ComputedName":""},"UserProfile":{"LoginName":"a@b"}}"#), None);
    }

    #[test]
    fn static_claims() {
        assert_eq!(
            parse_static("alice@example.com@laptop"),
            Some(Peer {
                user: "alice@example.com".into(),
                machine: "laptop".into()
            })
        );
        assert_eq!(parse_static("nomachine"), None);
        assert_eq!(parse_static("@m"), None);
        assert_eq!(parse_static("u@"), None);
        assert_eq!(parse_static(&format!("u@{}", "m".repeat(200))), None);
    }

    fn fake_tailscale(dir: &std::path::Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir).unwrap();
        let bin = dir.join("tailscale");
        // Prints whatever is in `answer`, or fails if the file is missing.
        std::fs::write(&bin, format!("#!/bin/sh\nexec cat '{}'\n", dir.join("answer").display())).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        bin
    }

    #[tokio::test]
    async fn whois_is_asked_on_every_connection() {
        let dir = std::env::temp_dir().join(format!("wh-ts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let id = Identifier::new(IdentityConfig::Tailscale { bin: fake_tailscale(&dir) });
        let peer: SocketAddr = "100.64.0.5:4000".parse().unwrap();

        std::fs::write(dir.join("answer"), WHOIS).unwrap();
        assert_eq!(id.identify(peer, None).await.unwrap().machine, "laptop-a");

        // The same IP now belongs to a different node: the new identity is used at once.
        std::fs::write(
            dir.join("answer"),
            WHOIS.replace("laptop-a", "laptop-b").replace("alice@", "bob@"),
        )
        .unwrap();
        let p = id.identify(peer, None).await.unwrap();
        assert_eq!((p.user.as_str(), p.machine.as_str()), ("bob@example.com", "laptop-b"));

        // whois fails: the connection is refused (identity fails closed).
        std::fs::remove_file(dir.join("answer")).unwrap();
        assert_eq!(id.identify(peer, None).await, None);
        // A static claim header is ignored under Tailscale identity.
        assert_eq!(id.identify(peer, Some("alice@laptop-a")).await, None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
