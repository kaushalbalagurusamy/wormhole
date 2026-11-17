//! Who is on the other end of a connection. The hub never takes identity from a token or
//! from the payload: it asks the private network (Tailscale) about the peer address.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;

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

/// The name `tailscale whois` gives every device shared in from another tailnet: Tailscale hides
/// the real name, so all of a sharer's machines look alike (ADR 0004).
pub const SHARED_PLACEHOLDER: &str = "device-of-shared-to-user";

/// Like [`parse_whois`], but a shared-in device is named after its tailnet address, which the hub
/// read from the connection itself, so it is as trustworthy as whois and stable per device.
pub fn parse_whois_at(json: &str, ip: Option<IpAddr>) -> Option<Peer> {
    let mut p = parse_whois(json)?;
    if let (true, Some(ip)) = (p.machine == SHARED_PLACEHOLDER, ip) {
        p.machine = format!("shared-{}", ip.to_string().replace(['.', ':'], "-"));
    }
    Some(p)
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

/// Most `tailscale whois` processes the hub runs at once; further lookups wait.
pub const WHOIS_LIMIT: usize = 4;

pub(crate) fn canonical_ip(addr: SocketAddr) -> IpAddr {
    addr.ip().to_canonical()
}

/// Resolves peers for the hub. whois runs once per new connection or request and is not
/// cached, so a reassigned tailnet address is never mapped to its previous owner. At most
/// `WHOIS_LIMIT` run at once, so requests cannot make the hub spawn processes without bound.
pub struct Identifier {
    cfg: IdentityConfig,
    /// Users (login names, or tags for tagged nodes) accepted; empty accepts every identified peer.
    allow: Vec<String>,
    whois: Arc<Semaphore>,
}

impl Identifier {
    pub fn new(cfg: IdentityConfig) -> Identifier {
        Self::with_allowlist(cfg, Vec::new())
    }

    pub fn with_allowlist(cfg: IdentityConfig, allow: Vec<String>) -> Identifier {
        Identifier {
            cfg,
            allow,
            whois: Arc::new(Semaphore::new(WHOIS_LIMIT)),
        }
    }

    /// `None` means reject the connection.
    pub async fn identify(&self, peer: SocketAddr, static_claim: Option<&str>) -> Option<Peer> {
        let p = self.resolve(peer, static_claim).await?;
        (self.allow.is_empty() || self.allow.contains(&p.user)).then_some(p)
    }

    async fn resolve(&self, peer: SocketAddr, static_claim: Option<&str>) -> Option<Peer> {
        let ip = canonical_ip(peer);
        match &self.cfg {
            IdentityConfig::Static => {
                if !ip.is_loopback() {
                    return None;
                }
                parse_static(static_claim?)
            }
            IdentityConfig::Tailscale { bin } => {
                let permit = self.whois.clone().acquire_owned().await.ok()?;
                let mut cmd = tokio::process::Command::new(bin);
                cmd.arg("whois")
                    .arg("--json")
                    .arg(ip.to_string())
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .kill_on_drop(true);
                // An owned task, so a dropped requester stops listening but the lookup still
                // runs to the child's exit; the permit is freed only once the child is reaped.
                let out = tokio::spawn(async move {
                    let _permit = permit;
                    let mut child = cmd.spawn().ok()?;
                    let mut stdout = child.stdout.take()?;
                    let out = tokio::time::timeout(Duration::from_secs(3), async {
                        let mut buf = Vec::new();
                        stdout.read_to_end(&mut buf).await.ok()?;
                        child.wait().await.ok()?.success().then_some(buf)
                    })
                    .await;
                    // SIGKILL and reap; a no-op once the child has been waited for.
                    let _ = child.kill().await;
                    out.ok().flatten()
                })
                .await
                .ok()??;
                parse_whois_at(&String::from_utf8_lossy(&out), Some(ip))
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
    fn a_shared_in_device_is_named_by_its_tailnet_address() {
        let j = r#"{"Node":{"Name":"","ComputedName":"device-of-shared-to-user"},
                   "UserProfile":{"LoginName":"bob@example.com"}}"#;
        let ip: IpAddr = "100.113.6.5".parse().unwrap();
        assert_eq!(
            parse_whois_at(j, Some(ip)),
            Some(Peer {
                user: "bob@example.com".into(),
                machine: "shared-100-113-6-5".into()
            })
        );
        let v6: IpAddr = "fd7a:115c:a1e0::1".parse().unwrap();
        assert_eq!(
            parse_whois_at(j, Some(v6)).unwrap().machine,
            "shared-fd7a-115c-a1e0--1"
        );
        // Without an address it keeps the placeholder, as before.
        assert_eq!(parse_whois(j).unwrap().machine, SHARED_PLACEHOLDER);
        // A named node is unchanged.
        assert_eq!(parse_whois_at(WHOIS, Some(ip)).unwrap().machine, "laptop-a");
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
        assert_eq!(
            parse_whois(r#"{"Node":{"ComputedName":"a"},"UserProfile":{"LoginName":""}}"#),
            None
        );
        assert_eq!(
            parse_whois(r#"{"Node":{"ComputedName":""},"UserProfile":{"LoginName":"a@b"}}"#),
            None
        );
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
        std::fs::write(
            &bin,
            format!("#!/bin/sh\nexec cat '{}'\n", dir.join("answer").display()),
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        bin
    }

    #[tokio::test]
    async fn allowlist_limits_who_is_accepted() {
        let peer: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let id = Identifier::with_allowlist(
            IdentityConfig::Static,
            vec!["alice@example.com".into(), "tag:ci".into()],
        );
        assert!(id
            .identify(peer, Some("alice@example.com@laptop"))
            .await
            .is_some());
        assert!(id.identify(peer, Some("tag:ci@runner")).await.is_some());
        assert_eq!(
            id.identify(peer, Some("mallory@example.com@laptop")).await,
            None
        );
        // No allowlist: every identified peer is accepted.
        let open = Identifier::new(IdentityConfig::Static);
        assert!(open
            .identify(peer, Some("mallory@example.com@laptop"))
            .await
            .is_some());
    }

    #[tokio::test]
    async fn whois_is_asked_on_every_connection() {
        let dir = std::env::temp_dir().join(format!("wh-ts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let id = Identifier::new(IdentityConfig::Tailscale {
            bin: fake_tailscale(&dir),
        });
        let peer: SocketAddr = "100.64.0.5:4000".parse().unwrap();

        std::fs::write(dir.join("answer"), WHOIS).unwrap();
        assert_eq!(id.identify(peer, None).await.unwrap().machine, "laptop-a");

        // The same IP now belongs to a different node: the new identity is used at once.
        std::fs::write(
            dir.join("answer"),
            WHOIS
                .replace("laptop-a", "laptop-b")
                .replace("alice@", "bob@"),
        )
        .unwrap();
        let p = id.identify(peer, None).await.unwrap();
        assert_eq!(
            (p.user.as_str(), p.machine.as_str()),
            ("bob@example.com", "laptop-b")
        );

        // whois fails: the connection is refused (identity fails closed).
        std::fs::remove_file(dir.join("answer")).unwrap();
        assert_eq!(id.identify(peer, None).await, None);
        // A static claim header is ignored under Tailscale identity.
        assert_eq!(id.identify(peer, Some("alice@laptop-a")).await, None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn whois_lookups_run_at_most_limit_at_once() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("wh-ts-bound-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("running")).unwrap();
        std::fs::write(dir.join("answer"), WHOIS).unwrap();
        let bin = dir.join("tailscale");
        // Each copy marks itself running, waits, then records how many copies run with it.
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\ncd '{d}'\ntouch running/$$\nsleep 0.3\nls running | wc -l >> seen\nrm running/$$\nexec cat answer\n",
                d = dir.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let id = std::sync::Arc::new(Identifier::new(IdentityConfig::Tailscale { bin }));
        let peer: SocketAddr = "100.64.0.5:4000".parse().unwrap();

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..WHOIS_LIMIT * 3 {
            let id = id.clone();
            set.spawn(async move { id.identify(peer, None).await });
        }
        // Lookups over the limit wait their turn; none is refused.
        while let Some(r) = set.join_next().await {
            assert_eq!(r.unwrap().unwrap().machine, "laptop-a");
        }
        let seen = std::fs::read_to_string(dir.join("seen")).unwrap();
        let most = seen
            .lines()
            .map(|l| l.trim().parse::<usize>().unwrap())
            .max();
        assert!(most <= Some(WHOIS_LIMIT), "{most:?} lookups ran at once");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
