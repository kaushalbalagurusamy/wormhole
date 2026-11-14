//! Who is on the other end of a connection. The hub never takes identity from a token or
//! from the payload: it asks the private network (Tailscale) about the peer address.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

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

/// Parse `tailscale whois --json` output. Requires a node name and a login name.
pub fn parse_whois(json: &str) -> Option<Peer> {
    let _ = json;
    todo!()
}

/// Parse a static claim `user@machine` (split at the last `@`).
pub fn parse_static(claim: &str) -> Option<Peer> {
    let _ = claim;
    todo!()
}

pub(crate) fn canonical_ip(addr: SocketAddr) -> IpAddr {
    addr.ip().to_canonical()
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
}
