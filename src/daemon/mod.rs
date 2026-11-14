//! The daemon: one per machine. Keeps one WebSocket to the hub and serves local sessions
//! over a Unix socket and HTTP hooks on loopback.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    /// `ws://host:port/ws`
    pub hub_url: String,
    /// Loopback address for Claude Code HTTP hooks.
    pub http_listen: SocketAddr,
    /// Unix socket path; its directory is created with mode 0700 if missing.
    pub socket_path: PathBuf,
    /// Sent only when the hub runs with static identity.
    pub static_identity: Option<String>,
    /// Repo-relative globs where a conflicting edit is denied instead of warned.
    pub protected: Vec<String>,
    pub lease_ttl: Duration,
    /// Longest a hook waits on the hub before failing open.
    pub hub_deadline: Duration,
    /// First reconnect delay; doubles up to 10 s.
    pub reconnect_min: Duration,
}

impl DaemonConfig {
    pub fn new(hub_url: String, socket_path: PathBuf) -> DaemonConfig {
        DaemonConfig {
            hub_url,
            http_listen: SocketAddr::from(([127, 0, 0, 1], 7421)),
            socket_path,
            static_identity: None,
            protected: Vec::new(),
            lease_ttl: Duration::from_secs(600),
            hub_deadline: Duration::from_millis(800),
            reconnect_min: Duration::from_millis(250),
        }
    }
}

pub struct DaemonHandle {
    pub http_addr: SocketAddr,
    pub socket_path: PathBuf,
}

impl DaemonHandle {
    /// How many times the daemon has completed a handshake with the hub.
    pub fn connects(&self) -> u64 {
        todo!()
    }

    pub async fn shutdown(self) {
        todo!()
    }
}

pub async fn start(cfg: DaemonConfig) -> Result<DaemonHandle, String> {
    let _ = cfg;
    todo!()
}
