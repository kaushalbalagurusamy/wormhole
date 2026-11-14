//! The hub: one process holding the ordered event log, presence, leases and inboxes.

pub mod identity;
pub mod store;

use identity::IdentityConfig;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct HubConfig {
    pub listen: SocketAddr,
    pub db: PathBuf,
    pub identity: IdentityConfig,
}

pub struct HubHandle {
    pub addr: SocketAddr,
}

impl HubHandle {
    /// Close every connection from `machine` (used by tests to simulate a network drop).
    pub fn kick(&self, machine: &str) {
        let _ = machine;
        todo!()
    }

    pub async fn shutdown(self) {
        todo!()
    }
}

pub async fn start(cfg: HubConfig) -> Result<HubHandle, String> {
    let _ = cfg;
    todo!()
}
