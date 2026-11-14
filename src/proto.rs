//! Wire types between daemon and hub. JSON text frames over one WebSocket.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Largest message body the hub accepts, in bytes.
pub const MAX_BODY: usize = 4096;
/// Longest one-line summary kept on an activity event, in characters.
pub const MAX_SUMMARY: usize = 200;
/// Most paths on one activity event.
pub const MAX_PATHS: usize = 32;
/// Longest path, scope, repo id or branch, in bytes.
pub const MAX_FIELD: usize = 512;
/// Longest task description, in characters.
pub const MAX_TASK: usize = 200;
/// Largest WebSocket frame either side accepts. Snapshots are the largest frames.
pub const MAX_FRAME: usize = 1024 * 1024;
/// Most sessions and leases in one snapshot, so it fits in a frame.
pub const MAX_SNAPSHOT_SESSIONS: usize = 500;
pub const MAX_SNAPSHOT_LEASES: usize = 1000;

/// Header a daemon uses to claim an identity when the hub runs with static identity.
pub const STATIC_ID_HEADER: &str = "x-wormhole-static-identity";

/// Where a message goes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Target {
    Session(String),
    User(String),
    Broadcast,
}

/// Frames a daemon sends.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Up {
    /// First frame on a connection. `from` is the last sequence number the daemon has
    /// processed; `None` asks the hub to use its stored cursor for this machine. `proof`
    /// answers the hub's challenge when a shared secret is set (see `auth`).
    Resume {
        from: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proof: Option<String>,
    },
    /// Everything up to and including `seq` has been processed.
    Ack {
        seq: u64,
    },
    Req {
        id: u64,
        req: Request,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Hello {
        session: String,
        repo: String,
        branch: String,
        task: String,
    },
    Heartbeat {
        session: String,
    },
    Bye {
        session: String,
    },
    Activity {
        session: String,
        kind: String,
        repo: String,
        paths: Vec<String>,
        summary: String,
    },
    Send {
        session: String,
        to: Target,
        body: String,
        reply_to: Option<u64>,
    },
    MsgRead {
        session: String,
        seq: u64,
    },
    LeaseAcquire {
        session: String,
        repo: String,
        scope: String,
        ttl_ms: u64,
    },
    LeaseRenew {
        session: String,
        repo: String,
        scope: String,
        token: u64,
        ttl_ms: u64,
    },
    LeaseRelease {
        session: String,
        repo: String,
        scope: String,
        token: u64,
    },
    LeaseRequestTransfer {
        session: String,
        repo: String,
        scope: String,
        reason: String,
    },
    LeaseGrant {
        session: String,
        repo: String,
        scope: String,
        to: String,
    },
    LeaseDeny {
        session: String,
        repo: String,
        scope: String,
        to: String,
        reason: String,
    },
    Snapshot,
}

/// Frames the hub sends.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Down {
    Welcome {
        user: String,
        machine: String,
        head: u64,
    },
    Event {
        event: Event,
    },
    Resp {
        id: u64,
        ok: bool,
        #[serde(default)]
        data: Value,
        #[serde(default)]
        error: Option<String>,
    },
}

/// One entry in the hub's ordered log. `user` and `machine` are set by the hub from the
/// connection's identity, never taken from the sender.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Event {
    pub seq: u64,
    pub ts: u64,
    pub kind: String,
    pub user: String,
    pub machine: String,
    pub session: String,
    pub data: Value,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LeaseInfo {
    pub repo: String,
    pub scope: String,
    pub session: String,
    pub user: String,
    pub machine: String,
    pub token: u64,
    pub since: u64,
    pub expires: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SessionInfo {
    pub session: String,
    pub user: String,
    pub machine: String,
    pub repo: String,
    pub branch: String,
    pub task: String,
    pub since: u64,
    pub last_seen: u64,
}

/// Result of `lease_acquire` and `lease_renew`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LeaseResult {
    Granted { lease: LeaseInfo },
    Held { lease: LeaseInfo },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Snapshot {
    pub sessions: Vec<SessionInfo>,
    pub leases: Vec<LeaseInfo>,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
