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

/// Capability a daemon advertises in `Resume` (only with a delegation policy) and the hub in
/// `Welcome`. A daemon sends delegation requests only on a connection whose `Welcome` listed it.
pub const CAP_DELEGATION: &str = "delegation";
/// The hub keeps a per-repository team log and answers `Log`; a daemon authoring entries for it.
pub const CAP_TEAM_LOG: &str = "team-log";
/// The hub announces a target build and accepts `DaemonStatus`; a daemon that follows targets.
pub const CAP_UPDATE: &str = "update";

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

/// Frames a daemon sends. `Req` is large because a delegation carries a whole contract; the
/// frames are short-lived, so boxing it would only change the pinned wire types.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Up {
    /// First frame on a connection. `from` is the last sequence number the daemon has
    /// processed; `None` asks the hub to use its stored cursor for this machine.
    Resume {
        from: Option<u64>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        caps: Vec<String>,
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
    /// Hand a task to another session. Sent only when the hub advertised the capability.
    Delegate {
        session: String,
        to: String,
        repo: String,
        contract: Contract,
    },
    /// The target session's answer to a delegated task.
    DelegateAck {
        session: String,
        request: u64,
        accept: bool,
        level: String,
        reason: String,
        ttl_ms: u64,
    },
    DelegateResult {
        session: String,
        request: u64,
        status: String,
        summary: String,
        #[serde(default)]
        fields: serde_json::Map<String, Value>,
    },
    /// Read this session's repository's team log. Sent only when the hub advertised the capability.
    Log {
        session: String,
        #[serde(default)]
        query: LogQuery,
    },
    /// The daemon's running commit, the target it has seen and its update status. Sent only
    /// when the hub advertised the capability.
    DaemonStatus {
        commit: String,
        target: String,
        status: String,
    },
}

/// Frames the hub sends.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Down {
    Welcome {
        user: String,
        machine: String,
        head: u64,
        #[serde(default)]
        caps: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<String>,
    },
    /// The hub's target build changed. Sent only to connections that advertised `update`.
    Target {
        #[serde(default)]
        commit: Option<String>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegations: Vec<DelegationInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub daemons: Vec<DaemonInfo>,
}

/// What the hub knows of one machine's daemon: the commit it runs, the target it was told
/// and its update status.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct DaemonInfo {
    pub user: String,
    pub machine: String,
    pub commit: String,
    pub target: String,
    pub status: String,
    pub ts: u64,
}

/// Filters for `Request::Log`; they combine with AND.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct LogQuery {
    #[serde(default)]
    pub since: Option<u64>,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    /// `msg`, `request`, `ack` or `result`.
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub task_id: Option<String>,
    /// 0: 50; capped at 200.
    #[serde(default)]
    pub limit: u64,
}

/// One row of the team log as the hub stored it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct LogEntry {
    pub seq: u64,
    pub ts: u64,
    pub kind: String,
    pub repo: String,
    pub from_session: String,
    pub from_user: String,
    pub from_machine: String,
    /// `session:<id>`, `user:<name>` or `all`.
    pub to: String,
    pub to_user: String,
    pub task_id: String,
    pub text: String,
    pub data: Value,
}

/// A delegated task as the hub keeps it: the contract's identifying fields and the outcome.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct DelegationInfo {
    pub seq: u64,
    pub from_session: String,
    pub from_user: String,
    pub from_machine: String,
    pub to_session: String,
    pub to_user: String,
    pub to_machine: String,
    pub repo: String,
    pub task_id: String,
    pub kind: String,
    pub status: String,
    pub level: String,
    pub summary: String,
    pub ts: u64,
}

/// What a delegated task may touch and when it is done. The receiving owner's policy, not
/// this, decides the permission level.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Contract {
    pub task_id: String,
    pub kind: String,
    /// Spec or slice reference.
    #[serde(default)]
    pub spec: String,
    /// Repo-relative files, directories ending in `/`, or globs.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Command patterns; `*` matches any characters.
    #[serde(default)]
    pub commands: Vec<String>,
    /// What done means.
    #[serde(default)]
    pub exit: String,
    /// 0: the grant's maximum.
    #[serde(default)]
    pub ttl_secs: u64,
    /// 0: the grant's maximum.
    #[serde(default)]
    pub max_steps: u64,
    /// Keys a `done` result must carry.
    #[serde(default)]
    pub result_fields: Vec<String>,
    /// An `https://` link to what the task concerns, such as a pull request.
    #[serde(rename = "ref", default, skip_serializing_if = "String::is_empty")]
    pub reference: String,
    pub text: String,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
