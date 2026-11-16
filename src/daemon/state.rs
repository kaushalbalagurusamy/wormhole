//! Per-session state the daemon keeps in memory: lease tokens, files read, and the inbox
//! of notices waiting for the session's next hook.

use crate::proto::{Event, Target};
use crate::repo::RepoInfo;
use crate::text;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::Instant;
use tokio::sync::mpsc;

/// Most notices kept per session; older ones are dropped and counted.
const INBOX_MAX: usize = 100;
/// An undelivered message older than this stops holding back the hub cursor, so a session
/// that vanished without ending cannot pin replay forever.
const HOLD_CURSOR_MS: u64 = 24 * 3600 * 1000;

pub(crate) struct Notice {
    pub seq: u64,
    /// Hub time of the event, for the undelivered-message age limit.
    pub ts: u64,
    pub block: String,
    pub meta: Vec<(String, String)>,
    /// Set for messages, so delivery can be acknowledged to the hub.
    pub msg_seq: Option<u64>,
}

impl Notice {
    pub fn push_value(&self) -> Value {
        let meta: serde_json::Map<String, Value> = self
            .meta
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        json!({
            "seq": self.seq,
            "text": format!("{}\n\n{}", text::PREAMBLE, self.block),
            "meta": meta,
        })
    }
}

pub(crate) struct Sess {
    pub cwd: Option<PathBuf>,
    pub repo: Option<RepoInfo>,
    pub task: String,
    /// Connection generation on which the hub accepted this session's hello.
    pub hello_gen: u64,
    pub last_active: Instant,
    pub tokens: HashMap<(String, String), u64>,
    /// Leases taken with the lease tool (not by an edit); their expiry is reported.
    pub explicit: std::collections::HashSet<(String, String)>,
    pub reads: HashMap<(String, String), u64>,
    pub inbox: VecDeque<Notice>,
    pub dropped: usize,
    pub subs: Vec<mpsc::UnboundedSender<Value>>,
}

impl Sess {
    fn new() -> Sess {
        Sess {
            cwd: None,
            repo: None,
            task: String::new(),
            hello_gen: 0,
            last_active: Instant::now(),
            tokens: HashMap::new(),
            explicit: std::collections::HashSet::new(),
            reads: HashMap::new(),
            inbox: VecDeque::new(),
            dropped: 0,
            subs: Vec::new(),
        }
    }

    pub fn notify(&mut self, n: Notice) {
        let v = n.push_value();
        self.subs.retain(|s| s.send(v.clone()).is_ok());
        if self.inbox.len() >= INBOX_MAX {
            self.inbox.pop_front();
            self.dropped += 1;
        }
        self.inbox.push_back(n);
    }
}

#[derive(Default)]
pub(crate) struct State {
    pub sessions: HashMap<String, Sess>,
    pub last_seq: Option<u64>,
}

pub(crate) fn hms(ms: u64) -> String {
    let s = ms / 1000;
    format!(
        "{:02}:{:02}:{:02} UTC",
        (s / 3600) % 24,
        (s / 60) % 60,
        s % 60
    )
}

fn from_attrs(e: &Event) -> Vec<(String, String)> {
    vec![
        ("from_session".into(), e.session.clone()),
        ("from_user".into(), e.user.clone()),
        ("from_machine".into(), e.machine.clone()),
        ("seq".into(), e.seq.to_string()),
    ]
}

pub(crate) fn notice(e: &Event, tag: &str, kind: &str, body: &str, msg: bool) -> Notice {
    notice_from(e.seq, e.ts, from_attrs(e), tag, kind, body, msg)
}

/// A notice with explicit attributes, for ones the daemon raises itself.
pub(crate) fn notice_from(
    seq: u64,
    ts: u64,
    attrs: Vec<(String, String)>,
    tag: &str,
    kind: &str,
    body: &str,
    msg: bool,
) -> Notice {
    let mut meta = vec![("kind".to_string(), kind.to_string())];
    meta.extend(attrs);
    let attrs: Vec<(&str, &str)> = meta[1..]
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    Notice {
        seq,
        ts,
        block: text::block(tag, &attrs, body),
        meta: meta
            .iter()
            .map(|(k, v)| (k.clone(), text::attr(v)))
            .collect(),
        msg_seq: msg.then_some(seq),
    }
}

impl State {
    /// What to acknowledge to the hub: everything processed, except that the cursor stays
    /// before the oldest message not yet delivered to its session, so a daemon restart
    /// replays it.
    pub fn ack_point(&self) -> Option<u64> {
        let last = self.last_seq?;
        let now = crate::proto::now_ms();
        let oldest = self
            .sessions
            .values()
            .flat_map(|s| s.inbox.iter())
            .filter(|n| n.msg_seq.is_some() && now.saturating_sub(n.ts) < HOLD_CURSOR_MS)
            .map(|n| n.seq.saturating_sub(1))
            .min();
        Some(oldest.map_or(last, |o| o.min(last)))
    }

    pub fn sess(&mut self, id: &str) -> &mut Sess {
        self.sessions
            .entry(id.to_string())
            .or_insert_with(Sess::new)
    }

    /// Apply one hub event. Returns false if it was already seen.
    pub fn apply(&mut self, e: &Event) -> bool {
        if self.last_seq.is_some_and(|l| e.seq <= l) {
            return false;
        }
        self.last_seq = Some(e.seq);
        let d = &e.data;
        let s = |k: &str| d[k].as_str().unwrap_or("").to_string();
        // Shown names come from the hub as stored: folded to one line so none can start a
        // forged line. Only a message body keeps its line breaks.
        let one = |v: &str| text::plain(v, text::MAX_BLOCK);
        let p = |k: &str| one(&s(k));
        let (from, user, machine) = (one(&e.session), one(&e.user), one(&e.machine));
        match e.kind.as_str() {
            "msg" => {
                let to: Option<Target> = serde_json::from_value(d["to"].clone()).ok();
                let recipients: Vec<String> = match &to {
                    Some(Target::Session(id)) => vec![id.clone()],
                    Some(Target::User(_)) | Some(Target::Broadcast) => {
                        self.sessions.keys().cloned().collect()
                    }
                    None => vec![],
                };
                let to_desc = match &to {
                    Some(Target::Session(_)) => "this session".to_string(),
                    Some(Target::User(u)) => format!("user {}", one(u)),
                    _ => "everyone".to_string(),
                };
                let body = format!(
                    "Message from session {from} ({user}@{machine}) to {}:\n{}",
                    to_desc,
                    s("body")
                );
                // Where the sender aimed it and whether that is this session: a session target
                // reaches only its session, a user target every session of this user.
                let (to_attr, for_you) = match &to {
                    Some(Target::Session(id)) => (format!("session:{id}"), "yes"),
                    Some(Target::User(u)) => (format!("user:{u}"), "yes"),
                    _ => ("all".to_string(), "all"),
                };
                for r in recipients.into_iter().filter(|r| *r != e.session) {
                    let mut attrs = from_attrs(e);
                    attrs.push(("to".into(), to_attr.clone()));
                    attrs.push(("for_you".into(), for_you.into()));
                    self.sess(&r).notify(notice_from(
                        e.seq,
                        e.ts,
                        attrs,
                        "wormhole-message",
                        "message",
                        &body,
                        true,
                    ));
                }
            }
            "activity" if s("kind") == "edit" => {
                let repo = s("repo");
                let paths: Vec<String> = d["paths"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|p| p.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                for (id, sess) in self.sessions.iter_mut() {
                    if *id == e.session {
                        continue;
                    }
                    for p in &paths {
                        let key = (repo.clone(), p.clone());
                        if sess.reads.get(&key).is_some_and(|&at| at < e.seq) {
                            sess.reads.remove(&key);
                            let body = format!(
                                "{} in {} was changed by session {from} ({user}@{machine}) at {}, after this session read it. The copy you read may be out of date.",
                                one(p), one(&repo), hms(e.ts)
                            );
                            sess.notify(notice(e, "wormhole-change", "change", &body, false));
                        }
                    }
                }
            }
            "lease.transfer_requested" => {
                let holder = s("holder");
                if let Some(sess) = self.sessions.get_mut(&holder) {
                    let body = format!(
                        "Session {from} ({user}@{machine}) asks for this session's lease on {} in {}. Their reason: {}\nTo hand it over, call wormhole_grant with scope \"{}\" and to_session \"{}\"; to refuse, call wormhole_deny.",
                        text::attr(&s("scope")), text::attr(&s("repo")), p("reason"), text::attr(&s("scope")), text::attr(&e.session)
                    );
                    sess.notify(notice(e, "wormhole-lease", "lease_request", &body, false));
                }
            }
            "lease.granted" => {
                let key = (s("repo"), s("scope"));
                let granter = s("from");
                if let Some(old) = self.sessions.get_mut(&granter) {
                    old.tokens.remove(&key);
                }
                if let Some(sess) = self.sessions.get_mut(&e.session) {
                    if let Some(t) = d["token"].as_u64() {
                        sess.tokens.insert(key.clone(), t);
                    }
                    if s("via") == "transfer" {
                        let body = format!(
                            "The lease on {} in {} was granted to this session by session {}.",
                            one(&key.1),
                            one(&key.0),
                            one(&granter)
                        );
                        sess.notify(notice(e, "wormhole-lease", "lease_granted", &body, false));
                    }
                }
            }
            // Answers to a task this machine's session handed out. Kept until delivered, like a
            // message, because they say whether the work was accepted and under what limits.
            "delegation.ack" | "delegation.result" => {
                if let Some(sess) = self.sessions.get_mut(&s("to")) {
                    let ack = e.kind == "delegation.ack";
                    let head = format!(
                        "Delegation request {} (task {}) {} session {from} ({user}@{machine}): status: {}",
                        d["request"],
                        p("task_id"),
                        if ack { "answered by" } else { "result from" },
                        p("status")
                    );
                    let body = if ack {
                        format!("{head}; level: {}; reason: {}", p("level"), p("reason"))
                    } else {
                        format!(
                            "{head}; summary: {}; fields: {}",
                            text::plain(&s("summary"), 600),
                            text::plain(&d["fields"].to_string(), 500)
                        )
                    };
                    let kind = if ack {
                        "delegation_ack"
                    } else {
                        "delegation_result"
                    };
                    sess.notify(notice(e, "wormhole-delegation", kind, &body, true));
                }
            }
            "lease.denied" => {
                if let Some(sess) = self.sessions.get_mut(&s("to")) {
                    let body = format!(
                        "Session {from} ({user}@{machine}) denied this session's request for the lease on {} in {}. Their reason: {}",
                        p("scope"), p("repo"), p("reason")
                    );
                    sess.notify(notice(e, "wormhole-lease", "lease_denied", &body, false));
                }
            }
            // A read receipt (ours, replayed after a restart) means the message was delivered.
            "msg.read" => {
                if let (Some(sess), Some(seq)) =
                    (self.sessions.get_mut(&e.session), d["seq"].as_u64())
                {
                    sess.inbox.retain(|n| n.msg_seq != Some(seq));
                }
            }
            "lease.expired" => {
                let key = (s("repo"), s("scope"));
                if let Some(sess) = self.sessions.get_mut(&e.session) {
                    if sess.tokens.get(&key).copied() == d["token"].as_u64()
                        && sess.explicit.remove(&key)
                    {
                        let body = format!(
                            "This session's lease on {} in {} expired at {}; other sessions are no longer warned about it.",
                            text::attr(&key.1),
                            text::attr(&key.0),
                            hms(e.ts)
                        );
                        sess.notify(notice(e, "wormhole-lease", "lease_expired", &body, false));
                    }
                }
            }
            // Tokens are kept through expiry on purpose: the next edit presents the old token,
            // the hub rejects it (fencing), and the session is told its lease is no longer valid.
            _ => {}
        }
        true
    }
}
