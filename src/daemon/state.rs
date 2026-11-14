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

pub(crate) struct Notice {
    pub seq: u64,
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

fn notice(e: &Event, tag: &str, kind: &str, body: &str, msg: bool) -> Notice {
    let mut meta = vec![("kind".to_string(), kind.to_string())];
    meta.extend(from_attrs(e));
    let attrs: Vec<(&str, &str)> = meta[1..]
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    Notice {
        seq: e.seq,
        block: text::block(tag, &attrs, body),
        meta: meta
            .iter()
            .map(|(k, v)| (k.clone(), text::attr(v)))
            .collect(),
        msg_seq: msg.then_some(e.seq),
    }
}

impl State {
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
                    Some(Target::User(u)) => format!("user {u}"),
                    _ => "everyone".to_string(),
                };
                let body = format!(
                    "Message from session {} ({}@{}) to {}:\n{}",
                    e.session,
                    e.user,
                    e.machine,
                    to_desc,
                    s("body")
                );
                for r in recipients.into_iter().filter(|r| *r != e.session) {
                    self.sess(&r)
                        .notify(notice(e, "wormhole-message", "message", &body, true));
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
                                "{p} in {repo} was changed by session {} ({}@{}) at {}, after this session read it. The copy you read may be out of date.",
                                e.session, e.user, e.machine, hms(e.ts)
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
                        "Session {} ({}@{}) asks for this session's lease on {} in {}. Their reason: {}\nTo hand it over, call wormhole_grant with scope \"{}\" and to_session \"{}\"; to refuse, call wormhole_deny.",
                        e.session, e.user, e.machine, s("scope"), s("repo"), s("reason"), s("scope"), e.session
                    );
                    sess.notify(notice(e, "wormhole-lease", "lease_request", &body, false));
                }
            }
            "lease.granted" => {
                let key = (s("repo"), s("scope"));
                let from = s("from");
                if let Some(old) = self.sessions.get_mut(&from) {
                    old.tokens.remove(&key);
                }
                if let Some(sess) = self.sessions.get_mut(&e.session) {
                    if let Some(t) = d["token"].as_u64() {
                        sess.tokens.insert(key.clone(), t);
                    }
                    if s("via") == "transfer" {
                        let body = format!(
                            "The lease on {} in {} was granted to this session by session {}.",
                            key.1, key.0, from
                        );
                        sess.notify(notice(e, "wormhole-lease", "lease_granted", &body, false));
                    }
                }
            }
            "lease.denied" => {
                if let Some(sess) = self.sessions.get_mut(&s("to")) {
                    let body = format!(
                        "Session {} ({}@{}) denied this session's request for the lease on {} in {}. Their reason: {}",
                        e.session, e.user, e.machine, s("scope"), s("repo"), s("reason")
                    );
                    sess.notify(notice(e, "wormhole-lease", "lease_denied", &body, false));
                }
            }
            // Tokens are kept through expiry on purpose: the next edit presents the old token,
            // the hub rejects it (fencing), and the session is told its lease is no longer valid.
            _ => {}
        }
        true
    }
}
