//! Claude Code hook handling, shared by the HTTP endpoint and the `wormhole hook` command.
//! Hooks fail open: if the hub does not answer by the deadline the action goes ahead with a
//! note that state is stale. They never return `permissionDecision: "allow"`, which would
//! skip the user's own permission prompt.

use super::{Daemon, HubError};
use crate::proto::*;
use crate::{glob, repo, text};
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

pub const STALE_HUB: &str = "[wormhole] Coordination state is stale: the wormhole hub did not answer, so leases were not checked and other sessions' recent activity may be missing. The action was not blocked.";
pub const STALE_DAEMON: &str = "[wormhole] Coordination state is stale: the local wormhole daemon did not answer, so other sessions' work and leases are unknown. The action was not blocked.";

const EDIT_TOOLS: &[&str] = &["Edit", "Write", "MultiEdit", "NotebookEdit"];

pub(crate) async fn serve_http(d: Arc<Daemon>, l: tokio::net::TcpListener) {
    let app = axum::Router::new()
        .route("/hook", axum::routing::post(http_hook))
        .with_state(d);
    let _ = axum::serve(l, app).await;
}

/// Only Claude Code on this machine should reach this endpoint. Reject anything that looks
/// like a browser (an Origin header) or a DNS-rebound request (a Host that is not loopback).
fn local_request(headers: &HeaderMap, port: u16) -> bool {
    if headers.contains_key(header::ORIGIN) {
        return false;
    }
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ]
    .iter()
    .any(|h| h == host)
}

/// Constant-time comparison of the Authorization header with the daemon's hook token, so
/// other local users (who can reach loopback) cannot drive this user's daemon.
fn authorized(headers: &HeaderMap, token: &str) -> bool {
    let got = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("");
    let (a, b) = (got.as_bytes(), token.as_bytes());
    a.len() == b.len()
        && !b.is_empty()
        && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Most bytes read from one hook body. Bodies carry file contents and are reduced while
/// they stream in (see `shrink`), so this only bounds time spent, not memory.
const MAX_HOOK_STREAM: u64 = 1024 * 1024 * 1024;

fn refusal(reason: &str) -> Value {
    json!({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": format!("[wormhole] {reason} The edit was refused so a protected path cannot be bypassed; retry with a smaller change."),
    }})
}

fn refuse(reason: &str) -> Response {
    Json(refusal(reason)).into_response()
}

/// Headers and token are checked before any of the body is read. No body size gets a 413:
/// Claude Code would treat that as a non-blocking error and the edit would skip the check.
async fn http_hook(State(d): State<Arc<Daemon>>, req: axum::extract::Request) -> Response {
    use futures_util::StreamExt;
    let headers = req.headers();
    if !local_request(headers, d.cfg_port()) || !authorized(headers, &d.hook_token) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let json_body = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        });
    if !json_body {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let mut stream = req.into_body().into_data_stream();
    let mut sh = super::shrink::Shrinker::default();
    let mut total: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            return refuse("The hook request could not be read in full.");
        };
        total += chunk.len() as u64;
        if total > MAX_HOOK_STREAM {
            return refuse("The hook request was too large to check.");
        }
        sh.feed(&chunk);
    }
    let Some(reduced) = sh.finish() else {
        return refuse("The hook request was too large to check.");
    };
    let Ok(input) = serde_json::from_slice::<Value>(&reduced) else {
        return refuse("The hook request could not be read as JSON.");
    };
    Json(handle(&d, input).await).into_response()
}

impl Daemon {
    fn cfg_port(&self) -> u16 {
        self.http_port.load(std::sync::atomic::Ordering::SeqCst) as u16
    }
}

fn output(event: &str, context: &str) -> Value {
    if context.is_empty() {
        return json!({});
    }
    json!({"hookSpecificOutput": {"hookEventName": event, "additionalContext": context}})
}

fn join(parts: &[&str]) -> String {
    parts
        .iter()
        .filter(|p| !p.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// Handle one hook input. Always returns a valid hook output.
pub(crate) async fn handle(d: &Daemon, input: Value) -> Value {
    let deadline = Instant::now() + d.cfg.hub_deadline;
    let event = input["hook_event_name"].as_str().unwrap_or("").to_string();
    let Some(session) = input["session_id"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= MAX_FIELD)
    else {
        return json!({});
    };
    let cwd = input["cwd"].as_str().map(PathBuf::from);
    let hub_ok = ensure_session(d, session, cwd.as_deref(), deadline).await;
    match event.as_str() {
        "SessionStart" => {
            let state = if hub_ok {
                who_text(d, session, deadline).await.ok()
            } else {
                None
            };
            let inbox = take_inbox(d, session);
            let ctx = match state {
                Some(s) => join(&[&s, &inbox]),
                None => join(&[STALE_HUB, &inbox]),
            };
            output("SessionStart", &ctx)
        }
        "PreToolUse" => pre_tool_use(d, session, &input, hub_ok, deadline).await,
        "PostToolUse" => {
            let recorded = record_activity(d, session, &input, hub_ok, deadline).await;
            let stale = if hub_ok && recorded { "" } else { STALE_HUB };
            output("PostToolUse", &join(&[stale, &take_inbox(d, session)]))
        }
        "UserPromptSubmit" => {
            let stale = if hub_ok { "" } else { STALE_HUB };
            output("UserPromptSubmit", &join(&[stale, &take_inbox(d, session)]))
        }
        "SessionEnd" => {
            let _ = d
                .request(
                    Request::Bye {
                        session: session.into(),
                    },
                    deadline,
                )
                .await;
            d.st.lock().unwrap().sessions.remove(session);
            json!({})
        }
        _ => json!({}),
    }
}

/// Note the session locally and make sure the hub knows it. False if the hub is unavailable.
async fn ensure_session(d: &Daemon, session: &str, cwd: Option<&Path>, deadline: Instant) -> bool {
    let found = cwd.and_then(repo::find);
    {
        let mut st = d.st.lock().unwrap();
        let s = st.sess(session);
        s.last_active = Instant::now();
        if let Some(c) = cwd {
            if s.cwd.as_deref() != Some(c) || s.repo != found {
                s.cwd = Some(c.to_path_buf());
                if s.repo != found {
                    s.repo = found;
                    s.hello_gen = 0;
                }
            }
        }
    }
    !matches!(d.hello(session, deadline).await, Err(HubError::Unavailable))
}

/// Deliver queued notices that fit, leaving the rest for next time.
pub(crate) fn take_inbox(d: &Daemon, session: &str) -> String {
    let (text, read) = {
        let mut st = d.st.lock().unwrap();
        let s = st.sess(session);
        let mut blocks: Vec<String> = Vec::new();
        if s.dropped > 0 {
            blocks.push(format!(
                "[wormhole] {} older notices were dropped because the inbox was full.",
                s.dropped
            ));
        }
        blocks.extend(s.inbox.iter().map(|n| n.block.clone()));
        let (text, n) = text::assemble(&blocks);
        let n_notices = if s.dropped > 0 {
            n.saturating_sub(1)
        } else {
            n
        };
        if n > 0 {
            s.dropped = 0;
        }
        let read: Vec<u64> = s
            .inbox
            .drain(..n_notices)
            .filter_map(|n| n.msg_seq)
            .collect();
        (text, read)
    };
    // Fire-and-forget read receipts; the hub's reply (to id u64::MAX) is ignored.
    let delivered = !read.is_empty();
    for seq in read {
        d.send_up(Up::Req {
            id: u64::MAX,
            req: Request::MsgRead {
                session: session.into(),
                seq,
            },
        });
    }
    // Delivered messages no longer hold the hub cursor back.
    if delivered {
        let ack = d.st.lock().unwrap().ack_point();
        if let Some(seq) = ack {
            d.send_up(Up::Ack { seq });
        }
    }
    text
}

/// Repo id and repo-relative path for an edit-like tool input, resolved through symlinks
/// and `..`; `None` when the file is outside the repository.
fn tool_path(d: &Daemon, session: &str, input: &Value) -> Option<(String, String)> {
    let ti = &input["tool_input"];
    let file = ti["file_path"]
        .as_str()
        .or_else(|| ti["notebook_path"].as_str())?;
    let (id, root, cwd) = {
        let st = d.st.lock().unwrap();
        let s = st.sessions.get(session)?;
        let r = s.repo.as_ref()?;
        (r.id.clone(), r.root.clone(), s.cwd.clone()?)
    };
    Some((id, repo::canonical_relative(&root, &cwd, file)?))
}

/// Protected-glob match; case-insensitive where the repository's filesystem is.
fn is_protected(d: &Daemon, session: &str, rel: &str) -> bool {
    let ci =
        d.st.lock()
            .unwrap()
            .sessions
            .get(session)
            .and_then(|s| s.repo.as_ref().map(|r| r.root.clone()))
            .is_some_and(|root| repo::case_insensitive(&root));
    d.cfg.protected.iter().any(|g| {
        glob::matches(g, rel) || (ci && glob::matches(&g.to_lowercase(), &rel.to_lowercase()))
    })
}

fn ago(ms: u64) -> String {
    let s = now_ms().saturating_sub(ms) / 1000;
    if s < 120 {
        format!("{s} s")
    } else {
        format!("{} min", s / 60)
    }
}

fn held_text(l: &LeaseInfo, rel: &str, repo: &str, protected: bool, lost: Option<u64>) -> String {
    let a = text::attr;
    let mut t = format!(
        "WARNING from wormhole: {rel} in {} is leased by another session: {} ({}@{}), scope {}, since {} ({} ago), expiring in {} s.",
        a(repo),
        a(&l.session),
        a(&l.user),
        a(&l.machine),
        a(&l.scope),
        super::state::hms(l.since),
        ago(l.since),
        l.expires.saturating_sub(now_ms()) / 1000
    );
    if let Some(tok) = lost {
        t.push_str(&format!(
            " This session's earlier lease on it (token {tok}) is no longer valid."
        ));
    }
    if protected {
        t.push_str(" The path is protected, so the edit was refused. Ask the holder with wormhole_request_transfer or message them with wormhole_send.");
    } else {
        t.push_str(" Editing it now may conflict with their work; consider messaging them (wormhole_send) or asking for the lease (wormhole_request_transfer) first.");
    }
    t
}

async fn pre_tool_use(
    d: &Daemon,
    session: &str,
    input: &Value,
    hub_ok: bool,
    deadline: Instant,
) -> Value {
    let tool = input["tool_name"].as_str().unwrap_or("");
    if !EDIT_TOOLS.contains(&tool) {
        return json!({});
    }
    // The repository comes from the session's cwd only; outside one no path is ever checked.
    let in_repo =
        d.st.lock()
            .unwrap()
            .sessions
            .get(session)
            .is_some_and(|s| s.repo.is_some());
    if !in_repo {
        return json!({});
    }
    let ti = &input["tool_input"];
    // A path over 4 KiB reaches here blanked by `shrink`.
    let blank = ti["file_path"]
        .as_str()
        .or_else(|| ti["notebook_path"].as_str())
        == Some("");
    // A blank path would resolve to the cwd, which is not the file being edited.
    let path = if blank {
        None
    } else {
        tool_path(d, session, input)
    };
    if path.is_none() && !blank {
        return json!({});
    }
    if !hub_ok {
        return output("PreToolUse", STALE_HUB);
    }
    let Some((repo_id, rel)) = path.filter(|(_, rel)| rel.len() <= MAX_FIELD) else {
        // Deny only if the hub answers now: `hub_ok` can be a cached registration.
        let beat = Request::Heartbeat {
            session: session.into(),
        };
        return match d.request(beat, deadline).await {
            Err(HubError::Unavailable) => output("PreToolUse", STALE_HUB),
            _ => refusal("The file path was too long to check."),
        };
    };
    let rel = text::plain(&rel, MAX_FIELD);
    let protected = is_protected(d, session, &rel);
    let ttl_ms = d.cfg.lease_ttl.as_millis() as u64;
    let key = (repo_id.clone(), rel.clone());
    let token = d.st.lock().unwrap().sess(session).tokens.get(&key).copied();
    let mut lost = None;
    if let Some(token) = token {
        let renew = Request::LeaseRenew {
            session: session.into(),
            repo: repo_id.clone(),
            scope: rel.clone(),
            token,
            ttl_ms,
        };
        match d.request(renew, deadline).await {
            Ok(_) => return json!({}),
            Err(HubError::Unavailable) => return output("PreToolUse", STALE_HUB),
            Err(HubError::Rejected(_)) => {
                d.st.lock().unwrap().sess(session).tokens.remove(&key);
                lost = Some(token);
            }
        }
    }
    let acquire = Request::LeaseAcquire {
        session: session.into(),
        repo: repo_id.clone(),
        scope: rel.clone(),
        ttl_ms,
    };
    match d.request(acquire, deadline).await {
        Err(HubError::Unavailable) => output("PreToolUse", STALE_HUB),
        Err(HubError::Rejected(e)) => output(
            "PreToolUse",
            &format!("[wormhole] Lease check failed: {}", text::one_line(&e, 200)),
        ),
        Ok(v) => match serde_json::from_value::<LeaseResult>(v) {
            Ok(LeaseResult::Granted { lease }) => {
                d.st.lock()
                    .unwrap()
                    .sess(session)
                    .tokens
                    .insert(key, lease.token);
                match lost {
                    // Fencing: the old token was rejected; say so even though the path was free.
                    Some(old) => output(
                        "PreToolUse",
                        &format!(
                            "[wormhole] This session's lease on {rel} (token {old}) lapsed and was granted again (token {}). Another session may have edited the file in between; re-read it if that matters.",
                            lease.token
                        ),
                    ),
                    None => json!({}),
                }
            }
            Ok(LeaseResult::Held { lease }) => {
                let t = held_text(&lease, &rel, &repo_id, protected, lost);
                if protected {
                    json!({"hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": t,
                    }})
                } else {
                    output("PreToolUse", &t)
                }
            }
            Err(_) => json!({}),
        },
    }
}

/// Record what the tool did: edits as activity, reads for change notices, git commit and
/// push by name only. Never sends file contents, command text or tool output. False if
/// the hub was needed and did not answer.
async fn record_activity(
    d: &Daemon,
    session: &str,
    input: &Value,
    hub_ok: bool,
    deadline: Instant,
) -> bool {
    let tool = input["tool_name"].as_str().unwrap_or("");
    let path = tool_path(d, session, input).filter(|(_, rel)| rel.len() <= MAX_FIELD);
    let last = d.st.lock().unwrap().last_seq.unwrap_or(0);
    if tool == "Read" {
        if let Some(k) = path {
            d.st.lock().unwrap().sess(session).reads.insert(k, last);
        }
        return true;
    }
    let (kind, repo_id, paths, summary) = if EDIT_TOOLS.contains(&tool) {
        let Some((repo_id, rel)) = path else {
            return true;
        };
        // Your own edit counts as having read the result.
        d.st.lock()
            .unwrap()
            .sess(session)
            .reads
            .insert((repo_id.clone(), rel.clone()), last);
        ("edit", repo_id, vec![rel.clone()], format!("edited {rel}"))
    } else if tool == "Bash" {
        let cmd = input["tool_input"]["command"]
            .as_str()
            .unwrap_or("")
            .trim_start();
        let kind = if cmd.starts_with("git commit") {
            "commit"
        } else if cmd.starts_with("git push") {
            "push"
        } else {
            return true;
        };
        let st = d.st.lock().unwrap();
        let Some(r) = st.sessions.get(session).and_then(|s| s.repo.clone()) else {
            return true;
        };
        (kind, r.id, vec![], format!("git {kind}"))
    } else {
        return true;
    };
    if !hub_ok {
        return false;
    }
    let req = Request::Activity {
        session: session.into(),
        kind: kind.into(),
        repo: repo_id,
        paths,
        summary,
    };
    !matches!(d.request(req, deadline).await, Err(HubError::Unavailable))
}

/// "Who is working on what", for SessionStart and the wormhole_who tool.
pub(crate) async fn who_text(
    d: &Daemon,
    session: &str,
    deadline: Instant,
) -> Result<String, HubError> {
    let v = d.request(Request::Snapshot, deadline).await?;
    let snap: Snapshot = serde_json::from_value(v).unwrap_or_default();
    let my_repo =
        d.st.lock()
            .unwrap()
            .sessions
            .get(session)
            .and_then(|s| s.repo.as_ref().map(|r| r.id.clone()));
    // The block is cut at text::MAX_BLOCK characters, so this repository's leases go first,
    // then its sessions, then a count of the rest; lines that do not fit are counted.
    const ROOM: usize = text::MAX_BLOCK - 300;
    let mut body = String::new();
    let lines = |header: &str, items: Vec<String>, body: &mut String| {
        if items.is_empty() {
            return;
        }
        body.push_str(header);
        let total = items.len();
        for (i, l) in items.into_iter().enumerate() {
            if body.chars().count() + l.chars().count() > ROOM {
                body.push_str(&format!("- and {} more\n", total - i));
                return;
            }
            body.push_str(&l);
        }
    };
    let here = |repo: &str| my_repo.as_deref().is_none_or(|r| r == repo);
    let leases: Vec<String> = snap
        .leases
        .iter()
        .filter(|l| here(&l.repo))
        .map(|l| {
            format!(
                "- {} held by session {} ({}@{}) since {}\n",
                l.scope,
                l.session,
                l.user,
                l.machine,
                super::state::hms(l.since)
            )
        })
        .collect();
    lines("Leases in this repository:\n", leases, &mut body);
    let others: Vec<&SessionInfo> = snap
        .sessions
        .iter()
        .filter(|s| s.session != session)
        .collect();
    let (same, elsewhere): (Vec<&SessionInfo>, Vec<&SessionInfo>) =
        others.iter().partition(|s| here(&s.repo));
    let same: Vec<String> = same
        .iter()
        .map(|s| {
            let task: String = if s.task.is_empty() {
                "not set".into()
            } else {
                s.task.chars().take(80).collect()
            };
            format!(
                "- session {} ({}@{}), branch {}, task: {}; last seen {}\n",
                s.session,
                s.user,
                s.machine,
                s.branch,
                task,
                super::state::hms(s.last_seen)
            )
        })
        .collect();
    if same.is_empty() {
        body.push_str("No other sessions are working in this repository.\n");
    }
    lines("Other sessions in this repository:\n", same, &mut body);
    if !elsewhere.is_empty() {
        body.push_str(&format!(
            "{} other sessions are connected in other repositories (wormhole_who lists them).\n",
            elsewhere.len()
        ));
    }
    body.push_str("Edits to a leased path get a warning naming the holder. The wormhole_* tools (send, lease, request_transfer) are available if the wormhole MCP server is configured.");
    let block = text::block(
        "wormhole-state",
        &[("as_of", &super::state::hms(now_ms()))],
        &body,
    );
    Ok(text::assemble(&[block]).0)
}
