//! Delegated tasks on the receiving daemon: decide a request from the local policy, open a
//! contract, tell the session what it may and may not do, answer `allow` only inside an open
//! bypass contract, and close contracts when their steps, time or the kill switch run out.
//! Contracts live in memory only: a restart closes them and a replayed request never
//! reopens one. See docs/adr/0001-delegation.md.

use super::state::{notice, notice_from};
use super::{hooks, Daemon, HubError};
use crate::delegation::{self, Decision, Level, Policy};
use crate::proto::*;
use crate::{glob, text};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// A contract the owner's policy let this session open.
#[derive(Clone)]
pub(crate) struct Open {
    pub seq: u64,
    pub level: Level,
    pub contract: Contract,
    pub repo: String,
    pub expires: Instant,
    pub steps_left: u64,
    /// When it was accepted and how many bypass answers it has given, to shrink it if the
    /// owner tightens the policy.
    pub accepted_at: Instant,
    pub steps_used: u64,
    /// The hub-stamped sender, to re-evaluate the policy before each bypass answer.
    pub from_user: String,
    pub from_machine: String,
}

/// Most characters of the sender's task text in a notice; the daemon's own lines come first
/// and the block cap never reaches them.
const TASK_CHARS: usize = 1000;
/// Most escaped characters the daemon's own lines may take before the relayed text.
const HEADER_BUDGET: usize = 950;

/// Best effort: closes, revokes and results are recorded when they can be.
fn audit(d: &Daemon, event: &str, seq: u64, session: &str, level: &str, extra: Value) {
    let _ = audit_strict(d, event, seq, session, level, extra);
}

/// For what grants authority (an acceptance, a bypass answer): if this fails, the authority
/// is not given.
fn audit_strict(
    d: &Daemon,
    event: &str,
    seq: u64,
    session: &str,
    level: &str,
    extra: Value,
) -> Result<(), String> {
    match &d.cfg.delegation_policy {
        Some(p) => delegation::audit(p, event, seq, session, level, extra),
        None => Err("no delegation policy".into()),
    }
}

fn shown(s: &str, n: usize) -> String {
    text::plain(s, n)
}

fn no(level: Level, reason: impl Into<String>) -> Decision {
    Decision {
        level,
        accepted: false,
        reason: reason.into(),
        ttl_secs: 0,
        max_steps: 0,
    }
}

/// The decision for one request. Only the hub-stamped sender is used, never payload fields.
fn decide(
    d: &Daemon,
    policy: Option<&Policy>,
    session: &str,
    e: &Event,
    repo: &str,
    c: &Contract,
) -> Decision {
    let path = d.cfg.delegation_policy.as_deref();
    if path.is_some_and(delegation::revoked) {
        return no(Level::Inform, "revoked");
    }
    let Some(policy) = policy else {
        return no(Level::Inform, "the delegation policy could not be read");
    };
    let mine =
        d.st.lock()
            .unwrap()
            .sessions
            .get(session)
            .and_then(|s| s.repo.as_ref().map(|r| r.id.clone()));
    if mine.as_deref() != Some(repo) {
        return no(Level::Inform, "this session is in a different repository");
    }
    policy.evaluate(&e.user, &e.machine, repo, c)
}

/// Handle a `delegation.request` event addressed to one of this daemon's sessions.
pub(crate) async fn on_request(d: std::sync::Arc<Daemon>, e: Event) {
    let Some(path) = d.cfg.delegation_policy.clone() else {
        return;
    };
    let Some(to) = e.data["to"].as_str().map(str::to_string) else {
        return;
    };
    if !d.st.lock().unwrap().sessions.contains_key(&to) || !d.hub_delegates() {
        return;
    }
    let Ok(c) = serde_json::from_value::<Contract>(e.data["contract"].clone()) else {
        return;
    };
    let repo = e.data["repo"].as_str().unwrap_or("").to_string();
    let policy = Policy::load(&path).ok();
    let mut dec = decide(&d, policy.as_ref(), &to, &e, &repo, &c);
    // Nothing is accepted that cannot be audited.
    if dec.accepted && delegation::audit_ready(&path).is_err() {
        dec = no(Level::Inform, "audit log unavailable");
    }
    let deadline = || Instant::now() + Duration::from_secs(5);
    let ack = |accept: bool, level: &str, reason: &str, ttl_ms: u64| Request::DelegateAck {
        session: to.clone(),
        request: e.seq,
        accept,
        level: level.into(),
        reason: shown(reason, MAX_SUMMARY),
        ttl_ms,
    };
    let mut granted: Vec<LeaseInfo> = Vec::new();
    if dec.accepted {
        let r = d
            .request(
                ack(true, dec.level.as_str(), &dec.reason, dec.ttl_secs * 1000),
                deadline(),
            )
            .await;
        match r {
            Ok(v) if v["fresh"] == json!(true) => {
                granted = serde_json::from_value(v["leases"].clone()).unwrap_or_default();
            }
            // Answered before (a replay after a restart): never reopen a contract.
            Ok(_) => {
                dec = no(
                    Level::Inform,
                    "this request was answered before a restart; no contract is reopened",
                )
            }
            // Fail closed: conflict, hub unavailable or anything else is not an acceptance.
            Err(HubError::Rejected(m)) => {
                dec = no(
                    Level::Inform,
                    format!("acceptance failed: {}", shown(&m, 160)),
                );
                let _ = d
                    .request(ack(false, "inform", &dec.reason, 0), deadline())
                    .await;
            }
            Err(HubError::Unavailable) => {
                dec = no(Level::Inform, "acceptance failed: the hub did not answer")
            }
        }
    } else {
        let _ = d
            .request(ack(false, dec.level.as_str(), &dec.reason, 0), deadline())
            .await;
    }
    let logged = audit_strict(
        &d,
        "request",
        e.seq,
        &to,
        dec.level.as_str(),
        json!({"accepted": dec.accepted, "reason": dec.reason, "from_user": e.user,
            "from_machine": e.machine, "task_id": c.task_id, "kind": c.kind}),
    );
    if dec.accepted && logged.is_err() {
        dec = no(Level::Inform, "audit log unavailable");
    }
    if dec.accepted {
        let o = Open {
            seq: e.seq,
            level: dec.level,
            contract: c.clone(),
            repo: repo.clone(),
            expires: Instant::now() + Duration::from_secs(dec.ttl_secs),
            steps_left: dec.max_steps,
            accepted_at: Instant::now(),
            steps_used: 0,
            from_user: e.user.clone(),
            from_machine: e.machine.clone(),
        };
        d.deleg
            .lock()
            .unwrap()
            .entry(to.clone())
            .or_default()
            .push(o);
        let mut st = d.st.lock().unwrap();
        let s = st.sess(&to);
        for l in &granted {
            s.tokens.insert((l.repo.clone(), l.scope.clone()), l.token);
        }
    }
    if dec.level == Level::Off {
        return;
    }
    let body = request_body(&e, &c, &repo, &dec, policy.as_ref());
    d.st.lock().unwrap().sess(&to).notify(notice(
        &e,
        "wormhole-delegation",
        "delegation_request",
        &body,
        true,
    ));
}

fn escaped_len(s: &str) -> usize {
    text::clean(s, usize::MAX / 8).chars().count()
}

/// The first characters of `s` whose escaped form fits in `n` characters.
fn fit(s: &str, n: usize) -> String {
    let (mut out, mut used) = (String::new(), 0);
    for c in s.chars() {
        let cost = match c {
            '<' | '>' => 4,
            '&' => 5,
            _ => 1,
        };
        if used + cost > n {
            out.push_str("…[truncated]");
            break;
        }
        used += cost;
        out.push(c);
    }
    out
}

/// The notice body. The daemon writes the status line and the boundary; the relayed task
/// text comes last and is cut so the block cap cannot remove the limits.
fn request_body(
    e: &Event,
    c: &Contract,
    repo: &str,
    dec: &Decision,
    policy: Option<&Policy>,
) -> String {
    let status = if dec.accepted {
        "accepted"
    } else if dec.level == Level::Off {
        "declined"
    } else {
        "informed"
    };
    let list = |v: &[String], n: usize| {
        if v.is_empty() {
            "none".to_string()
        } else {
            shown(&v.join(", "), n)
        }
    };
    let header = |div: usize| {
        let mut h = format!(
            "[wormhole delegation] request {} from session {} ({}@{}): status: {status}; level: {}; reason: {}; task {}; kind {}\n",
            e.seq,
            shown(&e.session, 64 / div),
            shown(&e.user, 64 / div),
            shown(&e.machine, 64 / div),
            dec.level.as_str(),
            shown(&dec.reason, 160 / div),
            shown(&c.task_id, 40 / div),
            shown(&c.kind, 40 / div)
        );
        if dec.accepted {
            h.push_str(&format!(
                "Boundary: repository {}; task {}; kind {}; paths: {}; commands: {}; spec: {}; done when: {}; expires in {} s; step budget {}.\n",
                shown(repo, 80 / div),
                shown(&c.task_id, 40 / div),
                shown(&c.kind, 40 / div),
                list(&c.paths, 160 / div),
                list(&c.commands, 160 / div),
                shown(&c.spec, 80 / div),
                shown(&c.exit, 100 / div),
                dec.ttl_secs,
                dec.max_steps
            ));
            h.push_str(&format!("Leases held: {}.\n", list(&c.paths, 120 / div)));
            h.push_str(if dec.level == Level::ScopedInstruction {
                "Your permission prompts remain in force.\n"
            } else {
                "Tool calls inside this boundary run without a permission prompt; anything else prompts as usual.\n"
            });
            if let Some(k) = policy.map(Policy::deny_kinds).filter(|k| !k.is_empty()) {
                h.push_str(&format!(
                    "Not authorised by this delegation: {}.\n",
                    shown(&k.join(", "), 120)
                ));
            }
            let fields = if c.result_fields.is_empty() {
                String::new()
            } else {
                format!(
                    " A done result must carry the fields: {}.",
                    shown(&c.result_fields.join(", "), 120 / div)
                )
            };
            h.push_str(&format!(
                "When finished, call wormhole_result with request {}, a status (done, failed or partial) and a summary.{fields}\n",
                e.seq
            ));
        } else {
            h.push_str(
                "This is information only: it carries no permission, and your permission prompts remain in force.\n",
            );
        }
        h.push_str(&format!(
            "Task text, relayed from session {}:\n",
            shown(&e.session, 64 / div)
        ));
        h
    };
    let mut h = header(1);
    for div in [2, 4, 8] {
        if escaped_len(&h) <= HEADER_BUDGET {
            break;
        }
        h = header(div);
    }
    let room = text::MAX_BLOCK
        .saturating_sub(escaped_len(&h) + 16)
        .min(TASK_CHARS);
    format!("{h}{}", fit(&c.text, room))
}

fn remove_if_empty(m: &mut std::collections::HashMap<String, Vec<Open>>, session: &str) {
    if m.get(session).is_some_and(Vec::is_empty) {
        m.remove(session);
    }
}

/// Close one contract: audit it and tell the session its prompts are back.
fn closed(d: &Daemon, session: &str, o: &Open, reason: &str) {
    audit(
        d,
        "close",
        o.seq,
        session,
        o.level.as_str(),
        json!({"reason": reason}),
    );
    let body = format!(
        "[wormhole delegation] request {} closed: {reason}. Tool calls prompt for permission as usual again.",
        o.seq
    );
    d.st.lock().unwrap().sess(session).notify(notice_from(
        o.seq,
        now_ms(),
        vec![("seq".into(), o.seq.to_string())],
        "wormhole-delegation",
        "delegation_closed",
        &body,
        false,
    ));
}

/// Close this session's contracts that ran out of time.
fn expire(d: &Daemon, session: Option<&str>) {
    let now = Instant::now();
    let gone: Vec<(String, Open)> = {
        let mut m = d.deleg.lock().unwrap();
        let mut gone = Vec::new();
        for (s, v) in m.iter_mut() {
            if session.is_some_and(|x| x != s) {
                continue;
            }
            let (dead, live): (Vec<Open>, Vec<Open>) = v.drain(..).partition(|o| o.expires <= now);
            *v = live;
            gone.extend(dead.into_iter().map(|o| (s.clone(), o)));
        }
        m.retain(|_, v| !v.is_empty());
        gone
    };
    for (s, o) in gone {
        closed(d, &s, &o, "its time ran out");
    }
}

/// The kill switch: close every open contract, tell each sender, audit it. Used by the
/// socket op, and by a hook or the sweeper that finds the file.
pub(crate) async fn kill(d: &Daemon) {
    let all: Vec<(String, Open)> = {
        let mut m = d.deleg.lock().unwrap();
        m.drain()
            .flat_map(|(s, v)| v.into_iter().map(move |o| (s.clone(), o)))
            .collect()
    };
    if all.is_empty() {
        audit(d, "revoke", 0, "", "", json!({}));
    }
    for (s, o) in all {
        audit(d, "revoke", o.seq, &s, o.level.as_str(), json!({}));
        closed(d, &s, &o, "revoked by the receiving machine's owner");
        audit(
            d,
            "result",
            o.seq,
            &s,
            o.level.as_str(),
            json!({"status": "revoked"}),
        );
        let r = Request::DelegateResult {
            session: s,
            request: o.seq,
            status: "revoked".into(),
            summary: "revoked by the receiving machine's owner".into(),
            fields: Default::default(),
        };
        // Only while the hub advertises delegation: an old hub must never see the frame.
        if d.hub_delegates() {
            let _ = d.request(r, Instant::now() + Duration::from_secs(3)).await;
        }
    }
}

fn any_open(d: &Daemon) -> bool {
    !d.deleg.lock().unwrap().is_empty()
}

/// Close what ran out of time and, if the kill switch file is set, everything.
async fn check(d: &Daemon, session: Option<&str>) {
    expire(d, session);
    if any_open(d)
        && d.cfg
            .delegation_policy
            .as_deref()
            .is_some_and(delegation::revoked)
    {
        kill(d).await;
    }
}

/// Close contracts as their time runs out or the kill switch is set, even when the session
/// makes no tool call.
pub(crate) async fn sweep(d: std::sync::Arc<Daemon>) {
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tick.tick().await;
        check(&d, None).await;
    }
}

/// A result was posted: the contract it answers closes.
pub(crate) fn finished(d: &Daemon, session: &str, request: u64, status: &str) {
    let o = {
        let mut m = d.deleg.lock().unwrap();
        let o = m
            .get_mut(session)
            .and_then(|v| v.iter().position(|o| o.seq == request).map(|i| v.remove(i)));
        remove_if_empty(&mut m, session);
        o
    };
    let level = o.as_ref().map_or("", |o| o.level.as_str());
    audit(
        d,
        "result",
        request,
        session,
        level,
        json!({"status": status}),
    );
    if let Some(o) = o {
        closed(d, session, &o, "the result was posted");
    }
}

/// The session's repository id and the working directory its paths are resolved against.
fn session_repo(
    d: &Daemon,
    session: &str,
) -> Option<(String, std::path::PathBuf, std::path::PathBuf)> {
    let st = d.st.lock().unwrap();
    let s = st.sessions.get(session)?;
    let r = s.repo.as_ref()?;
    Some((r.id.clone(), r.root.clone(), s.cwd.clone()?))
}

/// May the Bash operand `tok` be touched? It is read as a path: inside the repository after
/// symlinks are followed, not dangling, not protected, not denylisted.
fn operand_ok(d: &Daemon, session: &str, policy: &Policy, dir_ok: bool, tok: &str) -> bool {
    let Some((_, root, cwd)) = session_repo(d, session) else {
        return false;
    };
    if tok.starts_with('/')
        || tok.split('/').any(|x| x == "..")
        || crate::repo::dangling_symlink(&cwd, tok)
    {
        return false;
    }
    // A directory can hold denied files that a recursive read would print.
    if cwd.join(tok).is_dir() && !dir_ok {
        return false;
    }
    match crate::repo::canonical_relative(&root, &cwd, tok) {
        Some(rel) => policy.denied_path(&rel).is_none() && !hooks::is_protected(d, session, &rel),
        // `.` or the root itself names the repository, which no scope covers.
        None => false,
    }
}

/// Why `tool` with `input` may be answered `allow` under `o`, as the audit key and value.
fn permitted(
    d: &Daemon,
    session: &str,
    policy: &Policy,
    o: &Open,
    tool: &str,
    input: &Value,
    granted: bool,
) -> Option<(&'static str, String)> {
    let ti = &input["tool_input"];
    let edit = hooks::EDIT_TOOLS.contains(&tool);
    // Full bypass covers exactly Bash, the edit tools and Read; scoped bypass never Read.
    if edit || (tool == "Read" && o.level == Level::FullBypass) {
        // The path key is the tool's own, and only that one: two keys could name two files.
        let (want, other) = if tool == "NotebookEdit" {
            ("notebook_path", "file_path")
        } else {
            ("file_path", "notebook_path")
        };
        let file = ti[want].as_str()?;
        if !ti[other].is_null() {
            return None;
        }
        let (_, _, cwd) = session_repo(d, session)?;
        if crate::repo::dangling_symlink(&cwd, file) {
            return None;
        }
        // Edits need the lease step to have ended with this session holding the path: a held
        // lease, a protected path or an unchecked path never gets `allow`. Every path is
        // resolved inside the repository and checked against the denylist and --protected.
        let (repo, rel) = hooks::tool_path(d, session, input).filter(|_| granted || !edit)?;
        let inside = o.level == Level::FullBypass
            || o.contract
                .paths
                .iter()
                .any(|p| glob::matches(p, &rel) || glob::covers(p, &rel));
        let ok = repo == o.repo
            && inside
            && policy.denied_path(&rel).is_none()
            && !hooks::is_protected(d, session, &rel);
        return ok.then_some(("path", rel));
    }
    if tool == "Bash" {
        // An unsandboxed command is never answered for.
        if !ti["dangerouslyDisableSandbox"].is_null()
            && ti["dangerouslyDisableSandbox"] != json!(false)
        {
            return None;
        }
        let cmd = ti["command"].as_str()?;
        if session_repo(d, session)?.0 != o.repo {
            return None;
        }
        let ok = if o.level == Level::ScopedBypass {
            policy.command_allowed(&o.contract.commands, cmd).is_ok() && {
                // Every operand is a path the contract could have named; options carry no `=`.
                let t = delegation::tokenize(cmd).ok()?;
                let prog = t[0].rsplit('/').next().unwrap_or("").to_lowercase();
                // Plain options only, nothing recursive, and every operand a path inside the
                // contract's reach; a command with no operand would read the working directory.
                // `git status` reports names only, so like these it may take a directory.
                let dir_ok = matches!(
                    prog.as_str(),
                    "ls" | "stat" | "realpath" | "basename" | "dirname"
                ) || (prog == "git" && t.get(1).is_some_and(|s| s == "status"));
                delegation::command_operands(&t)
                    .ok()?
                    .iter()
                    .all(|x| operand_ok(d, session, policy, dir_ok, x))
            }
        } else {
            // Full bypass with the denylist on still refuses what cannot be read as plain words.
            !policy.denylist_on() || delegation::runnable(cmd).is_ok()
        };
        if !ok || policy.denied_argv(cmd).is_some() || policy.denied_command(cmd).is_some() {
            return None;
        }
        return Some(("command", shown(cmd, 512)));
    }
    None
}

/// The hook's last step. With no open bypass contract for the session `out` comes back
/// untouched, byte for byte. Otherwise, if everything the lease step found and the policy
/// still agree, the answer is `allow`, and it spends one step.
pub(crate) async fn bypass(
    d: &Daemon,
    session: &str,
    input: &Value,
    out: Value,
    granted: bool,
    hub_ok: bool,
) -> Value {
    if !d.deleg.lock().unwrap().contains_key(session) {
        return out;
    }
    check(d, Some(session)).await;
    let Some(path) = d.cfg.delegation_policy.as_deref() else {
        return out;
    };
    // The existing behaviour wins: a deny stays a deny, a stale hub gives no allow.
    if !hub_ok || out["hookSpecificOutput"]["permissionDecision"] == "deny" {
        return out;
    }
    let Ok(policy) = Policy::load(path) else {
        return out;
    };
    // The owner may have narrowed the policy since acceptance. A contract the file no longer
    // grants at its level closes; one it still grants is cut to the new time and step limits,
    // and closes if either is already used up.
    let closing: Vec<(Open, &str)> = {
        let mut m = d.deleg.lock().unwrap();
        let now = Instant::now();
        let mut out = Vec::new();
        if let Some(v) = m.get_mut(session) {
            let mut keep = Vec::new();
            for mut o in v.drain(..) {
                let dec = policy.evaluate(&o.from_user, &o.from_machine, &o.repo, &o.contract);
                if !(dec.accepted && dec.level >= o.level) {
                    out.push((o, "the policy no longer grants it"));
                    continue;
                }
                o.expires = o
                    .expires
                    .min(o.accepted_at + Duration::from_secs(dec.ttl_secs));
                o.steps_left = o.steps_left.min(dec.max_steps.saturating_sub(o.steps_used));
                if o.expires <= now || o.steps_left == 0 {
                    out.push((o, "policy tightened"));
                } else {
                    keep.push(o);
                }
            }
            *v = keep;
        }
        remove_if_empty(&mut m, session);
        out
    };
    for (o, why) in &closing {
        closed(d, session, o, why);
    }
    let open: Vec<Open> = d
        .deleg
        .lock()
        .unwrap()
        .get(session)
        .map(|v| {
            v.iter()
                .filter(|o| o.level >= Level::ScopedBypass)
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    if open.is_empty() {
        return out;
    }
    let tool = input["tool_name"].as_str().unwrap_or("");
    let Some((o, key, val)) = open.iter().find_map(|o| {
        permitted(d, session, &policy, o, tool, input, granted).map(|(k, v)| (o, k, v))
    }) else {
        return out;
    };
    // Spend the step before answering; a racing call that finds none left gets no allow.
    let left = {
        let mut m = d.deleg.lock().unwrap();
        let left = m
            .get_mut(session)
            .and_then(|v| v.iter_mut().find(|x| x.seq == o.seq))
            .filter(|x| x.steps_left > 0)
            .map(|x| {
                x.steps_left -= 1;
                x.steps_used += 1;
                x.steps_left
            });
        left
    };
    let Some(left) = left else {
        return out;
    };
    // No audit line, no allow.
    if audit_strict(
        d,
        "allow",
        o.seq,
        session,
        o.level.as_str(),
        json!({"tool": tool, key: val}),
    )
    .is_err()
    {
        return out;
    }
    if left == 0 {
        let gone = {
            let mut m = d.deleg.lock().unwrap();
            let gone = m
                .get_mut(session)
                .and_then(|v| v.iter().position(|x| x.seq == o.seq).map(|i| v.remove(i)));
            remove_if_empty(&mut m, session);
            gone
        };
        if let Some(g) = gone {
            closed(d, session, &g, "its step budget is spent");
        }
    }
    let mut h = json!({
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "permissionDecisionReason": format!(
            "wormhole delegation {} ({}): {tool} inside the contract boundary", o.seq, o.level.as_str()),
    });
    if let Some(c) = out["hookSpecificOutput"]["additionalContext"].as_str() {
        h["additionalContext"] = json!(c);
    }
    json!({"hookSpecificOutput": h})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> Event {
        Event {
            seq: 7,
            ts: 0,
            kind: "delegation.request".into(),
            user: "alice".into(),
            machine: "machine-a".into(),
            session: "s1".into(),
            data: json!({}),
        }
    }

    #[test]
    fn the_limits_survive_a_huge_hostile_task_text() {
        let policy = Policy::parse(r#"{"grants":[]}"#).unwrap();
        let c = Contract {
            task_id: "T-1".into(),
            kind: "tests".into(),
            paths: (0..30).map(|i| format!("src/dir{i}/**")).collect(),
            commands: (0..16)
                .map(|i| format!("cargo test --package p{i}*"))
                .collect(),
            spec: "s".repeat(1000),
            exit: "<&>".repeat(300),
            text: "<script>&".repeat(2000),
            result_fields: vec!["sha".into(); 16],
            ..Default::default()
        };
        let dec = Decision {
            level: Level::ScopedBypass,
            accepted: true,
            reason: "r".repeat(300),
            ttl_secs: 60,
            max_steps: 5,
        };
        let body = request_body(&event(), &c, "example.com/x/y", &dec, Some(&policy));
        let block = text::block("wormhole-delegation", &[], &body);
        for must in [
            "status: accepted; level: scoped-bypass",
            "Not authorised by this delegation",
            "wormhole_result",
            "Task text, relayed from session s1:",
        ] {
            assert!(block.contains(must), "{must} missing from {block}");
        }
        assert!(text::clean(&body, usize::MAX / 8).chars().count() <= text::MAX_BLOCK);
        // Not accepted: information only, still first.
        let no = no(Level::Inform, "outside the grant");
        let body = request_body(&event(), &c, "r", &no, None);
        assert!(body.starts_with("[wormhole delegation] request 7"));
        assert!(body.contains("information only") && !body.contains("Boundary"));
        assert!(body.contains("task T-1; kind tests"), "{body}");
    }

    #[test]
    fn fit_counts_escaped_characters() {
        assert_eq!(fit("abc", 10), "abc");
        assert_eq!(fit("<<<", 8), "<<…[truncated]");
        assert_eq!(fit("&&", 5), "&…[truncated]");
    }
}
