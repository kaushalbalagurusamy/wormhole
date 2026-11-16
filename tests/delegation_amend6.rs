//! Amendment 6 to the delegation spec: git only with `status` while the denylist is on,
//! directory operands for read programs, and tightening the policy shrinking open contracts.

mod common;

use common::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use wormhole::daemon::DaemonHandle;
use wormhole::delegation::{self, Policy, GIT_SUBCOMMANDS_DENYLIST_ON};
use wormhole::proto::Contract;

const REPO: &str = "example.com/team/proj";
const SA: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const SB: &str = "bbbbbbbb-0000-4000-8000-000000000002";
const NOTICE: &str = "[wormhole delegation] request";

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn grant(commands: Value) -> Value {
    json!({"from": ["alice@machine-a"], "repos": [REPO], "level": "scoped-bypass",
           "paths": ["src/**"], "kinds": ["fix"], "commands": commands})
}

fn load(commands: Value, denylist_on: bool) -> Result<Policy, String> {
    let mut p = json!({"grants": [grant(commands)], "safe_programs": ["git", "cargo", "ls", "cat", "head", "tail", "wc", "grep", "diff", "stat", "pwd", "echo", "true", "false", "cut", "tr", "basename", "dirname", "realpath"]});
    if !denylist_on {
        p["denylist"] = json!({"enabled": false});
    }
    Policy::parse(&p.to_string())
}

fn eval(p: &Policy, cmds: &[&str]) -> bool {
    p.evaluate(
        "alice",
        "machine-a",
        REPO,
        &Contract {
            task_id: "T-1".into(),
            kind: "fix".into(),
            paths: strs(&["src/a.rs"]),
            commands: strs(cmds),
            exit: "done".into(),
            text: "do it".into(),
            ..Default::default()
        },
    )
    .accepted
}

// ---- pure ----

#[test]
fn the_denylist_on_subcommand_list_is_status_only() {
    assert_eq!(GIT_SUBCOMMANDS_DENYLIST_ON, ["status"]);
}

#[test]
fn git_log_diff_and_show_are_refused_at_load_and_acceptance_while_the_denylist_is_on() {
    for pat in [
        "git log",
        "git diff",
        "git show *",
        "git log *",
        "git show",
        "git diff --stat",
    ] {
        assert!(load(json!([pat]), true).is_err(), "load: {pat}");
    }
    for pat in ["git status", "git status *", "git status --short"] {
        assert!(load(json!([pat]), true).is_ok(), "load: {pat}");
    }
    let p = load(json!(["*"]), true).unwrap();
    for pat in ["git log", "git diff", "git show *", "git log *"] {
        assert!(!eval(&p, &[pat]), "accept: {pat}");
    }
    assert!(eval(&p, &["git status", "git status *"]));
    // Per call, nothing but status gets through.
    let p = load(json!(["git status", "git status *"]), true).unwrap();
    let pats = strs(&["git status", "git status *"]);
    for cmd in [
        "git show HEAD",
        "git diff",
        "git log",
        "git log src",
        "git show src",
    ] {
        assert!(p.command_allowed(&pats, cmd).is_err(), "{cmd}");
    }
    assert!(p.command_allowed(&pats, "git status").is_ok());
    assert!(p.command_allowed(&pats, "git status src").is_ok());
}

#[test]
fn with_the_denylist_off_log_diff_and_show_work() {
    let pats = ["git log", "git diff", "git show *"];
    let p = load(json!(pats), false).unwrap();
    for cmd in ["git log", "git diff", "git show HEAD"] {
        assert!(p.command_allowed(&strs(&pats), cmd).is_ok(), "{cmd}");
    }
    assert!(p.command_allowed(&strs(&pats), "git push").is_err());
    assert!(eval(&load(json!(["*"]), false).unwrap(), &pats));
}

// ---- end to end ----

fn repo_id() -> String {
    let d = tmpdir();
    wormhole::repo::find(&make_repo(&d.join("r"))).unwrap().id
}

struct T {
    n: Net,
    policy: PathBuf,
}

fn policy_json(commands: &Value, denylist_on: bool, max_steps: u64, max_ttl: u64) -> Value {
    let g = json!({"from": ["alice@machine-a"], "repos": [repo_id()], "task_ids": ["SB-*"],
        "level": "scoped-bypass", "paths": ["src/**"], "kinds": ["fix"], "commands": commands,
        "max_steps": max_steps, "max_ttl_secs": max_ttl});
    let mut p = json!({"grants": [g], "safe_programs": ["git", "cargo", "ls", "cat", "head", "tail", "wc", "grep", "diff", "stat", "pwd", "echo", "true", "false", "cut", "tr", "basename", "dirname", "realpath"]});
    if !denylist_on {
        p["denylist"] = json!({"enabled": false});
    }
    p
}

async fn setup(commands: Value, denylist_on: bool) -> T {
    let policy = tmpdir().join("policy.json");
    std::fs::write(
        &policy,
        policy_json(&commands, denylist_on, 200, 3600).to_string(),
    )
    .unwrap();
    let n = net(Opts {
        policy_b: Some(policy.clone()),
        ..Opts::default()
    })
    .await;
    std::fs::create_dir_all(n.repo_b.join("src/sub")).unwrap();
    std::fs::create_dir_all(n.repo_b.join("src2")).unwrap();
    std::fs::write(n.repo_b.join("src/a.rs"), "x").unwrap();
    hook(&n.a, session_start(SA, &n.repo_a)).await;
    hook(&n.b, session_start(SB, &n.repo_b)).await;
    T { n, policy }
}

async fn next_ctx(
    d: &DaemonHandle,
    session: &str,
    cwd: &Path,
    pred: impl Fn(&str) -> bool,
) -> String {
    let t = Instant::now();
    loop {
        let c = ctx(&hook(d, post_bash(session, cwd)).await);
        if pred(&c) {
            return c;
        }
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "no matching context; last: {c}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn pre_bash(cwd: &Path, cmd: &str) -> Value {
    let mut v = base("PreToolUse", SB, cwd);
    v["tool_name"] = json!("Bash");
    v["tool_input"] = json!({"command": cmd});
    v["tool_use_id"] = json!("toolu_9");
    v
}

async fn allowed(d: &DaemonHandle, input: Value) -> bool {
    decision(&hook(d, input).await).as_deref() == Some("allow")
}

async fn delegate(n: &Net, task: &str, commands: Value, extra: Value) -> String {
    let mut a = json!({"to_session": SB, "to": SB, "task_id": task, "kind": "fix", "text": "do it",
               "paths": ["src/**"], "exit": "done", "commands": commands});
    for (k, v) in extra.as_object().unwrap() {
        a[k] = v.clone();
    }
    tool(&n.a, SA, "delegate", a).await.unwrap();
    next_ctx(&n.b, SB, &n.repo_b, |c| {
        c.contains(NOTICE) && c.contains(task)
    })
    .await
}

#[tokio::test]
async fn git_show_diff_and_log_get_no_allow_while_the_denylist_is_on() {
    let t = setup(json!(["*"]), true).await;
    let c = delegate(&t.n, "SB-1", json!(["git status"]), json!({})).await;
    assert!(c.contains("status: accepted"), "{c}");
    let (b, r) = (&t.n.b, &t.n.repo_b);
    assert!(allowed(b, pre_bash(r, "git status")).await);
    for cmd in ["git show HEAD", "git diff", "git log"] {
        assert!(!allowed(b, pre_bash(r, cmd)).await, "{cmd}");
    }
    // A contract naming them is information only.
    for (i, pat) in ["git log", "git diff", "git show *"].iter().enumerate() {
        let task = format!("SB-{}", i + 2);
        let c = delegate(&t.n, &task, json!([pat]), json!({})).await;
        assert!(c.contains("status: informed"), "{pat}: {c}");
    }
}

#[tokio::test]
async fn git_show_diff_and_log_are_allowed_with_the_denylist_off() {
    let cmds = json!(["git log", "git diff", "git show *"]);
    let t = setup(cmds.clone(), false).await;
    let c = delegate(&t.n, "SB-1", cmds, json!({})).await;
    assert!(c.contains("status: accepted"), "{c}");
    let (b, r) = (&t.n.b, &t.n.repo_b);
    for cmd in ["git log", "git diff", "git show HEAD"] {
        assert!(allowed(b, pre_bash(r, cmd)).await, "{cmd}");
    }
    assert!(!allowed(b, pre_bash(r, "git push")).await);
}

#[tokio::test]
async fn a_directory_operand_is_allowed_only_for_ls_stat_realpath_basename_dirname() {
    let pats = json!([
        "grep *",
        "cat *",
        "head *",
        "ls *",
        "stat *",
        "realpath *",
        "basename *",
        "dirname *",
        "diff *"
    ]);
    let t = setup(json!(["*"]), true).await;
    let c = delegate(&t.n, "SB-1", pats, json!({})).await;
    assert!(c.contains("status: accepted"), "{c}");
    let (b, r) = (&t.n.b, &t.n.repo_b);
    for cmd in [
        "ls src",
        "stat src",
        "realpath src",
        "basename src",
        "dirname src",
        "ls src/sub",
        "grep x src/a.rs",
        "cat src/a.rs",
        "head src/a.rs",
        "diff src/a.rs src/a.rs",
    ] {
        assert!(allowed(b, pre_bash(r, cmd)).await, "{cmd}");
    }
    for cmd in [
        "grep x src",
        "grep -r x src",
        "cat src",
        "head src",
        "diff src src2",
        "diff -r src src2",
        "cat src/a.rs src",
        "grep x src/sub",
    ] {
        assert!(!allowed(b, pre_bash(r, cmd)).await, "{cmd}");
    }
}

fn audit(policy: &Path) -> Vec<Value> {
    std::fs::read_to_string(delegation::audit_path(policy))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn closed_as_tightened(policy: &Path) -> bool {
    audit(policy).iter().any(|l| {
        l["event"] == "close"
            && l["reason"]
                .as_str()
                .is_some_and(|r| r.contains("policy tightened"))
    })
}

#[tokio::test]
async fn tightening_steps_and_ttl_shrinks_an_open_contract() {
    let t = setup(json!(["ls *"]), true).await;
    let cmds = json!(["ls *"]);
    std::fs::write(&t.policy, policy_json(&cmds, true, 10, 3600).to_string()).unwrap();
    let c = delegate(
        &t.n,
        "SB-1",
        cmds.clone(),
        json!({"max_steps": 10, "ttl_seconds": 3600}),
    )
    .await;
    assert!(c.contains("status: accepted"), "{c}");
    let (b, r) = (&t.n.b, &t.n.repo_b);
    for _ in 0..2 {
        assert!(allowed(b, pre_edit(SB, r, "src/a.rs")).await);
    }
    // Tighten: three steps in all, and a one-second lifetime counted from acceptance.
    std::fs::write(&t.policy, policy_json(&cmds, true, 3, 1).to_string()).unwrap();
    let mut more = 0;
    for _ in 0..4 {
        if allowed(b, pre_edit(SB, r, "src/a.rs")).await {
            more += 1;
        }
    }
    assert!(
        more <= 1,
        "{more} allows after tightening to 3 steps with 2 spent"
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!allowed(b, pre_edit(SB, r, "src/a.rs")).await);
    assert!(!allowed(b, pre_bash(r, "ls src")).await);
}

#[tokio::test]
async fn tightening_below_the_steps_already_spent_closes_the_contract() {
    let t = setup(json!(["ls *"]), true).await;
    let cmds = json!(["ls *"]);
    std::fs::write(&t.policy, policy_json(&cmds, true, 10, 3600).to_string()).unwrap();
    let c = delegate(
        &t.n,
        "SB-1",
        cmds.clone(),
        json!({"max_steps": 10, "ttl_seconds": 3600}),
    )
    .await;
    assert!(c.contains("status: accepted"), "{c}");
    let (b, r) = (&t.n.b, &t.n.repo_b);
    for _ in 0..2 {
        assert!(allowed(b, pre_edit(SB, r, "src/a.rs")).await);
    }
    std::fs::write(&t.policy, policy_json(&cmds, true, 2, 3600).to_string()).unwrap();
    assert!(!allowed(b, pre_edit(SB, r, "src/a.rs")).await);
    assert!(!allowed(b, pre_bash(r, "ls src")).await);
    assert!(closed_as_tightened(&t.policy), "{:?}", audit(&t.policy));
}
