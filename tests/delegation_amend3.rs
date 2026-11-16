//! Amendment 3 to the delegation spec: a tighter tokenizer, safe programs, validated command
//! patterns, `command_allowed` as a policy method, and a refused Bash command falling through
//! to the normal prompt. The `denied_argv` cases are examples, not a claim of completeness.

mod common;

use common::*;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};
use wormhole::daemon::DaemonHandle;
use wormhole::delegation::{tokenize, Level, Policy, DEFAULT_SAFE_PROGRAMS};
use wormhole::proto::Contract;

const REPO: &str = "example.com/team/proj";
const SA: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const SB: &str = "bbbbbbbb-0000-4000-8000-000000000002";
const NOTICE: &str = "[wormhole delegation] request";

// The programs the owner enables in these tests (none are safe by default, amendment 7).
const ALL: [&str; 19] = [
    "git", "cargo", "ls", "cat", "head", "tail", "wc", "grep", "diff", "stat", "pwd", "echo",
    "true", "false", "cut", "tr", "basename", "dirname", "realpath",
];

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn grant(commands: Value) -> Value {
    json!({"from": ["alice@machine-a"], "repos": [REPO], "level": "scoped-bypass",
           "paths": ["src/**"], "kinds": ["fix"], "commands": commands})
}

fn load(grants: Vec<Value>, safe: Option<Value>) -> Result<Policy, String> {
    let mut p = json!({"grants": grants});
    // git and cargo are not defaults (amendment 4); the owner adds them here.
    p["safe_programs"] = match safe {
        Some(Value::Array(mut a)) => {
            a.extend(ALL.iter().map(|s| json!(s)));
            Value::Array(a)
        }
        Some(other) => other,
        None => json!(ALL),
    };
    Policy::parse(&p.to_string())
}

fn pol() -> Policy {
    load(vec![], None).unwrap()
}

// ---- tokenizer ----

#[test]
fn tokenize_refuses_unquoted_glob_brace_tilde_and_comment_characters() {
    for bad in [
        "ls *", "ls a*", "ls a?b", "ls [a]", "ls a]", "ls {a,b}", "ls }", "ls ~", "ls ~/x",
        "ls ~root", "~ x", "#x", "ls #x", "ls a #b",
    ] {
        assert!(tokenize(bad).is_err(), "{bad:?}");
    }
    // Quoted, or not at the start of a token, they are text.
    for good in [
        "echo '*'",
        "echo \"a*\"",
        "echo '~'",
        "echo '#x'",
        "ls a~b",
        "ls a#b",
    ] {
        assert!(tokenize(good).is_ok(), "{good:?}");
    }
}

// ---- safe programs ----

#[test]
fn safe_program_defaults_and_exact_matching() {
    let defaults: [&str; 0] = []; // amendment 7: nothing is safe by default
    assert_eq!(DEFAULT_SAFE_PROGRAMS.len(), defaults.len());
    let p = Policy::parse(r#"{"grants": []}"#).unwrap();
    for d in defaults {
        assert!(DEFAULT_SAFE_PROGRAMS.contains(&d), "{d}");
        assert!(p.safe_program(d), "{d}");
    }
    for bad in [
        "sh",
        "SH",
        "bash",
        "zsh",
        "env",
        "xargs",
        "find",
        "awk",
        "sed",
        "make",
        "npx",
        "npm",
        "sudo",
        "python3",
        "LS",
        "Git",
        "/usr/bin/git",
        "git ",
        "",
    ] {
        assert!(!p.safe_program(bad), "{bad:?}");
    }
}

#[test]
fn safe_programs_can_be_added_by_the_owner() {
    let p = load(
        vec![],
        Some(json!([
            "make",
            "shellcheck",
            "./tools/lint.sh",
            "my-tool_2"
        ])),
    )
    .unwrap();
    for a in ["make", "shellcheck", "./tools/lint.sh"] {
        assert!(p.safe_program(a), "{a}");
    }
    assert!(
        p.safe_program("ls") && p.safe_program("cat"),
        "defaults stay"
    );
    assert!(!p.safe_program("sh"));
    assert!(!p.safe_program("Make"), "case-sensitive");
    assert!(!pol().safe_program("make"));
}

#[test]
fn a_bad_safe_program_name_is_refused_at_load() {
    for bad in ["bad name", "a;b", "x*", "a$b", "a'b", "", "sh -c"] {
        assert!(load(vec![], Some(json!([bad]))).is_err(), "{bad:?}");
    }
    assert!(load(vec![], Some(json!("make"))).is_err());
}

// ---- grant patterns at load ----

#[test]
fn unsafe_programs_in_grant_patterns_are_refused_at_load() {
    for bad in [
        "find . -exec",
        "awk",
        "awk x",
        "make",
        "make all",
        "npx x",
        "sh",
        "sh -c",
        "env x",
        "SH -c x",
        "/bin/sh x",
    ] {
        let e = load(vec![grant(json!([bad]))], None)
            .err()
            .unwrap_or_else(|| panic!("{bad}"));
        assert!(e.contains("not a safe program"), "{bad}: {e}");
    }
    // The owner can add one.
    assert!(load(vec![grant(json!(["make all"]))], Some(json!(["make"]))).is_ok());
}

#[test]
fn unsafe_options_in_git_and_cargo_grant_patterns_are_refused_at_load() {
    for bad in [
        "git status -c x",
        "git status --exec-path=x",
        "git status --upload-pack=x",
        "git status --receive-pack=x",
        "cargo test --config x",
        "cargo build --config-env=x",
    ] {
        let e = load(vec![grant(json!([bad]))], None)
            .err()
            .unwrap_or_else(|| panic!("{bad}"));
        assert!(e.contains("unsafe option"), "{bad}: {e}");
    }
    // An option or toolchain before the subcommand is refused too (amendment 4).
    for bad in [
        "git -c x=y status",
        "cargo --config x test",
        "cargo --config-env=x test",
        "git --exec-path=x status",
    ] {
        assert!(load(vec![grant(json!([bad]))], None).is_err(), "{bad}");
    }
    for good in [
        "git status",
        "git status *",
        "cargo test",
        "cargo test *",
        "ls *",
        "*",
    ] {
        assert!(load(vec![grant(json!([good]))], None).is_ok(), "{good}");
    }
}

// ---- contract patterns at acceptance ----

fn contract(cmds: &[&str]) -> Contract {
    Contract {
        task_id: "T-1".into(),
        kind: "fix".into(),
        paths: strs(&["src/a.rs"]),
        commands: strs(cmds),
        exit: "done".into(),
        text: "do it".into(),
        ..Default::default()
    }
}

#[test]
fn an_unsafe_contract_pattern_makes_the_request_inform() {
    let p = load(vec![grant(json!(["*"]))], None).unwrap();
    let eval = |p: &Policy, c: &[&str]| p.evaluate("alice", "machine-a", REPO, &contract(c));
    for ok in [&["git status"][..], &["ls src", "cargo test *"], &[]] {
        assert!(eval(&p, ok).accepted, "{ok:?}");
    }
    for bad in [
        "find . -exec rm x",
        "find . -exec rm {} ;",
        "awk x",
        "make all",
        "npx x",
        "sh -c x",
        "env x",
        "git -c x=y status",
        "cargo --config x test",
        "ls *x",
        "ls ~",
        "FOO=1 ls",
    ] {
        let d = eval(&p, &[bad]);
        assert!(!d.accepted && d.level == Level::Inform, "{bad}: {d:?}");
    }
    // One unsafe pattern refuses the whole contract.
    assert!(!eval(&p, &["ls src", "sh -c x"]).accepted);
    // Added programs are accepted.
    let p = load(vec![grant(json!(["*"]))], Some(json!(["make"]))).unwrap();
    assert!(eval(&p, &["make all"]).accepted);
}

// ---- Policy::command_allowed ----

fn ok(patterns: &[&str], cmd: &str) -> bool {
    pol().command_allowed(&strs(patterns), cmd).is_ok()
}

#[test]
fn command_allowed_requires_argv0_to_match_exactly() {
    assert!(ok(&["git status"], "git status"));
    for bad in [
        "/usr/bin/git status",
        "./git status",
        "GIT status",
        "git status x",
        "git",
        "git -c alias.x=!sh status",
        "git -c x=y status",
        "FOO=1 git status",
    ] {
        assert!(!ok(&["git status"], bad), "{bad:?}");
    }
    // A pattern naming a path form matches that form only.
    let p = load(vec![], Some(json!(["/usr/bin/git"]))).unwrap();
    assert!(p
        .command_allowed(&strs(&["/usr/bin/git status"]), "/usr/bin/git status")
        .is_ok());
    assert!(p
        .command_allowed(&strs(&["/usr/bin/git status"]), "git status")
        .is_err());
}

#[test]
fn command_allowed_refuses_glob_tilde_and_wrapper_commands() {
    for bad in [
        "ls *", "ls ~", "ls ?", "ls ~root", "ls {a,b}", "ls [a]", "ls 'a'", "ls a\\b",
    ] {
        assert!(!ok(&["ls *", "ls"], bad), "{bad:?}");
    }
    assert!(!ok(&["cat *"], "cat [ab]"));
    for bad in ["SH -c x", "sh -c x", "/bin/Bash -c x", "env ls"] {
        assert!(!ok(&["sh -c x", "SH -c x", "env ls", "ls"], bad), "{bad:?}");
    }
    assert!(!pol().safe_program("SH"));
}

#[test]
fn command_allowed_trailing_star_rule() {
    let p = ["ls *"];
    assert!(ok(&p, "ls src"));
    assert!(ok(&p, "ls a b c"));
    for bad in ["ls", "ls -l", "ls a -l", "ls --all x", "lsx a", "cat a"] {
        assert!(!ok(&p, bad), "{bad:?}");
    }
    // An exact pattern does not take extra arguments.
    assert!(ok(&["cargo test"], "cargo test"));
    assert!(!ok(&["cargo test"], "cargo test --lib"));
    // An invalid pattern never matches, but a valid one beside it still can.
    assert!(ok(&["sh -c x", "git status"], "git status"));
    assert!(!ok(&["sh -c x"], "sh -c x"));
    // Added programs.
    let p = load(vec![], Some(json!(["make"]))).unwrap();
    assert!(p.command_allowed(&strs(&["make all"]), "make all").is_ok());
    assert!(pol()
        .command_allowed(&strs(&["make all"]), "make all")
        .is_err());
}

// ---- denied_argv examples ----

#[test]
fn denied_argv_examples() {
    let p = pol();
    for cmd in [
        "/bin/Bash -c x",
        "git -c core.sshCommand=x push",
        "git -c core.sshcommand=x status",
        "git -c alias.x=!sh status",
        "git -c core.pager=x log",
        "git -c core.hooksPath=x status",
        "git --config-env=a=b push -f",
        "git -C x -c core.fsmonitor=x status",
        "gh -R owner/repo pr merge 1",
        "gh --repo owner/repo pr merge 1",
        "gh --hostname h release create v1",
        "GIT push --force",
        "/usr/bin/GIT push -f",
        "git --no-pager push --force",
        "git -p push -f",
        "git --bare push --force",
    ] {
        assert!(p.denied_argv(cmd).is_some(), "should be denied: {cmd:?}");
    }
    for cmd in [
        "git -c color.ui=never status",
        "gh -R owner/repo pr view 1",
        "gh --repo owner/repo issue list",
        "git --no-pager log",
        "git -C x status",
    ] {
        assert_eq!(p.denied_argv(cmd), None, "should pass: {cmd:?}");
    }
}

// ---- end to end ----

fn repo_id() -> String {
    let d = tmpdir();
    wormhole::repo::find(&make_repo(&d.join("r"))).unwrap().id
}

async fn setup(commands: Value, safe: Option<Value>) -> Net {
    let path = tmpdir().join("policy.json");
    let g = json!({"from": ["alice@machine-a"], "repos": [repo_id()], "task_ids": ["SB-*"],
        "level": "scoped-bypass", "paths": ["src/**"], "kinds": ["fix"], "commands": commands});
    let mut p = json!({"grants": [g]});
    let mut sp: Vec<Value> = ALL.iter().map(|s| json!(s)).collect();
    if let Some(Value::Array(a)) = safe {
        sp.extend(a);
    }
    p["safe_programs"] = Value::Array(sp);
    std::fs::write(&path, p.to_string()).unwrap();
    let n = net(Opts {
        policy_b: Some(path),
        ..Opts::default()
    })
    .await;
    hook(&n.a, session_start(SA, &n.repo_a)).await;
    hook(&n.b, session_start(SB, &n.repo_b)).await;
    n
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

/// Delegate and return B's notice.
async fn delegate(n: &Net, task: &str, commands: Value) -> String {
    tool(
        &n.a,
        SA,
        "delegate",
        json!({"to_session": SB, "to": SB, "task_id": task, "kind": "fix", "text": "do it",
               "paths": ["src/**"], "exit": "done", "commands": commands}),
    )
    .await
    .unwrap();
    next_ctx(&n.b, SB, &n.repo_b, |c| {
        c.contains(NOTICE) && c.contains(task)
    })
    .await
}

/// Allowed, or the hook output carries no permission decision at all (the normal prompt).
async fn verdict(d: &DaemonHandle, cwd: &Path, cmd: &str) -> Option<String> {
    let r = hook(d, pre_bash(cwd, cmd)).await;
    assert!(
        r["hookSpecificOutput"].get("permissionDecision").is_none()
            || decision(&r).as_deref() == Some("allow"),
        "{cmd:?} must fall through to the prompt, never deny: {r}"
    );
    decision(&r)
}

#[tokio::test]
async fn scoped_bypass_allows_exact_matches_and_refused_commands_fall_through() {
    let cmds = json!(["cargo test", "ls *", "git status"]);
    let n = setup(cmds.clone(), None).await;
    let c = delegate(&n, "SB-1", cmds).await;
    assert!(c.contains("status: accepted"), "{c}");
    let r = &n.repo_b;
    for cmd in ["cargo test", "ls src", "ls a b", "git status"] {
        assert_eq!(
            verdict(&n.b, r, cmd).await.as_deref(),
            Some("allow"),
            "{cmd}"
        );
    }
    for cmd in [
        "/usr/bin/git status",
        "GIT status",
        "git -c alias.x=!sh status",
        "git -c x=y status",
        "ls *",
        "ls ~",
        "ls ?",
        "cat [ab]",
        "ls -l",
        "SH -c x",
        "sh -c x",
        "cargo test --lib",
        "cargo build",
        "find . -exec rm x",
    ] {
        assert_eq!(verdict(&n.b, r, cmd).await, None, "{cmd}");
    }
}

#[tokio::test]
async fn an_unsafe_pattern_in_the_contract_gives_information_only_and_no_allow() {
    let n = setup(json!(["*"]), None).await;
    let c = delegate(
        &n,
        "SB-2",
        json!(["find . -exec rm {} ;", "awk x", "sh -c x"]),
    )
    .await;
    assert!(c.contains("information only"), "{c}");
    assert!(!c.contains("status: accepted"), "{c}");
    let r = &n.repo_b;
    for cmd in ["find . -exec rm x", "awk x", "ls src", "cargo test"] {
        assert_eq!(verdict(&n.b, r, cmd).await, None, "{cmd}");
    }
    assert_eq!(
        decision(&hook(&n.b, pre_edit(SB, r, "src/a.rs")).await),
        None
    );

    // A tokenisable unsafe pattern is refused the same way.
    let c = delegate(&n, "SB-3", json!(["find . -exec rm x"])).await;
    assert!(c.contains("information only"), "{c}");
    assert_eq!(verdict(&n.b, r, "find . -exec rm x").await, None);

    // A safe contract under the same grant is accepted.
    let c = delegate(&n, "SB-4", json!(["ls src"])).await;
    assert!(c.contains("status: accepted"), "{c}");
    assert_eq!(verdict(&n.b, r, "ls src").await.as_deref(), Some("allow"));
}

#[tokio::test]
async fn a_program_added_through_safe_programs_works_end_to_end() {
    let n = setup(json!(["make all"]), Some(json!(["make"]))).await;
    let c = delegate(&n, "SB-5", json!(["make all"])).await;
    assert!(c.contains("status: accepted"), "{c}");
    assert_eq!(
        verdict(&n.b, &n.repo_b, "make all").await.as_deref(),
        Some("allow")
    );
    assert_eq!(verdict(&n.b, &n.repo_b, "make clean").await, None);
}
