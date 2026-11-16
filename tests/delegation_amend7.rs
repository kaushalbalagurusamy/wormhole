//! Amendment 7 to the delegation spec: nothing is safe by default, option and operand rules for
//! every program the owner enables, recursive options refused, no-operand commands refused.

mod common;

use common::*;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};
use wormhole::daemon::DaemonHandle;
use wormhole::delegation::{Policy, DEFAULT_SAFE_PROGRAMS, NO_OPERAND_PROGRAMS};

const REPO: &str = "example.com/team/proj";
const SA: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const SB: &str = "bbbbbbbb-0000-4000-8000-000000000002";
const NOTICE: &str = "[wormhole delegation] request";
const ENABLED: [&str; 8] = ["cat", "grep", "ls", "diff", "head", "echo", "pwd", "git"];

// ---- pure ----

#[test]
fn nothing_is_safe_by_default_and_four_programs_need_no_operand() {
    assert!(DEFAULT_SAFE_PROGRAMS.is_empty());
    assert_eq!(NO_OPERAND_PROGRAMS, ["pwd", "echo", "true", "false"]);
    let p = Policy::parse(r#"{"grants": []}"#).unwrap();
    for prog in [
        "ls", "cat", "grep", "pwd", "echo", "git", "cargo", "head", "diff",
    ] {
        assert!(!p.safe_program(prog), "{prog}");
    }
}

#[test]
fn a_grant_pattern_needs_an_enabled_program() {
    let g = |c: Value| {
        json!({"from": ["alice@machine-a"], "repos": [REPO], "level": "scoped-bypass",
               "paths": ["src/**"], "kinds": ["fix"], "commands": c})
    };
    for pat in [
        "ls *",
        "cat *",
        "pwd",
        "echo hi",
        "grep x *",
        "git status",
        "cargo test",
    ] {
        let e = Policy::parse(&json!({"grants": [g(json!([pat]))]}).to_string())
            .err()
            .unwrap_or_else(|| panic!("{pat}"));
        assert!(e.contains("not a safe program"), "{pat}: {e}");
        let ok = Policy::parse(
            &json!({"grants": [g(json!([pat]))], "safe_programs": ["ls", "cat", "pwd", "echo", "grep", "git", "cargo"]})
                .to_string(),
        );
        assert!(ok.is_ok(), "{pat}: {:?}", ok.err());
    }
    // No commands at all is still a valid grant.
    assert!(Policy::parse(&json!({"grants": [g(json!([]))]}).to_string()).is_ok());
}

#[test]
fn the_example_policy_loads() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/examples/delegation-policy.json");
    let p = Policy::load(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    for prog in ["ls", "cat", "grep"] {
        assert!(p.safe_program(prog), "{prog}");
    }
    assert!(!p.safe_program("sh"));
}

// ---- end to end ----

fn repo_id() -> String {
    let d = tmpdir();
    wormhole::repo::find(&make_repo(&d.join("r"))).unwrap().id
}

async fn setup(safe: &[&str]) -> Net {
    setup_with(safe, json!(["*"])).await
}

async fn setup_with(safe: &[&str], commands: Value) -> Net {
    let path = tmpdir().join("policy.json");
    let g = json!({"from": ["alice@machine-a"], "repos": [repo_id()], "task_ids": ["SB-*"],
        "level": "scoped-bypass", "paths": ["src/**"], "kinds": ["fix"], "commands": commands});
    std::fs::write(
        &path,
        json!({"grants": [g], "safe_programs": safe}).to_string(),
    )
    .unwrap();
    let n = net(Opts {
        policy_b: Some(path),
        ..Opts::default()
    })
    .await;
    std::fs::create_dir_all(n.repo_b.join("src")).unwrap();
    std::fs::write(n.repo_b.join("src/a.rs"), "x").unwrap();
    std::fs::write(n.repo_b.join("src/.env"), "secret").unwrap();
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

async fn allowed(d: &DaemonHandle, cwd: &Path, cmd: &str) -> bool {
    decision(&hook(d, pre_bash(cwd, cmd)).await).as_deref() == Some("allow")
}

/// Delegate with these command patterns and return B's notice (accepted or not).
async fn delegate(n: &Net, task: &str, commands: &[&str]) -> String {
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

#[tokio::test]
async fn with_no_safe_programs_no_bash_command_is_allowed() {
    let n = setup(&[]).await;
    let r = &n.repo_b;
    // A contract naming any command cannot be accepted: the program is not safe.
    for (i, pat) in ["ls src", "ls *", "pwd", "echo hi"].iter().enumerate() {
        let c = delegate(&n, &format!("SB-{}", i + 1), &[pat]).await;
        assert!(c.contains("status: informed"), "{pat}: {c}");
    }
    // A contract without commands is accepted, and still gives no Bash allow.
    let c = delegate(&n, "SB-9", &[]).await;
    assert!(c.contains("status: accepted"), "{c}");
    assert!(decision(&hook(&n.b, pre_edit(SB, r, "src/a.rs")).await).as_deref() == Some("allow"));
    for cmd in [
        "ls src",
        "pwd",
        "echo hi",
        "cat src/a.rs",
        "true",
        "git status",
    ] {
        assert!(!allowed(&n.b, r, cmd).await, "{cmd}");
    }
}

#[tokio::test]
async fn enabled_programs_are_allowed_with_a_path_checked_operand() {
    // Option-bearing patterns are listed verbatim in the grant (amendment 8).
    let pats = [
        "grep x *",
        "grep -e x src/a.rs",
        "grep -n x src/a.rs",
        "cat *",
        "ls *",
        "echo hi",
        "pwd",
        "git status",
    ];
    let n = setup_with(&ENABLED, json!(pats)).await;
    let c = delegate(&n, "SB-1", &pats).await;
    assert!(c.contains("status: accepted"), "{c}");
    let r = &n.repo_b;
    for cmd in [
        // The grep pattern `x` is not path-checked.
        "grep x src/a.rs",
        "grep -e x src/a.rs",
        "grep -n x src/a.rs",
        "cat src/a.rs",
        "ls src",
        "echo hi",
        "pwd",
        // No pathspec: names only.
        "git status",
    ] {
        assert!(allowed(&n.b, r, cmd).await, "{cmd}");
    }
    // The operand is still a path.
    for cmd in [
        "grep x src/.env",
        "cat src/.env",
        "grep x /etc/passwd",
        "cat ../x",
        "grep x ../x",
    ] {
        assert!(!allowed(&n.b, r, cmd).await, "{cmd}");
    }
}

#[tokio::test]
async fn recursive_options_missing_operands_and_odd_option_tokens_get_no_allow() {
    let n = setup(&ENABLED).await;
    let r = &n.repo_b;
    // (pattern, command): the contract may be refused outright or accepted; either way no allow.
    let cases = [
        ("grep -r x", "grep -r x"),
        ("grep -R x", "grep -R x"),
        ("grep -rn x", "grep -rn x"),
        ("grep --recursive x", "grep --recursive x"),
        ("grep -d recurse x", "grep -d recurse x"),
        ("grep x", "grep x"),
        ("diff -r a b", "diff -r a b"),
        ("ls -R src", "ls -R src"),
        ("cat", "cat"),
        ("head -n5", "head -n5"),
        ("grep --include=x y src/a.rs", "grep --include=x y src/a.rs"),
        ("head -c1 src/.env", "head -c1 src/.env"),
        // A trailing star cannot absorb flags, so these are refused whatever the pattern.
        ("grep x *", "grep -r x"),
        ("grep x *", "grep x"),
        ("cat *", "cat"),
        ("ls *", "ls -R src"),
    ];
    for (i, (pat, cmd)) in cases.iter().enumerate() {
        delegate(&n, &format!("SB-{}", i + 1), &[pat]).await;
        assert!(
            !allowed(&n.b, r, cmd).await,
            "pattern {pat:?}, command {cmd:?}"
        );
    }
    // Positive control: the same machinery allows a plain read.
    let c = delegate(&n, "SB-99", &["ls *", "cat *"]).await;
    assert!(c.contains("status: accepted"), "{c}");
    assert!(allowed(&n.b, r, "ls src").await);
    assert!(allowed(&n.b, r, "cat src/a.rs").await);
}
