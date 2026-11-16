//! Amendment 2 to the delegation spec: exact argv command patterns (a trailing `*` matches
//! plain positional arguments), every Bash allow rechecked, and a pinned tool list with path
//! checks under full-bypass.

mod common;

use common::*;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};
use wormhole::daemon::DaemonHandle;
use wormhole::delegation::Policy;
use wormhole::proto::Contract;

const REPO: &str = "example.com/team/proj";
const SA: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const SB: &str = "bbbbbbbb-0000-4000-8000-000000000002";
const NOTICE: &str = "[wormhole delegation] request";

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn ok(patterns: &[&str], cmd: &str) -> bool {
    Policy::parse(r#"{"grants": []}"#)
        .unwrap()
        .command_allowed(&strs(patterns), cmd)
        .is_ok()
}

#[test]
fn a_pattern_without_a_star_matches_exactly() {
    assert!(ok(&["cargo test"], "cargo test"));
    assert!(ok(&["cargo test"], "cargo   test"));
    for bad in [
        "cargo test --lib",
        "cargo test x",
        "cargo testx",
        "cargo",
        "",
        "cargo build",
    ] {
        assert!(!ok(&["cargo test"], bad), "{bad:?}");
    }
    // Any listed pattern may match.
    assert!(ok(&["cargo test", "cargo fmt"], "cargo fmt"));
    assert!(!ok(&[], "cargo test"));
}

#[test]
fn a_trailing_star_matches_plain_positional_arguments_only() {
    let p = ["cargo test *"];
    assert!(ok(&p, "cargo test glob_tests"));
    assert!(ok(&p, "cargo test a b c"));
    for bad in [
        "cargo test",
        "cargo test --release x",
        "cargo test x --lib",
        "cargo test -q",
        "cargo test 'a b'",
        "cargo test \"a\"",
        "cargo test a*",
        "cargo test a?",
        "cargo test [a]",
        "cargo test *",
        "cargo build x",
        "cargo testx y",
    ] {
        assert!(!ok(&p, bad), "{bad:?}");
    }
    // The star is only a wildcard in last position.
    assert!(!ok(&["cargo * test"], "cargo x test"));
    assert!(!ok(&["cargo * test"], "cargo * test"));
}

#[test]
fn quotes_backslashes_and_glob_characters_are_refused_in_the_command() {
    for bad in [
        "echo 'hi'",
        "echo \"hi\"",
        r"echo h\i",
        "echo hi*",
        "echo hi?",
        "echo [hi]",
        "ec'ho' hi",
        "echo hi\\",
    ] {
        assert!(!ok(&["echo hi", "echo *"], bad), "{bad:?}");
    }
    assert!(ok(&["echo hi"], "echo hi"));
}

#[test]
fn a_command_cannot_smuggle_a_second_command_through_a_pattern() {
    for p in [&["git status *"][..], &["git status"]] {
        for bad in [
            "git status; rm -rf x",
            "git status x; rm -rf x",
            "git status && ls",
            "git status | cat",
            "git status $(id)",
            "git status `id`",
            "git status > f",
            "git status\nrm x",
        ] {
            assert!(!ok(p, bad), "{p:?}: {bad:?}");
        }
    }
    assert!(ok(&["git status *"], "git status src"));
    assert!(ok(&["git status"], "git status"));
}

#[test]
fn wrappers_and_env_prefixes_never_match_even_as_the_pattern() {
    assert!(!ok(&["sh -c"], "sh -c"));
    assert!(!ok(&["sh *"], "sh x"));
    assert!(!ok(&["/bin/bash *"], "/bin/bash x"));
    assert!(!ok(&["env *"], "env x"));
    assert!(!ok(&["FOO=1 ls"], "FOO=1 ls"));
    assert!(!ok(&["ls"], "FOO=1 ls"));
    // Not a safe program unless the owner adds it (see amendment 3).
    assert!(!ok(&["shellcheck x.sh"], "shellcheck x.sh"));
}

// ---- acceptance ----

fn grant(commands: Value) -> Value {
    json!({"from": ["alice@machine-a"], "repos": [REPO], "level": "scoped-bypass",
           "paths": ["src/**"], "kinds": ["fix"], "commands": commands})
}

fn policy(g: Value) -> Policy {
    Policy::parse(&json!({"grants": [g]}).to_string()).unwrap()
}

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

fn accepted(p: &Policy, cmds: &[&str]) -> bool {
    p.evaluate("alice", "machine-a", REPO, &contract(cmds))
        .accepted
}

#[test]
fn contract_patterns_must_equal_a_grant_pattern_token_for_token() {
    let p = policy(grant(json!(["cargo test", "cargo check *"])));
    assert!(accepted(&p, &["cargo test"]));
    assert!(accepted(&p, &["cargo check *"]));
    assert!(accepted(&p, &["cargo   test", "cargo check *"]));
    assert!(accepted(&p, &[]));
    for bad in [
        "cargo test --lib",
        "cargo test *",
        "cargo check x",
        "cargo check",
        "cargo",
        "cargo build",
        "sh -c ls",
        "cargo test; ls",
    ] {
        assert!(!accepted(&p, &[bad]), "{bad}");
    }
    // The grant value "*" alone accepts any valid pattern.
    let p = policy(grant(json!(["*"])));
    assert!(accepted(&p, &["cargo test --lib"]));
    assert!(accepted(&p, &["cargo test *"]));
    for bad in [
        "sh -c ls",
        "bash",
        "FOO=1 make",
        "make; id",
        "env x",
        "python3 x.py",
    ] {
        assert!(!accepted(&p, &[bad]), "{bad}");
    }
}

#[test]
fn a_destructive_pattern_is_checked_again_at_runtime_by_argv() {
    // The pattern itself matches...
    assert!(ok(&["git push -f"], "git push -f"));
    assert!(ok(&["git push origin +main"], "git push origin +main"));
    // ...but the argv check refuses it (denylist on).
    let p = policy(grant(json!(["*"])));
    assert!(p.denied_argv("git push -f").is_some());
    assert!(p.denied_argv("git push origin +main").is_some());
    // The text screen refuses the first pattern at acceptance as well.
    assert!(!accepted(&p, &["git push -f"]));
    // With the module off neither check applies.
    let off = Policy::parse(
        &json!({"grants": [grant(json!(["*"]))], "denylist": {"enabled": false}}).to_string(),
    )
    .unwrap();
    assert_eq!(off.denied_argv("git push -f"), None);
    assert!(accepted(&off, &["git push -f"]));
}

// ---- end to end ----

fn repo_id() -> String {
    let d = tmpdir();
    wormhole::repo::find(&make_repo(&d.join("r"))).unwrap().id
}

async fn setup(grants: Vec<Value>, denylist: Option<Value>, protected: &[&str]) -> Net {
    let path = tmpdir().join("policy.json");
    let mut p = json!({"grants": grants});
    if let Some(d) = denylist {
        p["denylist"] = d;
    }
    std::fs::write(&path, p.to_string()).unwrap();
    let n = net(Opts {
        policy_b: Some(path),
        protected: strs(protected),
        ..Opts::default()
    })
    .await;
    hook(&n.a, session_start(SA, &n.repo_a)).await;
    hook(&n.b, session_start(SB, &n.repo_b)).await;
    n
}

fn bypass_grant(task: &str, commands: Value) -> Value {
    json!({"from": ["alice@machine-a"], "repos": [repo_id()], "task_ids": [task],
           "level": "scoped-bypass", "paths": ["src/**"], "kinds": ["fix"], "commands": commands})
}

fn full_grant() -> Value {
    json!({"from": ["alice@machine-a"], "repos": [repo_id()], "task_ids": ["FB-*"],
           "level": "full-bypass"})
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

fn pre_tool(cwd: &Path, tool: &str, input: Value) -> Value {
    let mut v = base("PreToolUse", SB, cwd);
    v["tool_name"] = json!(tool);
    v["tool_input"] = input;
    v["tool_use_id"] = json!("toolu_9");
    v
}

fn pre_bash(cwd: &Path, cmd: &str) -> Value {
    pre_tool(cwd, "Bash", json!({"command": cmd}))
}

fn pre_read(cwd: &Path, path: impl AsRef<Path>) -> Value {
    pre_tool(cwd, "Read", json!({"file_path": path.as_ref()}))
}

async fn allowed(d: &DaemonHandle, input: Value) -> bool {
    decision(&hook(d, input).await).as_deref() == Some("allow")
}

async fn delegate(n: &Net, task: &str, kind: &str, extra: Value) {
    let mut a = json!({"to_session": SB, "to": SB, "task_id": task, "kind": kind, "text": "do it"});
    for (k, v) in extra.as_object().unwrap() {
        a[k] = v.clone();
    }
    tool(&n.a, SA, "delegate", a).await.unwrap();
    let c = next_ctx(&n.b, SB, &n.repo_b, |c| {
        c.contains(NOTICE) && c.contains(task)
    })
    .await;
    assert!(c.contains("status: accepted"), "{c}");
}

#[tokio::test]
async fn scoped_bypass_commands_are_exact_patterns_and_argv_is_rechecked() {
    let cmds = json!(["cargo test", "cargo test *", "git push origin +main"]);
    let n = setup(vec![bypass_grant("SB-*", cmds.clone())], None, &[]).await;
    delegate(
        &n,
        "SB-1",
        "fix",
        json!({"paths": ["src/**"], "exit": "done", "commands": cmds}),
    )
    .await;
    for cmd in ["cargo test", "cargo test glob_tests"] {
        assert!(allowed(&n.b, pre_bash(&n.repo_b, cmd)).await, "{cmd}");
    }
    for cmd in [
        "cargo test --lib",
        "cargo test --release x",
        "cargo test 'a b'",
        "cargo test; rm -rf x",
        "cargo test x; id",
        "cargo build",
        // The pattern matches exactly, but the argv check refuses the refspec.
        "git push origin +main",
    ] {
        assert!(!allowed(&n.b, pre_bash(&n.repo_b, cmd)).await, "{cmd:?}");
    }
    // scoped-bypass never allows Read or other tools.
    assert!(!allowed(&n.b, pre_read(&n.repo_b, n.repo_b.join("src/a.rs"))).await);
    assert!(
        !allowed(
            &n.b,
            pre_tool(&n.repo_b, "WebFetch", json!({"url": "https://example.com"}))
        )
        .await
    );
}

#[tokio::test]
async fn contract_pattern_not_equal_to_the_grant_is_information_only() {
    let n = setup(vec![bypass_grant("SB-*", json!(["cargo test"]))], None, &[]).await;
    tool(
        &n.a,
        SA,
        "delegate",
        json!({"to_session": SB, "to": SB, "task_id": "SB-2", "kind": "fix", "text": "x",
               "paths": ["src/**"], "exit": "done", "commands": ["cargo test --lib"]}),
    )
    .await
    .unwrap();
    let c = next_ctx(&n.b, SB, &n.repo_b, |c| {
        c.contains(NOTICE) && c.contains("SB-2")
    })
    .await;
    assert!(c.contains("information only"), "{c}");
    assert!(!allowed(&n.b, pre_bash(&n.repo_b, "cargo test --lib")).await);
}

#[tokio::test]
async fn full_bypass_answers_only_the_pinned_tools_inside_the_repository() {
    let n = setup(vec![full_grant()], None, &["prot/**"]).await;
    delegate(&n, "FB-1", "any", json!({"exit": "done"})).await;
    let r = &n.repo_b;

    // The pinned list.
    assert!(allowed(&n.b, pre_bash(r, "ls -la")).await);
    assert!(allowed(&n.b, pre_edit(SB, r, "src/a.rs")).await);
    assert!(allowed(&n.b, pre_read(r, r.join("src/a.rs"))).await);
    // Other tools prompt, MCP tools included.
    assert!(
        !allowed(
            &n.b,
            pre_tool(r, "WebFetch", json!({"url": "https://example.com"}))
        )
        .await
    );
    assert!(!allowed(&n.b, pre_tool(r, "mcp__x__y", json!({"a": 1}))).await);
    assert!(!allowed(&n.b, pre_tool(r, "WebSearch", json!({"query": "x"}))).await);

    // Paths: protected, denied and outside the repository all prompt.
    assert!(!allowed(&n.b, pre_read(r, r.join("prot/x.txt"))).await);
    assert!(!allowed(&n.b, pre_read(r, r.join("src/.env"))).await);
    assert!(!allowed(&n.b, pre_read(r, "/etc/hosts")).await);
    assert!(!allowed(&n.b, pre_edit(SB, r, "prot/x.txt")).await);
    assert!(!allowed(&n.b, pre_edit(SB, r, "src/.env")).await);
    let outside = tmpdir().join("outside.txt");
    assert!(!allowed(&n.b, pre_read(r, &outside)).await);
    let mut w = pre_tool(r, "Write", json!({"file_path": outside, "content": "x"}));
    w["tool_use_id"] = json!("toolu_10");
    assert!(!allowed(&n.b, w).await);

    // Bash with the denylist on: tokenised, no wrapper, no env prefix, no deny hit.
    for cmd in [
        "sh -c 'x'",
        "bash -c x",
        "FOO=1 ls",
        "env ls",
        "ls; id",
        "ls $(id)",
        "git push -f",
        "rm -rf x",
    ] {
        assert!(!allowed(&n.b, pre_bash(r, cmd)).await, "{cmd:?}");
    }
}

#[tokio::test]
async fn full_bypass_with_the_denylist_off_allows_wrappers_but_not_protected_paths_or_other_tools()
{
    let n = setup(
        vec![full_grant()],
        Some(json!({"enabled": false})),
        &["prot/**"],
    )
    .await;
    delegate(&n, "FB-1", "any", json!({"exit": "done"})).await;
    let r = &n.repo_b;
    assert!(allowed(&n.b, pre_bash(r, "sh -c 'x'")).await);
    assert!(allowed(&n.b, pre_bash(r, "git push -f")).await);
    assert!(allowed(&n.b, pre_edit(SB, r, "src/a.rs")).await);
    // Protected paths, paths outside the repository and other tools still prompt.
    assert!(!allowed(&n.b, pre_read(r, r.join("prot/x.txt"))).await);
    assert!(!allowed(&n.b, pre_edit(SB, r, "prot/x.txt")).await);
    assert!(!allowed(&n.b, pre_read(r, "/etc/hosts")).await);
    assert!(
        !allowed(
            &n.b,
            pre_tool(r, "WebFetch", json!({"url": "https://example.com"}))
        )
        .await
    );
    assert!(!allowed(&n.b, pre_tool(r, "mcp__x__y", json!({}))).await);
}
