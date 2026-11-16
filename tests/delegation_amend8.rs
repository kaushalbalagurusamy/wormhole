//! Amendment 8 to the delegation spec: blank and doubled path keys, options through a `*`
//! grant, `=` words, lookalike paths, git with the module off, background runs, audit order
//! and more default deny paths.

mod common;

use common::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use wormhole::daemon::DaemonHandle;
use wormhole::delegation::{self, Policy, DEFAULT_DENY_PATHS};

const SA: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const SB: &str = "bbbbbbbb-0000-4000-8000-000000000002";
const NOTICE: &str = "[wormhole delegation] request";
const SAFE: [&str; 8] = ["cat", "grep", "ls", "diff", "echo", "head", "stat", "git"];

fn repo_id() -> String {
    let d = tmpdir();
    wormhole::repo::find(&make_repo(&d.join("r"))).unwrap().id
}

fn grant(task: &str, level: &str, commands: Value) -> Value {
    let mut g = json!({"from": ["alice@machine-a"], "repos": [repo_id()], "task_ids": [task],
        "level": level, "paths": ["src/**"], "kinds": ["fix", "any"]});
    if level != "full-bypass" {
        g["commands"] = commands;
    }
    g
}

struct T {
    n: Net,
    policy: PathBuf,
}

/// `cwd_in_src`: the session works from `<repo>/src` instead of the repository root.
async fn setup(grants: Vec<Value>, denylist_off: bool, protected: &[&str], cwd_in_src: bool) -> T {
    let policy = tmpdir().join("policy.json");
    let mut p = json!({"grants": grants, "safe_programs": SAFE});
    if denylist_off {
        p["denylist"] = json!({"enabled": false});
    }
    std::fs::write(&policy, p.to_string()).unwrap();
    let n = net(Opts {
        policy_b: Some(policy.clone()),
        protected: protected.iter().map(|s| s.to_string()).collect(),
        ..Opts::default()
    })
    .await;
    std::fs::create_dir_all(n.repo_b.join("src")).unwrap();
    std::fs::write(n.repo_b.join("src/a.rs"), "x").unwrap();
    hook(&n.a, session_start(SA, &n.repo_a)).await;
    let cwd = if cwd_in_src {
        n.repo_b.join("src")
    } else {
        n.repo_b.clone()
    };
    hook(&n.b, session_start(SB, &cwd)).await;
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

async fn allowed(d: &DaemonHandle, input: Value) -> bool {
    decision(&hook(d, input).await).as_deref() == Some("allow")
}

/// Delegate and return B's notice (accepted or not).
async fn delegate(n: &Net, task: &str, commands: &[&str], extra: Value) -> String {
    let mut a = json!({"to_session": SB, "to": SB, "task_id": task, "kind": "fix", "text": "do it",
               "exit": "done", "commands": commands});
    if !extra.as_object().unwrap().contains_key("paths") {
        a["paths"] = json!(["src/**"]);
    }
    for (k, v) in extra.as_object().unwrap() {
        a[k] = v.clone();
    }
    tool(&n.a, SA, "delegate", a).await.unwrap();
    next_ctx(&n.b, SB, &n.repo_b, |c| {
        c.contains(NOTICE) && c.contains(task)
    })
    .await
}

// ---- F1 ----

#[tokio::test]
async fn f1_blank_and_oversized_read_paths_get_no_allow_from_a_subdirectory() {
    let t = setup(
        vec![grant("FB-*", "full-bypass", json!([]))],
        false,
        &[],
        true,
    )
    .await;
    let src = t.n.repo_b.join("src");
    assert!(src.is_dir());
    let c = delegate(&t.n, "FB-1", &[], json!({"paths": []})).await;
    assert!(c.contains("status: accepted"), "{c}");
    // Positive control from the same cwd.
    let read = |p: Value| pre_tool(&src, "Read", json!({ "file_path": p }));
    assert!(allowed(&t.n.b, read(json!(src.join("a.rs")))).await);
    // Over 4 KiB the body reducer blanks the string; an empty path is refused as well.
    let long = format!("{}a.rs", "./".repeat(2100));
    assert!(!allowed(&t.n.b, read(json!(long))).await);
    assert!(!allowed(&t.n.b, read(json!(""))).await);
    // The same for an edit tool.
    assert!(
        !allowed(
            &t.n.b,
            pre_tool(&src, "Write", json!({"file_path": "", "content": "x"}))
        )
        .await
    );
}

// ---- F2 ----

#[tokio::test]
async fn f2_options_are_allowed_only_in_patterns_the_owner_wrote() {
    let star = setup(
        vec![grant("SB-*", "scoped-bypass", json!(["*"]))],
        false,
        &[],
        false,
    )
    .await;
    for (i, pat) in ["grep -n x *", "diff -q a b", "grep -n x src/a.rs"]
        .iter()
        .enumerate()
    {
        let c = delegate(&star.n, &format!("SB-{}", i + 1), &[pat], json!({})).await;
        assert!(c.contains("status: informed"), "{pat}: {c}");
    }
    // Positive control: an option-free pattern under the same grant.
    let c = delegate(&star.n, "SB-9", &["grep x *"], json!({})).await;
    assert!(c.contains("status: accepted"), "{c}");
    assert!(allowed(&star.n.b, pre_bash(&star.n.repo_b, "grep x src/a.rs")).await);

    // The same patterns listed verbatim in the grant are accepted.
    let verbatim = json!(["diff -q a b", "grep -n x src/a.rs"]);
    let t = setup(
        vec![grant("SB-*", "scoped-bypass", verbatim)],
        false,
        &[],
        false,
    )
    .await;
    for (i, pat) in ["diff -q a b", "grep -n x src/a.rs"].iter().enumerate() {
        let c = delegate(&t.n, &format!("SB-{}", i + 1), &[pat], json!({})).await;
        assert!(c.contains("status: accepted"), "{pat}: {c}");
    }
    assert!(allowed(&t.n.b, pre_bash(&t.n.repo_b, "grep -n x src/a.rs")).await);
}

// ---- F3 ----

#[test]
fn f3_a_pattern_containing_an_equals_sign_is_invalid_at_load() {
    let load = |pat: &str| {
        Policy::parse(
            &json!({"grants": [grant("*", "scoped-bypass", json!([pat]))], "safe_programs": SAFE})
                .to_string(),
        )
    };
    for bad in ["echo a=b", "cat =ls", "cat src/a=b.rs", "echo x=*"] {
        assert!(load(bad).is_err(), "{bad}");
    }
    assert!(load("echo ab").is_ok());
    assert!(load("cat *").is_ok());
}

#[tokio::test]
async fn f3_a_command_with_an_equals_sign_gets_no_allow() {
    let t = setup(
        vec![grant("SB-*", "scoped-bypass", json!(["cat *", "echo *"]))],
        false,
        &[],
        false,
    )
    .await;
    let c = delegate(&t.n, "SB-1", &["cat *", "echo *"], json!({})).await;
    assert!(c.contains("status: accepted"), "{c}");
    let (b, r) = (&t.n.b, &t.n.repo_b);
    assert!(allowed(b, pre_bash(r, "cat src/a.rs")).await);
    assert!(allowed(b, pre_bash(r, "echo hi")).await);
    for cmd in ["cat =ls", "cat src/a=b.rs", "echo a=b", "echo =ls"] {
        assert!(!allowed(b, pre_bash(r, cmd)).await, "{cmd}");
    }
}

// ---- F4 ----

#[tokio::test]
async fn f4_a_lookalike_path_with_an_invisible_character_gets_no_allow() {
    let t = setup(
        vec![grant("SB-*", "scoped-bypass", json!([]))],
        false,
        &[],
        false,
    )
    .await;
    let c = delegate(&t.n, "SB-1", &[], json!({})).await;
    assert!(c.contains("status: accepted"), "{c}");
    let (b, r) = (&t.n.b, &t.n.repo_b);
    let w = |f: &str| pre_tool(r, "Write", json!({"file_path": f, "content": "x"}));
    assert!(allowed(b, w("src/ok.rs")).await);
    for f in [
        "s\u{200b}rc/evil.rs",
        "src/ev\u{200b}il.rs",
        "src/e\u{7}vil.rs",
        "src/ev\u{202e}il.rs",
    ] {
        assert!(!allowed(b, w(f)).await, "{f:?}");
    }
    assert!(
        !allowed(
            b,
            pre_tool(
                r,
                "Edit",
                json!({"file_path": "s\u{200b}rc/evil.rs",
        "old_string": "a", "new_string": "b"})
            )
        )
        .await
    );
}

// ---- F5 ----

#[tokio::test]
async fn f5_git_log_needs_the_denylist_off_and_no_protected_globs() {
    // Protected globs on the daemon: the policy cannot know them, so any refusal may come at load,
    // acceptance or per call. Either way git log gets no allow.
    let t = setup(
        vec![grant(
            "SB-*",
            "scoped-bypass",
            json!(["git status", "git log"]),
        )],
        true,
        &["secrets/**"],
        false,
    )
    .await;
    // Control: status works with the module off and protected globs.
    let c = delegate(&t.n, "SB-1", &["git status"], json!({})).await;
    assert!(c.contains("status: accepted"), "{c}");
    assert!(allowed(&t.n.b, pre_bash(&t.n.repo_b, "git status")).await);
    delegate(&t.n, "SB-2", &["git log"], json!({})).await;
    assert!(!allowed(&t.n.b, pre_bash(&t.n.repo_b, "git log")).await);

    // No protected globs, module off: git log is allowed.
    let t = setup(
        vec![grant(
            "SB-*",
            "scoped-bypass",
            json!(["git status", "git log"]),
        )],
        true,
        &[],
        false,
    )
    .await;
    let c = delegate(&t.n, "SB-1", &["git log"], json!({})).await;
    assert!(c.contains("status: accepted"), "{c}");
    assert!(allowed(&t.n.b, pre_bash(&t.n.repo_b, "git log")).await);
}

// ---- F6 ----

#[tokio::test]
async fn f6_a_background_bash_run_gets_no_allow() {
    let t = setup(
        vec![grant("SB-*", "scoped-bypass", json!(["ls *"]))],
        false,
        &[],
        false,
    )
    .await;
    let c = delegate(&t.n, "SB-1", &["ls *"], json!({})).await;
    assert!(c.contains("status: accepted"), "{c}");
    let (b, r) = (&t.n.b, &t.n.repo_b);
    let bash = |extra: Value| {
        let mut i = json!({"command": "ls src"});
        i.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        pre_tool(r, "Bash", i)
    };
    assert!(allowed(b, bash(json!({}))).await);
    assert!(allowed(b, bash(json!({"run_in_background": false}))).await);
    assert!(!allowed(b, bash(json!({"run_in_background": true}))).await);
}

// ---- F7 ----

#[tokio::test]
async fn f7_an_accepted_request_has_its_audit_line() {
    let t = setup(
        vec![grant("SB-*", "scoped-bypass", json!(["ls *"]))],
        false,
        &[],
        false,
    )
    .await;
    let c = delegate(&t.n, "SB-1", &["ls *"], json!({})).await;
    assert!(c.contains("status: accepted"), "{c}");
    let lines: Vec<Value> = std::fs::read_to_string(delegation::audit_path(&t.policy))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(
        lines
            .iter()
            .any(|l| l["event"] == "request" && l["accepted"] == true),
        "{lines:?}"
    );
}

// ---- deny paths ----

#[test]
fn new_default_deny_paths() {
    let p = Policy::parse(r#"{"grants": []}"#).unwrap();
    for g in [
        "**/.cargo/**",
        "**/rust-toolchain",
        "**/rust-toolchain.toml",
        "**/.pgpass",
        "**/.docker/config.json",
        "**/.gnupg/**",
    ] {
        assert!(DEFAULT_DENY_PATHS.contains(&g), "{g}");
    }
    for path in [
        ".cargo/config.toml",
        "a/.cargo/config.toml",
        "rust-toolchain.toml",
        "a/rust-toolchain",
        "x/rust-toolchain.toml",
        ".pgpass",
        "h/.pgpass",
        ".docker/config.json",
        "a/.docker/config.json",
        ".gnupg/x",
        "h/.gnupg/private-keys-v1.d/k",
    ] {
        assert!(p.denied_path(path).is_some(), "{path}");
    }
    for path in [
        "src/main.rs",
        "Cargo.toml",
        "docker/config.json",
        "src/.docker/other.json",
        "cargo/config.toml",
    ] {
        assert_eq!(p.denied_path(path), None, "{path}");
    }
}
