//! Amendment 4 to the delegation spec: a shorter safe-program list, `git` and `cargo` only by
//! owner addition and then only with a subcommand allowlist, refused options, and no literal
//! option word before a trailing `*`.

mod common;

use common::*;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};
use wormhole::daemon::DaemonHandle;
use wormhole::delegation::{Policy, CARGO_SUBCOMMANDS, DEFAULT_SAFE_PROGRAMS, GIT_SUBCOMMANDS};
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

fn load(commands: Value, safe: &[&str]) -> Result<Policy, String> {
    Policy::parse(&json!({"grants": [grant(commands)], "safe_programs": safe}).to_string())
}

fn plain() -> Policy {
    Policy::parse(r#"{"grants": []}"#).unwrap()
}

fn owner() -> Policy {
    Policy::parse(r#"{"grants": [], "safe_programs": ["git", "cargo"]}"#).unwrap()
}

// ---- constants ----

#[test]
fn default_safe_programs_exclude_programs_with_exec_or_write_options() {
    let want = [
        "ls", "cat", "head", "tail", "wc", "grep", "diff", "stat", "pwd", "echo", "true", "false",
        "cut", "tr", "basename", "dirname", "realpath",
    ];
    assert_eq!(DEFAULT_SAFE_PROGRAMS.len(), want.len());
    let p = plain();
    for w in want {
        assert!(DEFAULT_SAFE_PROGRAMS.contains(&w), "{w}");
        assert!(p.safe_program(w), "{w}");
    }
    for gone in ["rg", "sort", "uniq", "git", "cargo", "rustfmt"] {
        assert!(!DEFAULT_SAFE_PROGRAMS.contains(&gone), "{gone}");
        assert!(!p.safe_program(gone), "{gone}");
    }
}

#[test]
fn subcommand_allowlists() {
    assert_eq!(GIT_SUBCOMMANDS, ["status", "log", "diff", "show"]);
    assert_eq!(CARGO_SUBCOMMANDS, ["test", "check", "build"]);
}

// ---- git and cargo only by owner addition ----

#[test]
fn git_and_cargo_are_refused_unless_the_owner_adds_them() {
    for pat in ["git status", "git status *", "cargo test", "cargo build"] {
        let e = load(json!([pat]), &[])
            .err()
            .unwrap_or_else(|| panic!("{pat}"));
        assert!(e.contains("not a safe program"), "{pat}: {e}");
    }
    assert!(plain()
        .command_allowed(&strs(&["git status"]), "git status")
        .is_err());
    assert!(plain()
        .command_allowed(&strs(&["cargo test"]), "cargo test")
        .is_err());
    // Adding one does not add the other.
    assert!(load(json!(["git status"]), &["git"]).is_ok());
    assert!(load(json!(["cargo test"]), &["git"]).is_err());
    assert!(load(json!(["cargo test"]), &["cargo"]).is_ok());
    // Once added they work, with allowed subcommands.
    let p = owner();
    assert!(p
        .command_allowed(&strs(&["git status"]), "git status")
        .is_ok());
    assert!(p
        .command_allowed(&strs(&["cargo test"]), "cargo test")
        .is_ok());
}

#[test]
fn only_allowed_subcommands_are_valid_even_when_added() {
    for good in [
        "git status",
        "git status *",
        "cargo test",
        "cargo check",
        "cargo build",
        "cargo test *",
    ] {
        assert!(load(json!([good]), &["git", "cargo"]).is_ok(), "{good}");
    }
    for bad in [
        "git difftool -x x",
        "git submodule foreach x",
        "git bisect run x",
        "git config a b",
        "git -C x status",
        "git push",
        "git push origin *",
        "git commit",
        "git",
        "cargo run",
        "cargo install x",
        "cargo fmt",
        "cargo publish",
        "cargo",
    ] {
        assert!(load(json!([bad]), &["git", "cargo"]).is_err(), "{bad}");
    }
    // The same on the command side: a valid pattern never lets another subcommand through.
    let p = owner();
    for cmd in [
        "git difftool -x x",
        "git submodule foreach x",
        "git bisect run x",
        "git config a b",
        "git -C x status",
        "git push",
        "git push origin main",
        "cargo run",
        "cargo install x",
    ] {
        assert!(
            p.command_allowed(&strs(&["git status *", "git status", "cargo test *"]), cmd)
                .is_err(),
            "{cmd}"
        );
    }
}

#[test]
fn refused_git_and_cargo_options_at_load_and_in_commands() {
    for bad in [
        "git diff --ext-diff",
        "git diff --textconv",
        "git log --output=x",
        "git log --git-dir=x",
        "git log --work-tree=x",
        "git log --config=x",
        "git log --exec-path=x",
        "git show --upload-pack=x",
        "git show --receive-pack=x",
        "git status -c x=y",
        "git status -Cx",
        "cargo test --config x",
        "cargo test --config-env=x",
        "cargo test --manifest-path x",
        "cargo build -Zx",
        "cargo check -Z unstable-options",
        "cargo +nightly test",
        "cargo -Zx test",
        "cargo test +nightly",
    ] {
        assert!(load(json!([bad]), &["git", "cargo"]).is_err(), "{bad}");
    }
    for bad in [
        "git status --ext-diff",
        "git status --output=x",
        "cargo test --manifest-path x",
    ] {
        let e = load(json!([bad]), &["git", "cargo"]).err().unwrap();
        assert!(e.contains("unsafe option"), "{bad}: {e}");
    }
    // In a command: even a literal pattern for a harmless form cannot be stretched to them.
    let p = owner();
    let pats = strs(&["git status *", "cargo test", "cargo test *", "git status"]);
    for cmd in [
        "git diff --ext-diff",
        "git diff --textconv",
        "git log --output=x",
        "git log x --output=x",
        "git status -c x=y",
        "cargo test --config x",
        "cargo +nightly test",
        "cargo -Zx test",
        "cargo test --manifest-path x",
        "cargo test x --manifest-path y",
    ] {
        assert!(p.command_allowed(&pats, cmd).is_err(), "{cmd}");
    }
    assert!(p.command_allowed(&pats, "git status").is_ok());
    assert!(p.command_allowed(&pats, "git status src").is_ok());
    assert!(p.command_allowed(&pats, "cargo test glob_tests").is_ok());
}

// ---- trailing star with a literal option word ----

#[test]
fn a_trailing_star_after_a_literal_option_is_refused() {
    for bad in [
        "cargo test --release *",
        "ls -la *",
        "git status -n *",
        "grep -r *",
        "cat -n *",
    ] {
        let e = load(json!([bad]), &["git", "cargo"])
            .err()
            .unwrap_or_else(|| panic!("{bad}"));
        assert!(e.contains("unsafe option"), "{bad}: {e}");
    }
    // Without the star an option word is an ordinary exact literal.
    for good in ["ls -la", "cargo test --release", "ls *", "cargo test *"] {
        assert!(load(json!([good]), &["git", "cargo"]).is_ok(), "{good}");
    }
    // At acceptance the boundary is refused.
    let p = load(json!(["*"]), &["git", "cargo"]).unwrap();
    let eval = |cmds: &[&str]| {
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
    };
    for bad in ["cargo test --release *", "ls -la *"] {
        assert!(!eval(&[bad]).accepted, "{bad}");
    }
    for good in ["cargo test *", "ls -la", "git status *"] {
        assert!(eval(&[good]).accepted, "{good}");
    }
    // The same through the command check.
    assert!(owner()
        .command_allowed(&strs(&["ls -la *"]), "ls -la src")
        .is_err());
}

// ---- rg and sort ----

#[test]
fn rg_and_sort_are_refused_by_default() {
    for pat in [
        "rg --pre x",
        "rg x",
        "sort --compress-program x",
        "sort a",
        "rustfmt x.rs",
    ] {
        let e = load(json!([pat]), &[])
            .err()
            .unwrap_or_else(|| panic!("{pat}"));
        assert!(e.contains("not a safe program"), "{pat}: {e}");
    }
    let p = plain();
    for cmd in ["rg --pre x", "sort --compress-program x", "rg x", "sort a"] {
        assert!(
            p.command_allowed(&strs(&["rg *", "sort *", "rg x", "sort a"]), cmd)
                .is_err(),
            "{cmd}"
        );
    }
    // A contract naming them is not accepted under a "*" grant.
    let g = load(json!(["*"]), &[]).unwrap();
    for cmd in ["rg x", "sort a", "rg --pre x"] {
        let d = g.evaluate(
            "alice",
            "machine-a",
            REPO,
            &Contract {
                task_id: "T-1".into(),
                kind: "fix".into(),
                paths: strs(&["src/a.rs"]),
                commands: strs(&[cmd]),
                exit: "done".into(),
                text: "do it".into(),
                ..Default::default()
            },
        );
        assert!(!d.accepted, "{cmd}");
    }
}

// ---- end to end ----

fn repo_id() -> String {
    let d = tmpdir();
    wormhole::repo::find(&make_repo(&d.join("r"))).unwrap().id
}

async fn setup(commands: Value, safe: Value) -> Net {
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

/// "allow", or None when the hook output carries no permission decision (the normal prompt).
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
async fn git_and_cargo_work_end_to_end_only_with_allowed_subcommands() {
    let cmds = json!(["git status", "git status *", "cargo test"]);
    let n = setup(cmds.clone(), json!(["git", "cargo"])).await;
    let c = delegate(&n, "SB-1", cmds).await;
    assert!(c.contains("status: accepted"), "{c}");
    let r = &n.repo_b;
    for cmd in ["git status", "git status src", "cargo test"] {
        assert_eq!(
            verdict(&n.b, r, cmd).await.as_deref(),
            Some("allow"),
            "{cmd}"
        );
    }
    for cmd in [
        "git diff --ext-diff",
        "git push origin main",
        "git push",
        "git -C x status",
        "git config a b",
        "git difftool -x x",
        "git submodule foreach x",
        "git bisect run x",
        "git log --output=x",
        "cargo +nightly test",
        "cargo -Zx test",
        "cargo test --manifest-path x",
        "cargo test --config x",
        "cargo run",
    ] {
        assert_eq!(verdict(&n.b, r, cmd).await, None, "{cmd}");
    }
}

#[tokio::test]
async fn without_safe_programs_a_git_contract_is_information_only() {
    let n = setup(json!(["*"]), json!([])).await;
    let c = delegate(&n, "SB-2", json!(["git status"])).await;
    assert!(c.contains("information only"), "{c}");
    assert_eq!(verdict(&n.b, &n.repo_b, "git status").await, None);
    let c = delegate(&n, "SB-3", json!(["rg --pre x"])).await;
    assert!(c.contains("information only"), "{c}");
    let c = delegate(&n, "SB-4", json!(["ls -la *"])).await;
    assert!(c.contains("information only"), "{c}");
    let c = delegate(&n, "SB-5", json!(["ls src"])).await;
    assert!(c.contains("status: accepted"), "{c}");
    assert_eq!(
        verdict(&n.b, &n.repo_b, "ls src").await.as_deref(),
        Some("allow")
    );
}
