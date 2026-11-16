//! Amendment 5 to the delegation spec: Bash operands are paths, git and cargo option
//! allowlists, a fail-closed audit log, repository and symlink checks, tool input keys,
//! policy narrowing and the extra default deny paths.

mod common;

use common::*;
use serde_json::{json, Value};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use wormhole::daemon::DaemonHandle;
use wormhole::delegation::{
    self, Policy, CARGO_OPTIONS, DEFAULT_DENY_PATHS, DEFAULT_SAFE_PROGRAMS, GIT_OPTIONS,
};
use wormhole::proto::Contract;

const REPO: &str = "example.com/team/proj";
const SA: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const SB: &str = "bbbbbbbb-0000-4000-8000-000000000002";
const NOTICE: &str = "[wormhole delegation] request";

// Programs enabled by the owner besides git and cargo (none are safe by default).
const EXTRA: [&str; 17] = [
    "ls", "cat", "head", "tail", "wc", "grep", "diff", "stat", "pwd", "echo", "true", "false",
    "cut", "tr", "basename", "dirname", "realpath",
];

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn grant(commands: Value) -> Value {
    json!({"from": ["alice@machine-a"], "repos": [REPO], "level": "scoped-bypass",
           "paths": ["src/**"], "kinds": ["fix"], "commands": commands})
}

fn load(commands: Value, safe: &[&str]) -> Result<Policy, String> {
    let mut all: Vec<&str> = safe.to_vec();
    all.extend(EXTRA);
    Policy::parse(&json!({"grants": [grant(commands)], "safe_programs": all}).to_string())
}

fn owner() -> Policy {
    Policy::parse(r#"{"grants": [], "safe_programs": ["git", "cargo", "ls", "cat", "head", "tail", "wc", "grep", "diff", "stat", "pwd", "echo", "true", "false", "cut", "tr", "basename", "dirname", "realpath"]}"#).unwrap()
}

// ---- pure ----

#[test]
fn uniq_is_not_a_default_safe_program() {
    assert!(!DEFAULT_SAFE_PROGRAMS.contains(&"uniq"));
    assert!(!Policy::parse(r#"{"grants": []}"#)
        .unwrap()
        .safe_program("uniq"));
    let e = load(json!(["uniq a"]), &[]).err().unwrap();
    assert!(e.contains("not a safe program"), "{e}");
}

#[test]
fn option_allowlists_are_pinned() {
    assert_eq!(
        GIT_OPTIONS,
        [
            "--oneline",
            "--stat",
            "--name-only",
            "--name-status",
            "--short",
            "--porcelain",
            "--cached",
            "--staged",
            "--no-color"
        ]
    );
    assert_eq!(
        CARGO_OPTIONS,
        [
            "--lib",
            "--bins",
            "--tests",
            "--doc",
            "--all-targets",
            "--workspace",
            "--release",
            "--locked",
            "--offline",
            "--quiet",
            "-q",
            "--no-fail-fast"
        ]
    );
}

#[test]
fn git_and_cargo_accept_only_allowlisted_options() {
    let safe = ["git", "cargo"];
    for good in [
        "git status --short",
        "git status --short --porcelain",
        "git status --short --porcelain",
        "git status --porcelain",
        "git status --short *",
        "cargo test --lib",
        "cargo test --release --locked",
        "cargo build -q",
        "cargo check --workspace --all-targets --offline",
        "cargo test --lib *",
    ] {
        // A trailing star after a literal option word is refused by amendment 4.
        let star_after_option = good.ends_with('*') && good.contains(" --");
        assert_eq!(
            load(json!([good]), &safe).is_ok(),
            !star_after_option,
            "{good}"
        );
    }
    for bad in [
        "git reset --ha",
        "git status --ha",
        "git --attr-source HEAD status",
        "git status --",
        "git status --short=x",
        "git status --pretty=format:x",
        "git status --no-index",
        "cargo test --frozen",
        "cargo test --",
        "cargo test --lib=x",
        "cargo test --features x",
        "git *",
        "cargo *",
    ] {
        assert!(load(json!([bad]), &safe).is_err(), "{bad}");
    }
    // The same in a command.
    let p = owner();
    let pats = strs(&[
        "git status --short",
        "git status *",
        "cargo test --lib",
        "cargo test *",
    ]);
    for ok in [
        "git status --short",
        "git status src",
        "cargo test --lib",
        "cargo test x",
    ] {
        assert!(p.command_allowed(&pats, ok).is_ok(), "{ok}");
    }
    for bad in [
        "git reset --ha",
        "git --attr-source HEAD status",
        "git status --",
        "git status --ha",
        "git status --short --ha",
        "cargo test --frozen",
        "cargo test --lib --frozen",
    ] {
        assert!(p.command_allowed(&pats, bad).is_err(), "{bad}");
    }
}

#[test]
fn star_patterns_are_accepted_with_the_denylist_on() {
    let p = load(json!(["*"]), &["cargo"]).unwrap();
    for cmds in [&["ls *"][..], &["cargo test *"], &["ls *", "cargo test *"]] {
        let d = p.evaluate(
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
        );
        assert!(d.accepted, "{cmds:?}: {}", d.reason);
    }
}

#[test]
fn new_default_deny_paths() {
    let p = Policy::parse(r#"{"grants": []}"#).unwrap();
    for g in [
        "**/.aws/**",
        "**/.kube/**",
        "**/.npmrc",
        "**/.netrc",
        "**/.git-credentials",
        "**/.envrc",
        "**/*.p12",
        "**/*.pfx",
    ] {
        assert!(DEFAULT_DENY_PATHS.contains(&g), "{g}");
    }
    for path in [
        ".aws/credentials",
        "src/.aws/x",
        "a/.kube/config",
        ".npmrc",
        "a/.npmrc",
        ".netrc",
        "x/.git-credentials",
        "a/.envrc",
        "k.p12",
        "a/b/c.pfx",
        "A/.AWS/X",
    ] {
        assert!(p.denied_path(path).is_some(), "{path}");
    }
    assert_eq!(p.denied_path("src/awsome.rs"), None);
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

async fn setup_with(commands: Value, protected: &[&str], prep: impl Fn(&Path)) -> T {
    let policy = tmpdir().join("policy.json");
    prep(&delegation::audit_path(&policy));
    let g = json!({"from": ["alice@machine-a"], "repos": [repo_id()], "task_ids": ["SB-*"],
        "level": "scoped-bypass", "paths": ["src/**"], "kinds": ["fix"], "commands": commands});
    std::fs::write(
        &policy,
        json!({"grants": [g], "safe_programs": ["git", "cargo", "ls", "cat", "head", "tail", "wc", "grep", "diff", "stat", "pwd", "echo", "true", "false", "cut", "tr", "basename", "dirname", "realpath"]}).to_string(),
    )
    .unwrap();
    let n = net(Opts {
        policy_b: Some(policy.clone()),
        protected: strs(protected),
        ..Opts::default()
    })
    .await;
    std::fs::create_dir_all(n.repo_b.join("src")).unwrap();
    std::fs::write(n.repo_b.join("src/a.rs"), "x").unwrap();
    hook(&n.a, session_start(SA, &n.repo_a)).await;
    hook(&n.b, session_start(SB, &n.repo_b)).await;
    T { n, policy }
}

async fn setup(commands: Value, protected: &[&str]) -> T {
    setup_with(commands, protected, |_| {}).await
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

async fn accepted(t: &T, task: &str, commands: Value) {
    let c = delegate(&t.n, task, commands).await;
    assert!(c.contains("status: accepted"), "{c}");
}

#[tokio::test]
async fn bash_operands_are_paths_inside_the_repository() {
    let t = setup(json!(["cat *", "grep *", "ls *"]), &["prot/**"]).await;
    let n = &t.n;
    std::fs::create_dir_all(n.repo_b.join("prot")).unwrap();
    std::fs::write(n.repo_b.join("prot/x"), "x").unwrap();
    accepted(&t, "SB-1", json!(["cat *", "grep *", "ls *"])).await;
    let r = &n.repo_b;
    for cmd in ["cat src/a.rs", "grep x src/a.rs", "ls src", "ls"] {
        // `ls` alone has no operand but does not match `ls *`.
        let want = cmd != "ls";
        assert_eq!(allowed(&n.b, pre_bash(r, cmd)).await, want, "{cmd}");
    }
    for cmd in [
        "cat ./.env",
        "cat .env",
        "cat src/../.env",
        "cat /etc/passwd",
        "cat ../x",
        "cat prot/x",
        "cat src/.aws/x",
        "cat --x=y",
        "cat src/a.rs /etc/passwd",
        "grep x /abs",
        "grep x ../y",
        "ls ~",
    ] {
        assert!(!allowed(&n.b, pre_bash(r, cmd)).await, "{cmd}");
    }
}

#[tokio::test]
async fn git_and_cargo_option_allowlists_end_to_end() {
    let cmds = json!([
        "git status --short",
        "git status *",
        "cargo test --lib",
        "cargo test *"
    ]);
    // Option-bearing patterns are listed verbatim in the grant (amendment 8).
    let t = setup(cmds.clone(), &[]).await;
    accepted(&t, "SB-1", cmds).await;
    let (n, r) = (&t.n, &t.n.repo_b);
    for cmd in [
        "git status --short",
        "cargo test --lib",
        "git status src",
        "cargo test x",
    ] {
        assert!(allowed(&n.b, pre_bash(r, cmd)).await, "{cmd}");
    }
    for cmd in [
        "git reset --ha",
        "git --attr-source HEAD status",
        "git status --",
        "git status --ha",
        "cargo test --frozen",
        "cargo test --lib --frozen",
    ] {
        assert!(!allowed(&n.b, pre_bash(r, cmd)).await, "{cmd}");
    }
}

#[tokio::test]
async fn star_patterns_with_the_denylist_on_work_end_to_end() {
    let t = setup(json!(["*"]), &[]).await;
    accepted(&t, "SB-1", json!(["ls *", "cargo test *"])).await;
    assert!(allowed(&t.n.b, pre_bash(&t.n.repo_b, "ls src")).await);
    assert!(allowed(&t.n.b, pre_bash(&t.n.repo_b, "cargo test glob_tests")).await);
}

async fn audit_unavailable(prep: impl Fn(&Path)) {
    let t = setup_with(json!(["ls *"]), &[], prep).await;
    let c = delegate(&t.n, "SB-1", json!(["ls *"])).await;
    assert!(c.contains("information only"), "{c}");
    assert!(c.contains("audit log unavailable"), "{c}");
    assert!(!allowed(&t.n.b, pre_edit(SB, &t.n.repo_b, "src/a.rs")).await);
    assert!(!allowed(&t.n.b, pre_bash(&t.n.repo_b, "ls src")).await);
}

#[tokio::test]
async fn an_audit_path_that_is_a_directory_refuses_acceptance() {
    audit_unavailable(|p| std::fs::create_dir_all(p).unwrap()).await;
}

#[tokio::test]
async fn an_audit_path_that_is_a_symlink_refuses_acceptance() {
    audit_unavailable(|p| {
        let target = p.with_extension("target");
        std::fs::write(&target, "").unwrap();
        symlink(&target, p).unwrap();
    })
    .await;
}

#[tokio::test]
async fn an_audit_file_open_to_group_or_others_refuses_acceptance() {
    audit_unavailable(|p| {
        std::fs::write(p, "").unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
    })
    .await;
}

#[tokio::test]
async fn an_audit_log_that_breaks_later_stops_the_allow_answers() {
    let t = setup(json!(["ls *"]), &[]).await;
    accepted(&t, "SB-1", json!(["ls *"])).await;
    assert!(allowed(&t.n.b, pre_edit(SB, &t.n.repo_b, "src/a.rs")).await);
    let audit = delegation::audit_path(&t.policy);
    std::fs::remove_file(&audit).unwrap();
    std::fs::create_dir(&audit).unwrap();
    assert!(!allowed(&t.n.b, pre_edit(SB, &t.n.repo_b, "src/a.rs")).await);
    assert!(!allowed(&t.n.b, pre_bash(&t.n.repo_b, "ls src")).await);
}

#[tokio::test]
async fn a_session_that_moves_to_another_repository_gets_no_bash_allow() {
    let t = setup(json!(["ls *"]), &[]).await;
    accepted(&t, "SB-1", json!(["ls *"])).await;
    assert!(allowed(&t.n.b, pre_bash(&t.n.repo_b, "ls src")).await);
    let other = make_repo(&t.n.dir.join("b/other"));
    std::fs::write(
        other.join(".git/config"),
        "[remote \"origin\"]\n\turl = git@example.com:team/other.git\n",
    )
    .unwrap();
    std::fs::create_dir_all(other.join("src")).unwrap();
    assert!(!allowed(&t.n.b, pre_bash(&other, "ls src")).await);
}

#[tokio::test]
async fn dangling_symlinks_get_no_allow_for_edits_writes_and_operands() {
    let t = setup(json!(["cat *"]), &[]).await;
    let r = &t.n.repo_b;
    symlink("/nonexistent-outside/x", r.join("src/link")).unwrap();
    symlink("/nonexistent-outside/dir", r.join("src/dl")).unwrap();
    accepted(&t, "SB-1", json!(["cat *"])).await;
    assert!(allowed(&t.n.b, pre_edit(SB, r, "src/ok.rs")).await);
    assert!(!allowed(&t.n.b, pre_edit(SB, r, "src/link")).await);
    assert!(!allowed(&t.n.b, pre_edit(SB, r, "src/dl/new.rs")).await);
    let w = |f: &str| pre_tool(r, "Write", json!({"file_path": r.join(f), "content": "x"}));
    assert!(!allowed(&t.n.b, w("src/link")).await);
    assert!(!allowed(&t.n.b, w("src/dl/new.rs")).await);
    assert!(!allowed(&t.n.b, pre_bash(r, "cat src/link")).await);
    assert!(allowed(&t.n.b, w("src/fresh.rs")).await);
}

#[tokio::test]
async fn tool_input_keys_and_sandbox_override() {
    let t = setup(json!(["ls *"]), &[]).await;
    accepted(&t, "SB-1", json!(["ls *"])).await;
    let (n, r) = (&t.n, &t.n.repo_b);
    let nb = |input: Value| pre_tool(r, "NotebookEdit", input);
    assert!(
        allowed(
            &n.b,
            nb(json!({"notebook_path": r.join("src/n.ipynb"), "new_source": "x"}))
        )
        .await
    );
    assert!(
        !allowed(
            &n.b,
            nb(
                json!({"notebook_path": r.join("src/n.ipynb"), "file_path": r.join("src/n.ipynb"),
                      "new_source": "x"})
            )
        )
        .await
    );
    assert!(
        !allowed(
            &n.b,
            nb(
                json!({"notebook_path": r.join("src/n.ipynb"), "file_path": "/etc/passwd",
                      "new_source": "x"})
            )
        )
        .await
    );
    assert!(
        allowed(
            &n.b,
            pre_tool(
                r,
                "Bash",
                json!({"command": "ls src", "dangerouslyDisableSandbox": false})
            )
        )
        .await
    );
    assert!(
        !allowed(
            &n.b,
            pre_tool(
                r,
                "Bash",
                json!({"command": "ls src", "dangerouslyDisableSandbox": true})
            )
        )
        .await
    );
}

#[tokio::test]
async fn narrowing_the_policy_closes_the_contract_before_the_next_answer() {
    let t = setup(json!(["ls *"]), &[]).await;
    accepted(&t, "SB-1", json!(["ls *"])).await;
    let (n, r) = (&t.n, &t.n.repo_b);
    assert!(allowed(&n.b, pre_edit(SB, r, "src/a.rs")).await);
    std::fs::write(&t.policy, r#"{"grants": []}"#).unwrap();
    assert!(!allowed(&n.b, pre_edit(SB, r, "src/a.rs")).await);
    assert!(!allowed(&n.b, pre_bash(r, "ls src")).await);
    // The contract stays closed even if the grant comes back.
    let g = json!({"from": ["alice@machine-a"], "repos": [repo_id()], "task_ids": ["SB-*"],
        "level": "scoped-bypass", "paths": ["src/**"], "kinds": ["fix"], "commands": ["ls *"]});
    std::fs::write(&t.policy, json!({"grants": [g]}).to_string()).unwrap();
    assert!(!allowed(&n.b, pre_edit(SB, r, "src/a.rs")).await);
}
