//! Delegation end to end: one hub and two (sometimes three) daemons in-process over localhost.
//! Daemon b runs with a delegation policy that grants alice@machine-a by task-id prefix:
//! SI- scoped-instruction, SB- scoped-bypass (commands `cargo test*`), SBX- scoped-bypass
//! (any command), FB- full-bypass, IN- inform; anything else has no grant.

mod common;

use common::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wormhole::daemon::{self, DaemonHandle};
use wormhole::delegation;

const SA: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const SB: &str = "bbbbbbbb-0000-4000-8000-000000000002";
const SC: &str = "cccccccc-0000-4000-8000-000000000003";
const SD: &str = "dddddddd-0000-4000-8000-000000000004";
const SE: &str = "eeeeeeee-0000-4000-8000-000000000005";
const NOTICE: &str = "[wormhole delegation] request";

fn repo_id() -> String {
    let d = tmpdir();
    wormhole::repo::find(&make_repo(&d.join("r"))).unwrap().id
}

fn grant(task: &str, level: &str, extra: Value) -> Value {
    let mut g = json!({
        "from": ["alice@machine-a"], "repos": [repo_id()], "task_ids": [task], "level": level,
        "paths": ["src/**"], "kinds": ["tests", "fix", "any"],
    });
    for (k, v) in extra.as_object().unwrap() {
        g[k] = v.clone();
    }
    g
}

fn default_policy() -> Value {
    json!({"grants": [
        grant("SI-*", "scoped-instruction", json!({})),
        grant("SB-*", "scoped-bypass", json!({"commands": ["cargo test"]})),
        grant("SBX-*", "scoped-bypass", json!({"commands": ["*"]})),
        grant("FB-*", "full-bypass", json!({})),
        grant("IN-*", "inform", json!({})),
    ], "safe_programs": ["git", "cargo", "ls", "cat", "head", "tail", "wc", "grep", "diff", "stat", "pwd", "echo", "true", "false", "cut", "tr", "basename", "dirname", "realpath"]})
}

fn opts(policy: &Path) -> Opts {
    Opts {
        policy_b: Some(policy.to_path_buf()),
        ..Opts::default()
    }
}

/// A net whose daemon b has `policy`, with sessions SA on a and SB on b.
async fn setup(policy: Value) -> (Net, PathBuf) {
    let path = tmpdir().join("policy.json");
    std::fs::write(&path, policy.to_string()).unwrap();
    let n = net(opts(&path)).await;
    assert_eq!(wormhole::repo::find(&n.repo_b).unwrap().id, repo_id());
    hook(&n.a, session_start(SA, &n.repo_a)).await;
    hook(&n.b, session_start(SB, &n.repo_b)).await;
    (n, path)
}

/// Next PostToolUse context for `session` that satisfies `pred`.
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

/// Everything `session` is told over `ms` milliseconds.
async fn collect_ctx(d: &DaemonHandle, session: &str, cwd: &Path, ms: u64) -> String {
    let t = Instant::now();
    let mut all = String::new();
    while t.elapsed() < Duration::from_millis(ms) {
        all.push_str(&ctx(&hook(d, post_bash(session, cwd)).await));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    all
}

fn pre_tool(session: &str, cwd: &Path, tool: &str, input: Value) -> Value {
    let mut v = base("PreToolUse", session, cwd);
    v["tool_name"] = json!(tool);
    v["tool_input"] = input;
    v["tool_use_id"] = json!("toolu_9");
    v
}

fn pre_bash(session: &str, cwd: &Path, cmd: &str) -> Value {
    pre_tool(session, cwd, "Bash", json!({"command": cmd}))
}

async fn allowed(d: &DaemonHandle, input: Value) -> bool {
    decision(&hook(d, input).await).as_deref() == Some("allow")
}

/// A delegate call from SA to SB; `extra` keys override the defaults.
async fn delegate(
    n: &Net,
    task: &str,
    kind: &str,
    text: &str,
    extra: Value,
) -> Result<String, String> {
    let mut a = json!({"to_session": SB, "to": SB, "task_id": task, "kind": kind, "text": text});
    for (k, v) in extra.as_object().unwrap() {
        a[k] = v.clone();
    }
    tool(&n.a, SA, "delegate", a).await
}

/// The request id in a delegation notice.
fn request_id(notice: &str) -> u64 {
    let rest = &notice[notice.find(NOTICE).expect("no delegation notice") + NOTICE.len()..];
    rest.trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap()
}

/// Delegate and wait for B's notice; returns (request id, notice).
async fn delegate_ok(n: &Net, task: &str, kind: &str, text: &str, extra: Value) -> (u64, String) {
    delegate(n, task, kind, text, extra).await.unwrap();
    let c = next_ctx(&n.b, SB, &n.repo_b, |c| {
        c.contains(NOTICE) && c.contains(task)
    })
    .await;
    (request_id(&c), c)
}

fn audit_lines(policy: &Path) -> Vec<Value> {
    std::fs::read_to_string(delegation::audit_path(policy))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("audit line {l}: {e}")))
        .collect()
}

#[tokio::test]
async fn scoped_instruction_end_to_end() {
    let (n, _) = setup(default_policy()).await;
    let text = "TASK-TEXT-ALPHA add tests for the glob module";
    let r = delegate(
        &n,
        "SI-12",
        "tests",
        text,
        json!({"paths": ["src/a/**"], "exit": "tests pass", "result_fields": ["tests_added"]}),
    )
    .await
    .unwrap();
    assert!(r.chars().any(|c| c.is_ascii_digit()), "no seq in {r}");

    let c = next_ctx(&n.b, SB, &n.repo_b, |c| c.contains(NOTICE)).await;
    let req = request_id(&c);
    for want in [
        "status: accepted",
        "level: scoped-instruction",
        "Your permission prompts remain in force.",
        "Not authorised by this delegation",
        "SI-12",
        "src/a/**",
        SA,
    ] {
        assert!(c.contains(want), "missing {want}: {c}");
    }
    // The shared preamble mentions "information only" in every context, so look at the
    // delegation block alone.
    let start = c.find("<wormhole-delegation").expect("no delegation block");
    let end = c
        .find("</wormhole-delegation>")
        .expect("unterminated delegation block");
    assert!(!c[start..end].contains("information only"), "{c}");
    assert!(
        c.find("TASK-TEXT-ALPHA").unwrap() > c.find("status: accepted").unwrap(),
        "task text must come after the status line: {c}"
    );

    // B holds the leases: A's edit inside the paths is warned about, naming B's session.
    let w = ctx(&hook(&n.a, pre_edit(SA, &n.repo_a, "src/a/x.rs")).await);
    assert!(w.contains("WARNING") && w.contains(SB), "{w}");
    let who = tool(&n.b, SB, "who", json!({})).await.unwrap();
    assert!(who.contains("src/a/**"), "{who}");
    assert!(
        who.contains("Delegations:") && who.contains("SI-12"),
        "{who}"
    );

    // A sees the acknowledgement.
    let a = next_ctx(&n.a, SA, &n.repo_a, |c| {
        c.contains("SI-12") && c.contains("accepted")
    })
    .await;
    assert!(a.contains("scoped-instruction"), "{a}");

    // Prompts stay: an edit inside the paths is never allowed by wormhole.
    let r = hook(&n.b, pre_edit(SB, &n.repo_b, "src/a/y.rs")).await;
    assert_eq!(decision(&r), None, "{r}");

    // A done result must carry the required field.
    let e = tool(
        &n.b,
        SB,
        "result",
        json!({"request": req, "status": "done", "summary": "added tests", "fields": {}}),
    )
    .await
    .unwrap_err();
    assert!(e.contains("missing result field"), "{e}");
    tool(
        &n.b,
        SB,
        "result",
        json!({"request": req, "status": "done", "summary": "RESULT-SUMMARY-BETA",
               "fields": {"tests_added": 3}}),
    )
    .await
    .unwrap();
    let a = next_ctx(&n.a, SA, &n.repo_a, |c| c.contains("RESULT-SUMMARY-BETA")).await;
    assert!(a.contains("done") && a.contains("SI-12"), "{a}");

    // B's leases on the paths are released, so A can edit there again.
    eventually(5, || async {
        let w = ctx(&hook(&n.a, pre_edit(SA, &n.repo_a, "src/a/x.rs")).await);
        (!w.contains("WARNING")).then_some(())
    })
    .await;
    // A result on a closed request is refused.
    assert!(tool(
        &n.b,
        SB,
        "result",
        json!({"request": req, "status": "done", "summary": "again", "fields": {"tests_added": 1}}),
    )
    .await
    .is_err());
}

#[tokio::test]
async fn sender_leases_are_handed_off_and_broader_ones_block_acceptance() {
    let (n, _) = setup(default_policy()).await;
    tool(&n.a, SA, "lease", json!({"scope": "src/a/x.rs"}))
        .await
        .unwrap();
    delegate_ok(
        &n,
        "SI-1",
        "tests",
        "hand-off",
        json!({"paths": ["src/a/**"], "exit": "x"}),
    )
    .await;
    // The lease moved to B: A's own edit is now the one that warns.
    let w = ctx(&hook(&n.a, pre_edit(SA, &n.repo_a, "src/a/x.rs")).await);
    assert!(w.contains("WARNING") && w.contains(SB), "{w}");

    // A lease of the sender that is broader than the contract path blocks the acceptance.
    tool(&n.a, SA, "lease", json!({"scope": "src/z/**"}))
        .await
        .unwrap();
    delegate(
        &n,
        "SI-2",
        "tests",
        "too narrow",
        json!({"paths": ["src/z/q.rs"], "exit": "x"}),
    )
    .await
    .unwrap();
    let c = next_ctx(&n.b, SB, &n.repo_b, |c| {
        c.contains(NOTICE) && c.contains("SI-2")
    })
    .await;
    assert!(c.contains("information only"), "{c}");
    assert!(!c.contains("status: accepted"), "{c}");
}

#[tokio::test]
async fn scoped_bypass_answers_allow_inside_the_contract_only() {
    let (n, _) = setup(default_policy()).await;
    let (_, c) = delegate_ok(
        &n,
        "SB-1",
        "fix",
        "fix the parser",
        json!({"paths": ["src/**"], "commands": ["cargo test"], "exit": "tests green"}),
    )
    .await;
    assert!(
        c.contains("status: accepted") && c.contains("level: scoped-bypass"),
        "{c}"
    );
    assert!(
        !c.contains("Your permission prompts remain in force."),
        "{c}"
    );
    assert!(c.contains("Not authorised by this delegation"), "{c}");

    let r = hook(&n.b, pre_edit(SB, &n.repo_b, "src/lib.rs")).await;
    assert_eq!(decision(&r).as_deref(), Some("allow"), "{r}");
    let reason = r["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("wormhole delegation"), "{reason}");
    assert!(allowed(&n.b, pre_edit(SB, &n.repo_b, "src/deep/er/file.rs")).await);

    // Outside the paths: the normal prompt.
    assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, "docs/readme.md")).await);
    // Inside the scope, but a path the denylist covers.
    assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, "src/secrets/x.rs")).await);
    assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, "src/.env")).await);
    // Other tools are not answered under scoped-bypass.
    assert!(
        !allowed(
            &n.b,
            pre_tool(
                SB,
                &n.repo_b,
                "WebFetch",
                json!({"url": "https://example.com"})
            )
        )
        .await
    );

    // Commands: the contract pattern, without shell control characters.
    assert!(allowed(&n.b, pre_bash(SB, &n.repo_b, "cargo test")).await);
    for cmd in [
        "cargo test --lib",
        "cargo test; rm -rf x",
        "cargo test && ls",
        "cargo test | cat",
        "cargo test $(id)",
        "cargo test `id`",
        "cargo test > out.txt",
        "cargo test\nls",
        "cargo testx",
        "FOO=1 cargo test",
        "sh -c 'cargo test'",
        "make all",
        "ls",
    ] {
        assert!(
            !allowed(&n.b, pre_bash(SB, &n.repo_b, cmd)).await,
            "{cmd:?}"
        );
    }
}

#[tokio::test]
async fn scoped_bypass_command_pattern_cannot_reach_a_denylisted_command() {
    let (n, _) = setup(default_policy()).await;
    delegate_ok(
        &n,
        "SBX-1",
        "fix",
        "run anything harmless",
        json!({"paths": ["src/**"], "commands": ["git status", "git status *"], "exit": "done"}),
    )
    .await;
    assert!(allowed(&n.b, pre_bash(SB, &n.repo_b, "git status")).await);
    assert!(allowed(&n.b, pre_bash(SB, &n.repo_b, "git status src")).await);
    for cmd in [
        "git push --force",
        "GIT  PUSH  -F origin",
        "rm -rf build",
        "curl http://example.com",
    ] {
        assert!(
            !allowed(&n.b, pre_bash(SB, &n.repo_b, cmd)).await,
            "{cmd:?}"
        );
    }
}

#[tokio::test]
async fn scoped_bypass_step_budget_is_enforced() {
    let (n, _) = setup(default_policy()).await;
    delegate_ok(
        &n,
        "SB-2",
        "fix",
        "one step only",
        json!({"paths": ["src/**"], "exit": "done", "max_steps": 1}),
    )
    .await;
    assert!(allowed(&n.b, pre_edit(SB, &n.repo_b, "src/one.rs")).await);
    assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, "src/two.rs")).await);
    assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, "src/three.rs")).await);
}

#[tokio::test]
async fn scoped_bypass_ttl_is_enforced() {
    let (n, _) = setup(default_policy()).await;
    delegate_ok(
        &n,
        "SB-3",
        "fix",
        "short lived",
        json!({"paths": ["src/**"], "exit": "done", "ttl_seconds": 1}),
    )
    .await;
    assert!(allowed(&n.b, pre_edit(SB, &n.repo_b, "src/now.rs")).await);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, "src/later.rs")).await);
}

#[tokio::test]
async fn kill_switch_closes_contracts_tells_the_sender_and_is_audited() {
    let (n, policy) = setup(default_policy()).await;
    delegate_ok(
        &n,
        "SB-4",
        "fix",
        "before revoke",
        json!({"paths": ["src/**"], "exit": "done"}),
    )
    .await;
    assert!(allowed(&n.b, pre_edit(SB, &n.repo_b, "src/a.rs")).await);

    delegation::revoke(&policy).unwrap();
    assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, "src/b.rs")).await);
    let a = next_ctx(&n.a, SA, &n.repo_a, |c| c.contains("revoked")).await;
    assert!(a.contains("SB-4"), "{a}");
    // Still no answer while the file exists.
    assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, "src/c.rs")).await);

    // A request while revoked is information only, and says why.
    delegate(
        &n,
        "SB-5",
        "fix",
        "while revoked",
        json!({"paths": ["src/**"], "exit": "done"}),
    )
    .await
    .unwrap();
    let c = next_ctx(&n.b, SB, &n.repo_b, |c| {
        c.contains(NOTICE) && c.contains("SB-5")
    })
    .await;
    assert!(
        c.contains("information only") && c.contains("revoked"),
        "{c}"
    );

    // After resume a new request is accepted and answered again.
    delegation::resume(&policy).unwrap();
    let (_, c) = delegate_ok(
        &n,
        "SB-6",
        "fix",
        "after resume",
        json!({"paths": ["src/**"], "exit": "done"}),
    )
    .await;
    assert!(c.contains("status: accepted"), "{c}");
    assert!(allowed(&n.b, pre_edit(SB, &n.repo_b, "src/d.rs")).await);

    let lines = audit_lines(&policy);
    let events: Vec<&str> = lines.iter().map(|l| l["event"].as_str().unwrap()).collect();
    assert!(events.contains(&"request"), "{events:?}");
    assert!(events.contains(&"allow"), "{events:?}");
    assert!(
        events.contains(&"close") || events.contains(&"revoke"),
        "{events:?}"
    );
    for l in &lines {
        for k in ["ts", "event", "seq", "session", "level"] {
            assert!(l.get(k).is_some(), "{k} missing in {l}");
        }
    }
    let allow = lines.iter().find(|l| l["event"] == "allow").unwrap();
    assert!(allow.get("tool").is_some(), "{allow}");
    let req = lines.iter().find(|l| l["event"] == "request").unwrap();
    assert!(
        req.get("accepted").is_some() && req.get("reason").is_some(),
        "{req}"
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(delegation::audit_path(&policy))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[tokio::test]
async fn full_bypass_answers_allow_for_any_tool_except_denylist_hits() {
    let (n, _) = setup(default_policy()).await;
    let (_, c) = delegate_ok(
        &n,
        "FB-1",
        "any",
        "do whatever is needed",
        json!({"exit": "done"}),
    )
    .await;
    assert!(c.contains("level: full-bypass"), "{c}");
    // Only the pinned tool list is answered; other tools prompt.
    assert!(
        !allowed(
            &n.b,
            pre_tool(
                SB,
                &n.repo_b,
                "WebFetch",
                json!({"url": "https://example.com"})
            )
        )
        .await
    );
    let read = pre_tool(
        SB,
        &n.repo_b,
        "Read",
        json!({"file_path": n.repo_b.join("src/lib.rs")}),
    );
    assert!(allowed(&n.b, read).await);
    assert!(allowed(&n.b, pre_bash(SB, &n.repo_b, "ls -la")).await);
    assert!(allowed(&n.b, pre_edit(SB, &n.repo_b, "anywhere/file.rs")).await);
    for cmd in [
        "rm -rf build",
        "git push --force",
        "FOO=1 ls",
        "sh -c ls",
        "/bin/sh -c id",
        "env ls",
        "ls; id",
        "ls $(id)",
        "echo 'open",
    ] {
        assert!(
            !allowed(&n.b, pre_bash(SB, &n.repo_b, cmd)).await,
            "{cmd:?}"
        );
    }
    assert!(allowed(&n.b, pre_bash(SB, &n.repo_b, "git commit -m 'two words'")).await);
    assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, "config/.env")).await);
}

#[tokio::test]
async fn full_bypass_does_not_override_another_sessions_lease() {
    let (n, _) = setup(default_policy()).await;
    let sc = "ffffffff-0000-4000-8000-000000000006";
    hook(&n.b, session_start(sc, &n.repo_b)).await;
    tool(&n.b, sc, "lease", json!({"scope": "held/x.rs"}))
        .await
        .unwrap();
    delegate_ok(&n, "FB-2", "any", "careful", json!({"exit": "done"})).await;
    assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, "held/x.rs")).await);
    assert!(allowed(&n.b, pre_edit(SB, &n.repo_b, "free/y.rs")).await);
}

#[tokio::test]
async fn a_sender_without_a_grant_is_declined_and_the_receiver_is_not_bothered() {
    let (n, _) = setup(default_policy()).await;
    delegate(
        &n,
        "NONE-1",
        "tests",
        "NO-GRANT-TEXT",
        json!({"paths": ["src/a.rs"]}),
    )
    .await
    .unwrap();
    let a = next_ctx(&n.a, SA, &n.repo_a, |c| c.contains("NONE-1")).await;
    assert!(a.contains("declined") || a.contains("off"), "{a}");
    let b = collect_ctx(&n.b, SB, &n.repo_b, 600).await;
    assert!(
        !b.contains("[wormhole delegation]") && !b.contains("NO-GRANT-TEXT"),
        "{b}"
    );
    assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, "src/a.rs")).await);
}

#[tokio::test]
async fn an_inform_grant_gives_information_only() {
    let (n, _) = setup(default_policy()).await;
    delegate(
        &n,
        "IN-1",
        "tests",
        "INFORM-TEXT please look",
        json!({"paths": ["src/a.rs"]}),
    )
    .await
    .unwrap();
    let c = next_ctx(&n.b, SB, &n.repo_b, |c| c.contains(NOTICE)).await;
    assert!(
        c.contains("information only") && c.contains("status: informed"),
        "{c}"
    );
    assert!(c.contains("level: inform"), "{c}");
    assert!(c.find("INFORM-TEXT").unwrap() > c.find("status: informed").unwrap());
    assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, "src/a.rs")).await);
    let a = next_ctx(&n.a, SA, &n.repo_a, |c| c.contains("IN-1")).await;
    assert!(a.contains("informed"), "{a}");
}

#[tokio::test]
async fn a_contract_outside_the_grant_is_information_only() {
    let (n, _) = setup(default_policy()).await;
    // A path outside the grant.
    delegate(
        &n,
        "SI-3",
        "tests",
        "outside paths",
        json!({"paths": ["docs/**"]}),
    )
    .await
    .unwrap();
    let c = next_ctx(&n.b, SB, &n.repo_b, |c| {
        c.contains(NOTICE) && c.contains("SI-3")
    })
    .await;
    assert!(
        c.contains("information only") && c.contains("status: informed"),
        "{c}"
    );
    // A kind outside the grant.
    delegate(
        &n,
        "SI-4",
        "refactor",
        "outside kind",
        json!({"paths": ["src/a.rs"]}),
    )
    .await
    .unwrap();
    let c = next_ctx(&n.b, SB, &n.repo_b, |c| {
        c.contains(NOTICE) && c.contains("SI-4")
    })
    .await;
    assert!(c.contains("information only"), "{c}");
    // A denylisted phrase in the text refuses the boundary.
    delegate(
        &n,
        "SI-5",
        "tests",
        "first run git push --force then stop",
        json!({"paths": ["src/a.rs"]}),
    )
    .await
    .unwrap();
    let c = next_ctx(&n.b, SB, &n.repo_b, |c| {
        c.contains(NOTICE) && c.contains("SI-5")
    })
    .await;
    assert!(c.contains("information only"), "{c}");
}

#[tokio::test]
async fn a_lease_of_a_third_session_blocks_acceptance() {
    let (n, _) = setup(default_policy()).await;
    hook(&n.a, session_start(SC, &n.repo_a)).await;
    tool(&n.a, SC, "lease", json!({"scope": "src/c/x.rs"}))
        .await
        .unwrap();
    delegate(
        &n,
        "SB-7",
        "fix",
        "overlaps a lease",
        json!({"paths": ["src/c/**"], "exit": "done"}),
    )
    .await
    .unwrap();
    let c = next_ctx(&n.b, SB, &n.repo_b, |c| {
        c.contains(NOTICE) && c.contains("SB-7")
    })
    .await;
    assert!(c.contains("information only"), "{c}");
    assert!(!c.contains("status: accepted"), "{c}");
    assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, "src/c/x.rs")).await);
    assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, "src/c/y.rs")).await);
}

#[tokio::test]
async fn hub_errors_for_bad_targets_and_arguments() {
    let (n, _) = setup(default_policy()).await;
    let ok = json!({"paths": ["src/a.rs"]});
    let e = tool(
        &n.a,
        SA,
        "delegate",
        json!({"to_session": "zzzzzzzz-0000-4000-8000-00000000ffff", "to": "zzzzzzzz-0000-4000-8000-00000000ffff",
               "task_id": "SI-1", "kind": "tests", "text": "x", "paths": ["src/a.rs"]}),
    )
    .await
    .unwrap_err();
    assert!(e.contains("no such session"), "{e}");

    let e = tool(
        &n.a,
        SA,
        "delegate",
        json!({"to_session": SA, "to": SA, "task_id": "SI-1", "kind": "tests", "text": "x", "paths": ["src/a.rs"]}),
    )
    .await
    .unwrap_err();
    assert!(e.contains("cannot delegate to this session"), "{e}");

    // A session of the same daemon in a different repository.
    let other = make_repo(&n.dir.join("b/other"));
    std::fs::write(
        other.join(".git/config"),
        "[remote \"origin\"]\n\turl = git@example.com:team/other.git\n",
    )
    .unwrap();
    hook(&n.b, session_start(SD, &other)).await;
    let e = tool(
        &n.a,
        SA,
        "delegate",
        json!({"to_session": SD, "to": SD, "task_id": "SI-1", "kind": "tests", "text": "x", "paths": ["src/a.rs"]}),
    )
    .await
    .unwrap_err();
    assert!(e.contains("different repository"), "{e}");

    // Argument validation.
    assert!(delegate(&n, "SI-9", "tests", "x", ok.clone()).await.is_ok());
    for bad in [
        json!({"kind": "Bad Kind"}),
        json!({"kind": ""}),
        json!({"task_id": ""}),
        json!({"text": ""}),
        json!({"paths": ["../etc/passwd"]}),
        json!({"paths": ["area:build"]}),
        json!({"ttl_seconds": 14401}),
        json!({"commands": ["ls\nrm"]}),
    ] {
        assert!(
            delegate(&n, "SI-9", "tests", "x", bad.clone())
                .await
                .is_err(),
            "{bad}"
        );
    }
}

#[tokio::test]
async fn a_third_machine_never_sees_delegation_events_and_the_page_shows_no_contents() {
    let (n, _) = setup(default_policy()).await;
    let url = format!("ws://{}/ws", n.hub.addr);
    let c = daemon::start(daemon_config(
        &n.dir,
        url,
        "carol@machine-c",
        &Opts::default(),
    ))
    .await
    .unwrap();
    wait_connected(&c).await;
    let repo_c = make_repo(&n.dir.join("c/proj"));
    hook(&c, session_start(SE, &repo_c)).await;

    let mut sse = tokio::net::TcpStream::connect(n.hub.addr).await.unwrap();
    sse.write_all(
        format!("GET /api/events HTTP/1.1\r\nHost: {}\r\nx-wormhole-static-identity: carol@viewer\r\n\r\n", n.hub.addr)
            .as_bytes(),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let secrets = [
        "PRIVATE-TASK-GAMMA",
        "PRIVATE-SUMMARY-DELTA",
        "PRIVATE-EXIT-EPSILON",
        "PRIVATE-FIELD-ZETA",
    ];
    let (req, _) = delegate_ok(
        &n,
        "SI-20",
        "tests",
        secrets[0],
        json!({"paths": ["src/a/**"], "exit": secrets[2], "spec": "PRIVATE-SPEC-ETA",
               "commands": [], "result_fields": ["note"]}),
    )
    .await;
    tool(
        &n.b,
        SB,
        "result",
        json!({"request": req, "status": "done", "summary": secrets[1], "fields": {"note": secrets[3]}}),
    )
    .await
    .unwrap();
    next_ctx(&n.a, SA, &n.repo_a, |c| c.contains(secrets[1])).await;

    // The third machine is live and receives what is addressed to it, but nothing of this.
    tool(
        &n.a,
        SA,
        "send",
        json!({"to": format!("session:{SE}"), "body": "ping-for-carol"}),
    )
    .await
    .unwrap();
    let mut seen = next_ctx(&c, SE, &repo_c, |c| c.contains("ping-for-carol")).await;
    seen.push_str(&collect_ctx(&c, SE, &repo_c, 500).await);
    for s in secrets.iter().chain(&["PRIVATE-SPEC-ETA", "SI-20"]) {
        assert!(!seen.contains(s), "third machine saw {s}: {seen}");
    }
    assert!(!seen.contains("[wormhole delegation]"), "{seen}");

    // The activity page and its live stream show no contents.
    let id = ("x-wormhole-static-identity", "carol@viewer");
    let (s, _, state) = http(n.hub.addr, "GET", "/api/state", &[id], "").await;
    assert_eq!(s, 200);
    let mut got = String::new();
    let mut buf = vec![0u8; 65536];
    while let Ok(Ok(k)) = tokio::time::timeout(Duration::from_millis(300), sse.read(&mut buf)).await
    {
        if k == 0 {
            break;
        }
        got.push_str(&String::from_utf8_lossy(&buf[..k]));
    }
    assert!(got.contains("text/event-stream"), "{got}");
    for s in secrets.iter().chain(&["PRIVATE-SPEC-ETA"]) {
        assert!(!state.contains(s), "state page leaked {s}: {state}");
        assert!(!got.contains(s), "event stream leaked {s}: {got}");
    }
}

#[tokio::test]
async fn without_any_policy_wormhole_never_answers_allow() {
    let n = net(Opts::default()).await;
    hook(&n.a, session_start(SA, &n.repo_a)).await;
    hook(&n.b, session_start(SB, &n.repo_b)).await;
    for who in [(&n.a, SA, &n.repo_a), (&n.b, SB, &n.repo_b)] {
        let r = hook(who.0, pre_edit(who.1, who.2, "src/lib.rs")).await;
        assert_ne!(decision(&r).as_deref(), Some("allow"), "{r}");
        let r = hook(who.0, pre_bash(who.1, who.2, "cargo test --lib")).await;
        assert_ne!(decision(&r).as_deref(), Some("allow"), "{r}");
        let r = hook(
            who.0,
            pre_tool(
                who.1,
                who.2,
                "WebFetch",
                json!({"url": "https://example.com"}),
            ),
        )
        .await;
        assert_ne!(decision(&r).as_deref(), Some("allow"), "{r}");
    }
}

#[tokio::test]
async fn a_restarted_daemon_does_not_reopen_an_accepted_contract() {
    let path = tmpdir().join("policy.json");
    std::fs::write(&path, default_policy().to_string()).unwrap();
    let o = opts(&path);
    let n = net(opts(&path)).await;
    hook(&n.a, session_start(SA, &n.repo_a)).await;
    hook(&n.b, session_start(SB, &n.repo_b)).await;
    delegate_ok(
        &n,
        "SB-8",
        "fix",
        "survive a restart?",
        json!({"paths": ["src/**"], "exit": "done"}),
    )
    .await;
    assert!(allowed(&n.b, pre_edit(SB, &n.repo_b, "src/before.rs")).await);

    let Net {
        hub,
        a,
        b,
        repo_a,
        repo_b,
        dir,
    } = n;
    b.shutdown().await;
    let mut cfg = daemon_config(&dir, format!("ws://{}/ws", hub.addr), "bob@machine-b", &o);
    cfg.delegation_policy = o.policy_b.clone();
    let b = daemon::start(cfg).await.unwrap();
    wait_connected(&b).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    hook(&b, session_start(SB, &repo_b)).await;
    for f in ["src/after.rs", "src/after2.rs"] {
        let r = hook(&b, pre_edit(SB, &repo_b, f)).await;
        assert_ne!(decision(&r).as_deref(), Some("allow"), "{r}");
    }
    let r = hook(&b, pre_bash(SB, &repo_b, "cargo test --lib")).await;
    assert_ne!(decision(&r).as_deref(), Some("allow"), "{r}");
    let _ = (a, repo_a);
}
