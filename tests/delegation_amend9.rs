//! Amendment 9 to the delegation spec: a character allowlist for Bash tokens at scoped-bypass,
//! and more default deny paths.

mod common;

use common::*;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};
use wormhole::daemon::DaemonHandle;
use wormhole::delegation::Policy;

const SA: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const SB: &str = "bbbbbbbb-0000-4000-8000-000000000002";
const NOTICE: &str = "[wormhole delegation] request";

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn policy() -> Policy {
    Policy::parse(r#"{"grants": [], "safe_programs": ["cat", "grep"]}"#).unwrap()
}

fn ok(patterns: &[&str], cmd: &str) -> bool {
    policy().command_allowed(&strs(patterns), cmd).is_ok()
}

#[test]
fn characters_outside_the_allowlist_get_no_allow() {
    for bad in [
        "cat .en#v",
        "cat ^zzz",
        "cat a!b",
        "cat a%b",
        "cat a:b",
        "cat é.rs",
        "cat a;b",
        "cat a~b",
        "cat a=b",
        "cat a b#",
    ] {
        assert!(!ok(&["cat *"], bad), "{bad:?}");
    }
    assert!(!ok(&["grep *"], "grep ^x src/a.rs"));
    // Positive controls.
    assert!(ok(&["cat *"], "cat src/a.rs"));
    assert!(ok(&["cat *"], "cat src/a-b_c.d+e@f,g.rs"));
    assert!(ok(&["grep *"], "grep foo src/a.rs"));
}

#[test]
fn patterns_with_characters_outside_the_allowlist_are_invalid_at_load() {
    let load = |pat: &str| {
        Policy::parse(
            &json!({"grants": [{"from": ["alice@machine-a"], "repos": ["example.com/team/proj"],
                "level": "scoped-bypass", "paths": ["src/**"], "kinds": ["fix"],
                "commands": [pat]}], "safe_programs": ["cat", "grep"]})
            .to_string(),
        )
    };
    for bad in [
        "cat a^b",
        "cat #x",
        "cat a#b",
        "cat a%b",
        "cat a!b",
        "cat é.rs",
        "grep ^x *",
    ] {
        assert!(load(bad).is_err(), "{bad}");
    }
    // The final whole `*` is the only exception.
    for good in ["cat *", "cat a-b_c.d+e@f,g.rs", "grep foo *"] {
        assert!(load(good).is_ok(), "{good}");
    }
}

#[test]
fn more_default_deny_paths() {
    let p = Policy::parse(r#"{"grants": []}"#).unwrap();
    for path in [
        "id_ecdsa",
        "a/id_ecdsa.pub",
        "id_dsa",
        "x.jks",
        "a/x.jks",
        "x.keystore",
        ".env_local",
        "a/.env_local",
        ".env-prod",
        "a/.env-prod",
        ".pypirc",
        "h/.pypirc",
        ".dockercfg",
        "a.tfstate",
        "infra/a.tfstate",
        ".htpasswd",
        "web/.htpasswd",
        "credentials.json",
        "a/credentials.json",
        "aws/credentials",
    ] {
        assert!(p.denied_path(path).is_some(), "{path}");
    }
    for path in [
        "src/a.rs",
        "src/env.rs",
        "src/keystore_helper.rs",
        "docs/id.md",
    ] {
        assert_eq!(p.denied_path(path), None, "{path}");
    }
}

// ---- end to end ----

fn repo_id() -> String {
    let d = tmpdir();
    wormhole::repo::find(&make_repo(&d.join("r"))).unwrap().id
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

#[tokio::test]
async fn a_glob_operator_in_a_bash_operand_gets_no_permission_decision_end_to_end() {
    let path = tmpdir().join("policy.json");
    let g = json!({"from": ["alice@machine-a"], "repos": [repo_id()], "task_ids": ["SB-*"],
        "level": "scoped-bypass", "paths": ["src/**"], "kinds": ["fix"], "commands": ["cat *"]});
    std::fs::write(
        &path,
        json!({"grants": [g], "safe_programs": ["cat", "grep"]}).to_string(),
    )
    .unwrap();
    let n = net(Opts {
        policy_b: Some(path),
        ..Opts::default()
    })
    .await;
    std::fs::create_dir_all(n.repo_b.join("src")).unwrap();
    std::fs::write(n.repo_b.join("src/a.rs"), "x").unwrap();
    std::fs::write(n.repo_b.join(".env"), "secret").unwrap();
    hook(&n.a, session_start(SA, &n.repo_a)).await;
    hook(&n.b, session_start(SB, &n.repo_b)).await;
    tool(
        &n.a,
        SA,
        "delegate",
        json!({"to_session": SB, "to": SB, "task_id": "SB-1", "kind": "fix", "text": "do it",
               "paths": ["src/**"], "exit": "done", "commands": ["cat *"]}),
    )
    .await
    .unwrap();
    let c = next_ctx(&n.b, SB, &n.repo_b, |c| {
        c.contains(NOTICE) && c.contains("SB-1")
    })
    .await;
    assert!(c.contains("status: accepted"), "{c}");

    let r = hook(&n.b, pre_bash(&n.repo_b, "cat src/a.rs")).await;
    assert_eq!(decision(&r).as_deref(), Some("allow"), "{r}");
    for cmd in ["cat .en#v", "cat ^zzz", "cat a!b", "cat a%b", "cat é.rs"] {
        let r = hook(&n.b, pre_bash(&n.repo_b, cmd)).await;
        assert_eq!(decision(&r), None, "{cmd}: {r}");
    }
}
