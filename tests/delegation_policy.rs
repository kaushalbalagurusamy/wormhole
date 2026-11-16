//! Pure tests of the delegation policy module (spec section C).

mod common;

use common::tmpdir;
use serde_json::{json, Value};
use wormhole::delegation::{self, Level, Policy};
use wormhole::proto::Contract;

const REPO: &str = "example.com/team/proj";

fn grant(level: &str) -> Value {
    json!({"from": ["alice@machine-a"], "repos": [REPO], "level": level,
           "paths": ["src/a/**"], "kinds": ["tests", "fix"]})
}

fn policy(grants: Vec<Value>) -> Policy {
    Policy::parse(&json!({"grants": grants, "safe_programs": ["git", "cargo"]}).to_string())
        .unwrap()
}

fn parse_err(v: Value) -> String {
    match Policy::parse(&v.to_string()) {
        Ok(_) => panic!("accepted: {v}"),
        Err(e) => e,
    }
}

fn contract() -> Contract {
    Contract {
        task_id: "T-1".into(),
        kind: "tests".into(),
        paths: vec!["src/a/x.rs".into()],
        exit: "tests pass".into(),
        text: "add tests".into(),
        ..Default::default()
    }
}

fn eval(p: &Policy, c: &Contract) -> delegation::Decision {
    p.evaluate("alice", "machine-a", REPO, c)
}

#[test]
fn level_order_and_names() {
    let all = [
        Level::Off,
        Level::Inform,
        Level::ScopedInstruction,
        Level::ScopedBypass,
        Level::FullBypass,
    ];
    assert!(all.windows(2).all(|w| w[0] < w[1]));
    let names = [
        "off",
        "inform",
        "scoped-instruction",
        "scoped-bypass",
        "full-bypass",
    ];
    for (l, n) in all.iter().zip(names) {
        assert_eq!(l.as_str(), n);
        assert_eq!(Level::parse(n), Some(*l));
        assert_eq!(serde_json::to_value(l).unwrap(), json!(n));
    }
    assert_eq!(Level::parse("root"), None);
    assert_eq!(Level::parse(""), None);
}

#[test]
fn load_errors() {
    let mut g = grant("bogus");
    assert!(parse_err(json!({"grants": [g.clone()]})).contains("unknown level"));
    for from in [json!(["*"]), json!(["alice@*"]), json!(["al*"]), json!([])] {
        g = grant("scoped-instruction");
        g["from"] = from;
        assert!(parse_err(json!({"grants": [g]})).contains("from"));
    }
    g = grant("scoped-instruction");
    g["repos"] = json!([]);
    assert!(parse_err(json!({"grants": [g]})).contains("repos"));
    for level in ["scoped-instruction", "scoped-bypass"] {
        g = grant(level);
        g["paths"] = json!([]);
        assert!(
            parse_err(json!({"grants": [g]})).contains("paths"),
            "{level}"
        );
        g = grant(level);
        g.as_object_mut().unwrap().remove("paths");
        assert!(
            parse_err(json!({"grants": [g]})).contains("paths"),
            "{level}"
        );
        g = grant(level);
        g["kinds"] = json!([]);
        assert!(
            parse_err(json!({"grants": [g]})).contains("kinds"),
            "{level}"
        );
    }
    g = grant("scoped-instruction");
    g["kinds"] = json!(["deploy"]);
    assert!(parse_err(json!({"grants": [g]})).contains("denylisted kind"));
    // Malformed JSON and unknown keys are errors.
    assert!(Policy::parse("{not json").is_err());
    assert!(Policy::parse("").is_err());
    assert!(Policy::parse(r#"{"grants": [], "surprise": 1}"#).is_err());
    let mut g = grant("scoped-instruction");
    g["surprise"] = json!(true);
    assert!(Policy::parse(&json!({"grants": [g]}).to_string()).is_err());
    assert!(Policy::parse(r#"{"grants": [], "denylist": {"surprise": 1}}"#).is_err());
}

#[test]
fn load_reads_a_file_and_reports_a_missing_one() {
    let d = tmpdir();
    let f = d.join("policy.json");
    std::fs::write(
        &f,
        json!({"grants": [grant("scoped-instruction")]}).to_string(),
    )
    .unwrap();
    let p = Policy::load(&f).unwrap();
    assert!(eval(&p, &contract()).accepted);
    assert!(Policy::load(&d.join("missing.json")).is_err());
    std::fs::write(&f, "{").unwrap();
    assert!(Policy::load(&f).is_err());
}

#[test]
fn no_matching_grant_is_off() {
    let p = policy(vec![grant("scoped-instruction")]);
    let c = contract();
    for d in [
        p.evaluate("mallory", "machine-a", REPO, &c),
        p.evaluate("alice", "machine-z", REPO, &c),
        p.evaluate("alice", "machine-a", "example.com/other/repo", &c),
    ] {
        assert_eq!(d.level, Level::Off);
        assert!(!d.accepted);
        assert!(d.reason.contains("no grant"), "{}", d.reason);
    }
    // A sender named by user alone matches any of their machines.
    let mut g = grant("scoped-instruction");
    g["from"] = json!(["alice"]);
    let p = policy(vec![g]);
    assert!(p.evaluate("alice", "machine-z", REPO, &c).accepted);
    assert!(!p.evaluate("bob", "machine-z", REPO, &c).accepted);
    // "*" in repos matches any repository.
    let mut g = grant("scoped-instruction");
    g["repos"] = json!(["*"]);
    assert!(
        policy(vec![g])
            .evaluate("alice", "machine-a", "x.example/any/repo", &c)
            .accepted
    );
}

#[test]
fn task_id_patterns_select_the_grant() {
    let mut g = grant("scoped-instruction");
    g["task_ids"] = json!(["T-*"]);
    let p = policy(vec![g]);
    assert!(eval(&p, &contract()).accepted);
    let mut c = contract();
    c.task_id = "X-1".into();
    let d = eval(&p, &c);
    assert_eq!(d.level, Level::Off);
    assert!(d.reason.contains("no grant"), "{}", d.reason);
}

#[test]
fn an_off_grant_wins() {
    let mut off = grant("off");
    off["paths"] = json!([]);
    off["kinds"] = json!([]);
    let mut full = grant("full-bypass");
    full["task_ids"] = json!(["*"]);
    let p = policy(vec![full, off]);
    let d = eval(&p, &contract());
    assert_eq!(d.level, Level::Off);
    assert!(!d.accepted);
}

#[test]
fn highest_fitting_grant_wins() {
    let mut bypass = grant("scoped-bypass");
    bypass["commands"] = json!(["cargo test"]);
    let instr = {
        let mut g = grant("scoped-instruction");
        g["paths"] = json!(["src/**"]);
        g
    };
    let mut full = grant("full-bypass");
    full["task_ids"] = json!(["FB-*"]);
    let p = policy(vec![instr, bypass, full]);

    let mut c = contract();
    c.commands = vec!["cargo test".into()];
    let d = eval(&p, &c);
    assert_eq!((d.level, d.accepted), (Level::ScopedBypass, true));

    // Outside the bypass paths but inside the instruction paths.
    c.paths = vec!["src/b/x.rs".into()];
    let d = eval(&p, &c);
    assert_eq!((d.level, d.accepted), (Level::ScopedInstruction, true));

    // A command the bypass grant does not list.
    let mut c = contract();
    c.commands = vec!["make".into()];
    assert_eq!(eval(&p, &c).level, Level::ScopedInstruction);

    // No exit condition: only the instruction grant fits.
    let mut c = contract();
    c.exit.clear();
    assert_eq!(eval(&p, &c).level, Level::ScopedInstruction);

    // The full-bypass grant applies by task id.
    let mut c = contract();
    c.task_id = "FB-1".into();
    c.paths = vec!["anywhere/x".into()];
    c.kind = "whatever".into();
    let d = eval(&p, &c);
    assert_eq!((d.level, d.accepted), (Level::FullBypass, true));
}

#[test]
fn contract_outside_every_boundary_is_inform_with_the_refusal() {
    let p = policy(vec![grant("scoped-instruction")]);
    let mut c = contract();
    c.kind = "refactor".into();
    let d = eval(&p, &c);
    assert_eq!((d.level, d.accepted), (Level::Inform, false));
    assert!(!d.reason.is_empty());
    let mut c = contract();
    c.paths.clear();
    assert!(!eval(&p, &c).accepted);
    // An inform grant alone gives inform with the reason "inform".
    let p = policy(vec![{
        let mut g = grant("inform");
        g["paths"] = json!([]);
        g["kinds"] = json!([]);
        g
    }]);
    let d = eval(&p, &contract());
    assert_eq!((d.level, d.accepted), (Level::Inform, false));
    assert_eq!(d.reason, "inform");
}

#[test]
fn scoped_instruction_boundary() {
    let p = policy(vec![grant("scoped-instruction")]);
    assert!(eval(&p, &contract()).accepted);
    // Kind not listed.
    let mut c = contract();
    c.kind = "docs".into();
    assert!(!eval(&p, &c).accepted);
    // Empty kind or task id.
    let mut c = contract();
    c.kind.clear();
    assert!(!eval(&p, &c).accepted);
    let mut c = contract();
    c.task_id.clear();
    assert!(!eval(&p, &c).accepted);
    // No paths, or one path outside.
    let mut c = contract();
    c.paths.clear();
    assert!(!eval(&p, &c).accepted);
    let mut c = contract();
    c.paths = vec!["src/a/x.rs".into(), "src/b/x.rs".into()];
    assert!(!eval(&p, &c).accepted);
    // A directory and a nested glob inside the grant path are covered.
    let mut c = contract();
    c.paths = vec![
        "src/a/sub/".into(),
        "src/a/**/y.rs".into(),
        "src/a/*.rs".into(),
    ];
    assert!(eval(&p, &c).accepted);
    // "*" in kinds allows any kind.
    let mut g = grant("scoped-instruction");
    g["kinds"] = json!(["*"]);
    let mut c = contract();
    c.kind = "anything".into();
    assert!(
        policy(vec![g])
            .evaluate("alice", "machine-a", REPO, &c)
            .accepted
    );
}

#[test]
fn glob_coverage_is_conservative() {
    let p = policy(vec![grant("scoped-instruction")]);
    for path in [
        "**",
        "src/**/x",
        "src/*",
        "src/",
        "src/ab/x.rs",
        "*",
        "area:build",
    ] {
        let mut c = contract();
        c.paths = vec![path.into()];
        assert!(
            !eval(&p, &c).accepted,
            "{path} should not be covered by src/a/**"
        );
    }
    for path in ["src/a/b/c.rs", "src/a/b/", "src/a/b/**"] {
        let mut c = contract();
        c.paths = vec![path.into()];
        assert!(
            eval(&p, &c).accepted,
            "{path} should be covered by src/a/**"
        );
    }
}

#[test]
fn scoped_bypass_boundary() {
    let mut g = grant("scoped-bypass");
    g["commands"] = json!(["cargo test", "cargo build", "cargo check *"]);
    let p = policy(vec![g.clone()]);
    // Contract command patterns must equal a grant pattern token for token.
    let mut c = contract();
    c.commands = vec![
        "cargo test".into(),
        "cargo build".into(),
        "cargo check *".into(),
    ];
    let d = eval(&p, &c);
    assert_eq!((d.level, d.accepted), (Level::ScopedBypass, true));
    // No commands at all is fine.
    assert!(eval(&p, &contract()).accepted);
    // Not equal to any grant pattern, including extensions and narrower forms.
    for bad in [
        "cargo test --lib",
        "cargo test *",
        "cargo check x",
        "cargo fmt",
        "cargo testx",
        "cargo",
        "make",
    ] {
        c.commands = vec![bad.into()];
        assert!(!eval(&p, &c).accepted, "{bad}");
    }
    // No exit condition.
    let mut c = contract();
    c.exit.clear();
    assert!(!eval(&p, &c).accepted);
    // A grant listing "*" alone allows any contract pattern.
    g["commands"] = json!(["*"]);
    let mut c = contract();
    c.commands = vec!["ls src".into()];
    assert!(
        policy(vec![g])
            .evaluate("alice", "machine-a", REPO, &c)
            .accepted
    );
}

#[test]
fn full_bypass_boundary_has_no_path_kind_or_command_limit() {
    let p = policy(vec![{
        let mut g = grant("full-bypass");
        g.as_object_mut().unwrap().remove("paths");
        g.as_object_mut().unwrap().remove("kinds");
        g
    }]);
    let mut c = contract();
    c.paths = vec!["any/where/x".into()];
    c.kind = "whatever".into();
    c.commands = vec!["make".into()];
    let d = eval(&p, &c);
    assert_eq!((d.level, d.accepted), (Level::FullBypass, true));
    let mut c2 = c.clone();
    c2.exit.clear();
    assert!(!eval(&p, &c2).accepted);
    let mut c3 = c;
    c3.task_id.clear();
    assert!(!eval(&p, &c3).accepted);
}

#[test]
fn default_denylist_contents() {
    assert_eq!(
        delegation::DEFAULT_DENY_KINDS,
        [
            "force-push",
            "delete-branch",
            "delete-data",
            "deploy",
            "merge-pr",
            "publish",
            "external-message",
            "secrets"
        ]
    );
    for want in [
        "push --force",
        "push -f",
        "--force-with-lease",
        "push --delete",
        "push origin :",
        "branch -d",
        "git reset --hard",
        "git clean -f",
        "rm -rf",
        "rm -fr",
        "drop table",
        "drop database",
        "truncate table",
        "gh pr merge",
        "git merge",
        "deploy",
        "kubectl",
        "terraform apply",
        "npm publish",
        "cargo publish",
        "twine upload",
        "gh release",
        "curl ",
        "wget ",
        "ssh ",
        "scp ",
        "sendmail",
        "mail ",
        "printenv",
        "security find-",
        "gpg --export-secret",
        "cat .env",
    ] {
        assert!(
            delegation::DEFAULT_DENY_COMMANDS.contains(&want),
            "command {want}"
        );
    }
    for want in [
        "**/.env",
        "**/.env.*",
        "**/*.pem",
        "**/*.key",
        "**/id_rsa*",
        "**/id_ed25519*",
        "**/secrets/**",
        "**/.git/**",
        "**/.ssh/**",
    ] {
        assert!(
            delegation::DEFAULT_DENY_PATHS.contains(&want),
            "path {want}"
        );
    }
}

#[test]
fn denied_command_and_path_with_the_default_module() {
    let p = policy(vec![grant("scoped-instruction")]);
    for c in [
        "git push --force origin main",
        "GIT   PUSH \t --FORCE",
        "ls && rm -rf /tmp/x",
        "curl http://example.com",
        "cat .env",
    ] {
        assert!(p.denied_command(c).is_some(), "{c}");
    }
    for c in ["cargo test --lib", "git status", "git push origin main"] {
        assert_eq!(p.denied_command(c), None, "{c}");
    }
    for path in [
        ".env",
        "a/.env",
        "a/.env.local",
        "config/server.pem",
        "x/secrets/y.txt",
        ".git/config",
        "home/.ssh/id_rsa",
        "k/id_ed25519.pub",
    ] {
        assert!(p.denied_path(path).is_some(), "{path}");
    }
    assert_eq!(p.denied_path("src/main.rs"), None);
    assert_eq!(p.denied_path("src/environment.rs"), None);
    assert_eq!(
        p.denied_path("config/server.pem").as_deref(),
        Some("**/*.pem")
    );
}

#[test]
fn denylist_refuses_the_boundary_on_every_level_above_inform() {
    let mut g = grant("scoped-instruction");
    g["kinds"] = json!(["*"]);
    let p = policy(vec![g]);
    let refused = |c: &Contract, hit: &str| {
        let d = eval(&p, c);
        assert!(!d.accepted, "{c:?}");
        assert_eq!(d.level, Level::Inform);
        assert!(d.reason.to_lowercase().contains(hit), "{hit}: {}", d.reason);
    };
    let mut c = contract();
    c.kind = "deploy".into();
    refused(&c, "deploy");
    let mut c = contract();
    c.paths = vec!["src/a/keys/server.pem".into()];
    refused(&c, "pem");
    let mut c = contract();
    c.text = "then RM   -RF the build dir".into();
    refused(&c, "rm -rf");
    let mut c = contract();
    c.exit = "when git push --force succeeds".into();
    refused(&c, "push --force");
    let mut c = contract();
    c.spec = "run terraform apply first".into();
    refused(&c, "terraform apply");

    let mut g = grant("scoped-bypass");
    g["commands"] = json!(["*"]);
    let pb = policy(vec![g]);
    let mut c = contract();
    c.commands = vec!["git reset --hard".into()];
    assert!(!pb.evaluate("alice", "machine-a", REPO, &c).accepted);
    // The same text screen applies to full-bypass.
    let mut g = grant("full-bypass");
    g["task_ids"] = json!(["*"]);
    let pf = policy(vec![g]);
    let mut c = contract();
    c.text = "please kubectl delete everything".into();
    let d = pf.evaluate("alice", "machine-a", REPO, &c);
    assert!(!d.accepted && d.level == Level::Inform, "{d:?}");
    assert!(
        pf.evaluate("alice", "machine-a", REPO, &contract())
            .accepted
    );
}

#[test]
fn wildcard_kind_grant_still_refuses_a_denylisted_kind() {
    let mut g = grant("scoped-instruction");
    g["kinds"] = json!(["*"]);
    let p = policy(vec![g]);
    let mut c = contract();
    c.kind = "publish".into();
    assert!(!eval(&p, &c).accepted);
    c.kind = "tests".into();
    assert!(eval(&p, &c).accepted);
}

#[test]
fn edited_denylist_replaces_only_the_lists_given() {
    let mut g = grant("scoped-instruction");
    g["kinds"] = json!(["deploy", "tests"]);
    let p = Policy::parse(
        &json!({"grants": [g],
                "denylist": {"enabled": true, "kinds": ["risky"], "commands": ["foo bar"]}})
        .to_string(),
    )
    .unwrap();
    // "deploy" is no longer denylisted, so the grant loads and the kind is accepted.
    let mut c = contract();
    c.kind = "deploy".into();
    assert!(eval(&p, &c).accepted);
    // The edited command list replaced the default one.
    assert_eq!(p.denied_command("rm -rf /"), None);
    assert!(p.denied_command("run FOO   bar now").is_some());
    let mut c = contract();
    c.text = "rm -rf the cache".into();
    assert!(eval(&p, &c).accepted);
    c.text = "do foo bar".into();
    assert!(!eval(&p, &c).accepted);
    // The paths list was not given, so the default stays.
    assert!(p.denied_path("a/.env").is_some());
    // The edited kinds are enforced at load.
    let mut g = grant("scoped-instruction");
    g["kinds"] = json!(["risky"]);
    assert!(
        parse_err(json!({"grants": [g], "denylist": {"kinds": ["risky"]}}))
            .contains("denylisted kind")
    );
}

#[test]
fn denylist_switched_off() {
    let mut g = grant("scoped-instruction");
    g["kinds"] = json!(["deploy"]);
    let p =
        Policy::parse(&json!({"grants": [g], "denylist": {"enabled": false}}).to_string()).unwrap();
    let mut c = contract();
    c.kind = "deploy".into();
    c.text = "rm -rf the cache, then git push --force".into();
    c.paths = vec!["src/a/k.pem".into()];
    assert!(eval(&p, &c).accepted);
    assert_eq!(p.denied_command("git push --force"), None);
    assert_eq!(p.denied_path(".env"), None);
}

#[test]
fn ttl_and_step_clamping() {
    let with = |ttl: Option<u64>, steps: Option<u64>| {
        let mut g = grant("scoped-instruction");
        if let Some(t) = ttl {
            g["max_ttl_secs"] = json!(t);
        }
        if let Some(s) = steps {
            g["max_steps"] = json!(s);
        }
        policy(vec![g])
    };
    let ask = |p: &Policy, ttl: u64, steps: u64| {
        let mut c = contract();
        c.ttl_secs = ttl;
        c.max_steps = steps;
        let d = eval(p, &c);
        assert!(d.accepted);
        (d.ttl_secs, d.max_steps)
    };
    // Grant defaults: 3600 s and 200 steps.
    let p = with(None, None);
    assert_eq!(ask(&p, 0, 0), (3600, 200));
    assert_eq!(ask(&p, 100, 7), (100, 7));
    assert_eq!(ask(&p, 14400, 1000), (3600, 200));
    // Grant maximums apply when the contract asks for more or nothing.
    let p = with(Some(600), Some(50));
    assert_eq!(ask(&p, 0, 0), (600, 50));
    assert_eq!(ask(&p, 5000, 5000), (600, 50));
    assert_eq!(ask(&p, 60, 5), (60, 5));
    // A grant maximum at the cap passes; the contract's own value may not exceed 14400.
    let p = with(Some(14400), None);
    assert_eq!(ask(&p, 0, 0).0, 14400);
    assert_eq!(ask(&p, 99999, 0).0, 14400);
    // A grant maximum above the cap is refused at load or clamped, never honoured.
    let big = json!({"grants": [{"from": ["alice@machine-a"], "repos": [REPO],
        "level": "scoped-instruction", "paths": ["src/a/**"], "kinds": ["tests"],
        "max_ttl_secs": 20000}]});
    if let Ok(p) = Policy::parse(&big.to_string()) {
        assert_eq!(ask(&p, 0, 0).0, 14400);
    }
}

#[test]
fn kill_switch_files() {
    let d = tmpdir();
    let f = d.join("policy.json");
    std::fs::write(&f, "{}").unwrap();
    let flag = d.join("policy.json.revoked");
    assert_eq!(
        delegation::audit_path(&f),
        d.join("policy.json.audit.jsonl")
    );
    assert!(!delegation::revoked(&f));
    delegation::revoke(&f).unwrap();
    assert!(delegation::revoked(&f));
    assert!(flag.exists());
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&flag).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    // Revoking twice is fine.
    delegation::revoke(&f).unwrap();
    delegation::resume(&f).unwrap();
    assert!(!delegation::revoked(&f));
    assert!(!flag.exists());
    delegation::resume(&f).unwrap();
}
