//! Amendment 1 to the delegation spec: normalised and case-insensitive path denies, argv-prefix
//! commands, tokenizer, wrappers and argv-aware destructive checks.

mod common;

use common::*;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};
use wormhole::daemon::DaemonHandle;
use wormhole::delegation::{tokenize, Level, Policy};
use wormhole::proto::Contract;

const REPO: &str = "example.com/team/proj";
const SA: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const SB: &str = "bbbbbbbb-0000-4000-8000-000000000002";

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

// ---- tokenize ----

#[test]
fn tokenize_words_quotes_and_escapes() {
    assert_eq!(
        tokenize("cargo test --lib").unwrap(),
        strs(&["cargo", "test", "--lib"])
    );
    assert_eq!(
        tokenize("  cargo \t test  ").unwrap(),
        strs(&["cargo", "test"])
    );
    assert_eq!(
        tokenize("git commit -m 'a b; c'").unwrap(),
        strs(&["git", "commit", "-m", "a b; c"])
    );
    assert_eq!(tokenize("echo 'a$b`c'").unwrap(), strs(&["echo", "a$b`c"]));
    assert_eq!(tokenize(r#"echo "a b""#).unwrap(), strs(&["echo", "a b"]));
    assert_eq!(
        tokenize(r#"echo "a \"b\" c""#).unwrap(),
        strs(&["echo", r#"a "b" c"#])
    );
    assert_eq!(tokenize(r#"echo "x\\y""#).unwrap(), strs(&["echo", r"x\y"]));
    assert_eq!(tokenize(r"echo a\ b").unwrap(), strs(&["echo", "a b"]));
    assert_eq!(tokenize(r"echo a\;b").unwrap(), strs(&["echo", "a;b"]));
    assert_eq!(tokenize(r#""git" push"#).unwrap(), strs(&["git", "push"]));
    assert_eq!(tokenize("ca'rgo' test").unwrap(), strs(&["cargo", "test"]));
}

#[test]
fn tokenize_refuses_what_a_shell_would_interpret() {
    for bad in ["", "   ", "echo 'abc", r#"echo "abc"#, "a\nb", "a\r\nb"] {
        assert!(tokenize(bad).is_err(), "{bad:?}");
    }
    for c in [';', '&', '|', '<', '>', '(', ')', '`', '$', '{', '}'] {
        for cmd in [
            format!("echo a{c}b"),
            format!("echo {c}"),
            format!("ls {c}"),
        ] {
            assert!(tokenize(&cmd).is_err(), "{cmd:?}");
        }
    }
    for bad in [
        "echo a && ls",
        "echo a || ls",
        "echo a | cat",
        "echo $(id)",
        "echo ${HOME}",
        "echo `id`",
        "ls > out",
        "cat < in",
        "(ls)",
        "ls &",
        // Substitution survives double quotes.
        r#"echo "$HOME""#,
        r#"echo "`id`""#,
        r#"echo "$(id)""#,
    ] {
        assert!(tokenize(bad).is_err(), "{bad:?}");
    }
    // Metacharacters inside single quotes, and harmless ones in double quotes, are text.
    assert!(tokenize("echo 'a;b|c&d'").is_ok());
    assert!(tokenize(r#"echo "a;b""#).is_ok());
}

// ---- command_allowed ----

fn pol() -> Policy {
    Policy::parse(r#"{"grants": [], "safe_programs": ["git", "cargo"]}"#).unwrap()
}

#[test]
fn command_allowed_matches_argv_prefixes() {
    let p = strs(&["cargo test"]);
    for ok in ["cargo test", "cargo   test"] {
        assert!(pol().command_allowed(&p, ok).is_ok(), "{ok}");
    }
    for bad in [
        "cargo test --lib",
        "'cargo' test",
        "cargo testx",
        "cargo build",
        "cargo",
        "",
        "cargo test; ls",
        "cargo test $(id)",
        "FOO=1 cargo test",
        "cargo test\nls",
    ] {
        assert!(pol().command_allowed(&p, bad).is_err(), "{bad:?}");
    }
    // Several prefixes: any one will do.
    let p = strs(&["cargo test", "cargo build"]);
    assert!(pol().command_allowed(&p, "cargo build").is_ok());
    assert!(pol().command_allowed(&p, "cargo build -q").is_err());
    assert!(pol().command_allowed(&p, "cargo check").is_err());
    assert!(pol().command_allowed(&[], "cargo test").is_err());
}

#[test]
fn wrappers_are_refused_by_base_name_even_when_listed() {
    let wrappers = [
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "fish",
        "csh",
        "tcsh",
        "eval",
        "exec",
        "env",
        "xargs",
        "sudo",
        "doas",
        "su",
        "nohup",
        "time",
        "command",
        "builtin",
        "source",
        ".",
        "nice",
        "timeout",
        "watch",
        "script",
        "parallel",
        "python",
        "python3",
        "perl",
        "ruby",
        "node",
        "osascript",
    ];
    for w in wrappers {
        for cmd in [format!("{w} x"), format!("/usr/bin/{w} x")] {
            let first = cmd.split(' ').next().unwrap();
            let prefixes = strs(&[w, first]);
            assert!(pol().command_allowed(&prefixes, &cmd).is_err(), "{cmd}");
        }
    }
    let p = strs(&["sh", "/bin/sh", "env"]);
    assert!(pol().command_allowed(&p, "sh -c 'ls'").is_err());
    assert!(pol().command_allowed(&p, "/bin/sh -c ls").is_err());
    assert!(pol().command_allowed(&p, "env FOO=1 ls").is_err());
    // A program that merely starts like a wrapper is fine.
    // Not a wrapper, but not a safe program either unless the owner adds it.
    assert!(pol()
        .command_allowed(&strs(&["shellcheck x.sh"]), "shellcheck x.sh")
        .is_err());
    let added = Policy::parse(r#"{"grants": [], "safe_programs": ["shellcheck"]}"#).unwrap();
    assert!(added
        .command_allowed(&strs(&["shellcheck x.sh"]), "shellcheck x.sh")
        .is_ok());
}

// ---- Policy::denied_argv, denied_path ----

fn grant(level: &str) -> Value {
    json!({"from": ["alice@machine-a"], "repos": [REPO], "level": level,
           "paths": ["**"], "kinds": ["*"]})
}

fn policy(g: Value) -> Policy {
    Policy::parse(&json!({"grants": [g], "safe_programs": ["git", "cargo"]}).to_string()).unwrap()
}

#[test]
fn denied_argv_catches_flag_spellings_refspecs_quoting_and_clusters() {
    let p = policy(grant("scoped-instruction"));
    for cmd in [
        "git push -f",
        "git push --force",
        "git push --force-with-lease",
        "git push --force-with-lease=main",
        "git push --force-if-includes",
        "git push origin +main",
        "git push origin :main",
        "git push --delete origin b",
        "git push -d origin b",
        "git push --mirror",
        "git push --prune origin",
        "git push -fu origin main",
        "git -C x push -fu",
        "git -c core.x=1 push --force",
        "git --no-pager push -f",
        "git --git-dir=x --work-tree=y push -f",
        r#""git" push --force"#,
        "git branch -D x",
        "git branch -d x",
        "git branch --delete x",
        "git reset --hard",
        "git reset --hard HEAD~1",
        "git clean -f",
        "git clean -fd",
        "git clean --force",
        "git merge topic",
        "git filter-branch --all",
        "git update-ref -d refs/heads/x",
        "gh pr merge 3",
        "gh release create v1",
        "gh repo delete x",
        "rm -rf x",
        "rm -fr x",
        "rm -r -f x",
        "rm -R --force x",
        "rm --recursive -f x",
        "kubectl get pods",
        "terraform plan",
        "helm install x",
        "npm publish",
        "cargo publish",
        "twine upload dist/*",
        "curl example.com",
        "wget example.com",
        "ssh host",
        "scp a b",
        "sendmail x",
        "mail x",
        "printenv",
        "security find-generic-password",
        // An untokenisable command counts as denied.
        "echo 'unterminated",
        "ls; id",
        "",
    ] {
        assert!(p.denied_argv(cmd).is_some(), "should be denied: {cmd:?}");
    }
    for cmd in [
        "git push",
        "git push origin main",
        "git push -u origin main",
        "git status",
        "git branch",
        "git branch -a",
        "git reset --soft HEAD~1",
        "git clean -n",
        "git commit -m 'drop table x'",
        "rm file",
        "rm -r dir",
        "rm -f file",
        "cargo test --lib",
        "cargo build",
        "npm test",
        "gh pr view 3",
        "ls -la",
    ] {
        assert_eq!(p.denied_argv(cmd), None, "should pass: {cmd:?}");
    }
}

#[test]
fn denied_argv_is_off_with_the_module() {
    let p = Policy::parse(
        &json!({"grants": [grant("scoped-instruction")], "denylist": {"enabled": false}})
            .to_string(),
    )
    .unwrap();
    assert_eq!(p.denied_argv("git push -f"), None);
    assert_eq!(p.denied_argv("echo 'unterminated"), None);
}

#[test]
fn denied_path_is_case_insensitive() {
    let p = policy(grant("scoped-instruction"));
    for path in [
        "SECRETS/x",
        "src/.ENV",
        "src/.Env.Local",
        "KEY.PEM",
        "a/Id_RSA",
        "x/.GIT/config",
        "x/.SSH/k",
    ] {
        assert!(p.denied_path(path).is_some(), "{path}");
    }
    for path in ["src/main.rs", "src/Secretary.rs", "docs/ENV.md"] {
        assert_eq!(p.denied_path(path), None, "{path}");
    }
}

// ---- acceptance ----

fn contract(paths: &[&str]) -> Contract {
    Contract {
        task_id: "T-1".into(),
        kind: "tests".into(),
        paths: strs(paths),
        exit: "tests pass".into(),
        text: "add tests".into(),
        ..Default::default()
    }
}

fn eval(p: &Policy, c: &Contract) -> wormhole::delegation::Decision {
    p.evaluate("alice", "machine-a", REPO, c)
}

#[test]
fn acceptance_refuses_denied_and_unanchored_scopes_at_every_scoped_level() {
    for level in ["scoped-instruction", "scoped-bypass", "full-bypass"] {
        let p = policy(grant(level));
        for path in [
            "secrets/**",
            ".git/",
            "src/*/.env",
            "SECRETS/x",
            "src/.ENV",
            "keys/server.pem",
            "**",
            "*",
            "*.rs",
            "**/x",
            "src/../.env",
        ] {
            let d = eval(&p, &contract(&[path]));
            assert!(!d.accepted, "{level}: {path}");
            assert_eq!(d.level, Level::Inform, "{level}: {path}");
            if !path.contains("..") {
                assert!(
                    d.reason.contains(path)
                        || d.reason.to_lowercase().contains(&path.to_lowercase()),
                    "{level}: {path}: {}",
                    d.reason
                );
            }
        }
        // One bad path refuses the whole contract.
        assert!(
            !eval(&p, &contract(&["src/a.rs", "**"])).accepted,
            "{level}"
        );
        // Anchored, non-denied scopes pass, including after normalisation.
        for path in ["src/**", "src/a.rs", "./src/a.rs", "src//a.rs", "docs/"] {
            let d = eval(&p, &contract(&[path]));
            assert!(d.accepted, "{level}: {path}: {}", d.reason);
        }
    }
}

#[test]
fn an_empty_path_after_normalisation_is_not_accepted() {
    let p = policy(grant("scoped-instruction"));
    for path in ["./", "", "/", ".//"] {
        assert!(!eval(&p, &contract(&[path])).accepted, "{path:?}");
    }
}

#[test]
fn unanchored_and_denied_scopes_are_accepted_when_the_module_is_off() {
    let p = Policy::parse(
        &json!({"grants": [grant("scoped-instruction")], "denylist": {"enabled": false}})
            .to_string(),
    )
    .unwrap();
    assert!(eval(&p, &contract(&["secrets/**", "**"])).accepted);
}

#[test]
fn acceptance_checks_contract_command_prefixes() {
    let mut g = grant("scoped-bypass");
    g["commands"] = json!(["cargo test", "git status *"]);
    let p = policy(g.clone());
    let with = |cmds: &[&str]| {
        let mut c = contract(&["src/a.rs"]);
        c.commands = strs(cmds);
        eval(&p, &c)
    };
    for ok in [&["cargo test"][..], &["cargo test", "git status *"], &[]] {
        let d = with(ok);
        assert!(
            d.accepted && d.level == Level::ScopedBypass,
            "{ok:?}: {}",
            d.reason
        );
    }
    for bad in [
        "cargo test --lib",
        "git push origin main",
        "cargo testx",
        "cargo build",
        "cargo",
        "sh -c 'cargo test'",
        "cargo test; ls",
        "FOO=1 cargo test",
        "env cargo test",
        "make",
    ] {
        assert!(!with(&[bad]).accepted, "{bad}");
    }
    // The grant value "*" alone accepts any contract prefix, but never a wrapper or untokenisable one.
    g["commands"] = json!(["*"]);
    let p = policy(g);
    let with = |cmd: &str| {
        let mut c = contract(&["src/a.rs"]);
        c.commands = vec![cmd.into()];
        eval(&p, &c)
    };
    assert!(with("ls src").accepted);
    for bad in [
        "sh -c ls",
        "/bin/bash",
        "python3 x.py",
        "make; id",
        "FOO=1 make",
        "sudo make",
    ] {
        assert!(!with(bad).accepted, "{bad}");
    }
}

// ---- end to end ----

const NOTICE: &str = "[wormhole delegation] request";

fn id() -> String {
    let d = tmpdir();
    wormhole::repo::find(&make_repo(&d.join("r"))).unwrap().id
}

async fn setup(paths: &str, commands: Value) -> Net {
    let path = tmpdir().join("policy.json");
    let g = json!({"from": ["alice@machine-a"], "repos": [id()], "task_ids": ["SB-*"],
        "level": "scoped-bypass", "paths": [paths], "kinds": ["fix"], "commands": commands});
    std::fs::write(
        &path,
        json!({"grants": [g], "safe_programs": ["git", "cargo"]}).to_string(),
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

async fn allowed(d: &DaemonHandle, input: Value) -> bool {
    decision(&hook(d, input).await).as_deref() == Some("allow")
}

async fn delegate(n: &Net, task: &str, extra: Value) -> Result<String, String> {
    let mut a =
        json!({"to_session": SB, "to": SB, "task_id": task, "kind": "fix", "text": "do it"});
    for (k, v) in extra.as_object().unwrap() {
        a[k] = v.clone();
    }
    tool(&n.a, SA, "delegate", a).await
}

#[tokio::test]
async fn bypass_hook_checks_each_concrete_path_and_argv() {
    let n = setup("src/**", json!(["cargo test", "git status *"])).await;
    delegate(
        &n,
        "SB-1",
        json!({"paths": ["src/**"], "exit": "done", "commands": ["cargo test", "git status *"]}),
    )
    .await
    .unwrap();
    let c = next_ctx(&n.b, SB, &n.repo_b, |c| c.contains(NOTICE)).await;
    assert!(c.contains("status: accepted"), "{c}");

    assert!(allowed(&n.b, pre_edit(SB, &n.repo_b, "src/ok.rs")).await);
    for f in [
        "src/secrets/a.rs",
        "src/.ENV",
        "src/.env",
        "src/Secrets/b.rs",
        "src/k.PEM",
    ] {
        assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, f)).await, "{f}");
    }
    assert!(allowed(&n.b, pre_bash(&n.repo_b, "cargo test")).await);
    assert!(allowed(&n.b, pre_bash(&n.repo_b, "git status src")).await);
    for cmd in [
        "git push -f",
        "git push --force-with-lease",
        "git push origin +main",
        "git push origin :main",
        "git -C x push -fu",
        r#""git" push --force"#,
        "cargo testx",
        "cargo build",
        "FOO=1 cargo test",
        "sh -c 'cargo test'",
        "/bin/sh -c 'cargo test'",
        "cargo test; id",
        "cargo test $(id)",
    ] {
        assert!(!allowed(&n.b, pre_bash(&n.repo_b, cmd)).await, "{cmd:?}");
    }
}

#[tokio::test]
async fn unanchored_or_denied_contract_paths_are_information_only_end_to_end() {
    let n = setup("**", json!(["cargo test"])).await;
    for (i, path) in ["**", "secrets/**", ".git/", "*.rs", "src/*/.env"]
        .iter()
        .enumerate()
    {
        let task = format!("SB-{}", i + 1);
        delegate(&n, &task, json!({"paths": [path], "exit": "done"}))
            .await
            .unwrap();
        let c = next_ctx(&n.b, SB, &n.repo_b, |c| {
            c.contains(NOTICE) && c.contains(&task)
        })
        .await;
        assert!(c.contains("information only"), "{path}: {c}");
        assert!(!c.contains("status: accepted"), "{path}: {c}");
    }
    assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, "src/a.rs")).await);
    // An anchored scope in the same grant is accepted.
    delegate(&n, "SB-9", json!({"paths": ["src/**"], "exit": "done"}))
        .await
        .unwrap();
    let c = next_ctx(&n.b, SB, &n.repo_b, |c| {
        c.contains(NOTICE) && c.contains("SB-9")
    })
    .await;
    assert!(c.contains("status: accepted"), "{c}");
    assert!(allowed(&n.b, pre_edit(SB, &n.repo_b, "src/a.rs")).await);
    assert!(!allowed(&n.b, pre_edit(SB, &n.repo_b, "src/secrets/a.rs")).await);
}

#[tokio::test]
async fn an_unsafe_contract_command_is_information_only_end_to_end() {
    let n = setup("src/**", json!(["cargo test"])).await;
    delegate(
        &n,
        "SB-1",
        json!({"paths": ["src/**"], "exit": "done", "commands": ["sh -c 'cargo test'"]}),
    )
    .await
    .unwrap();
    let c = next_ctx(&n.b, SB, &n.repo_b, |c| {
        c.contains(NOTICE) && c.contains("SB-1")
    })
    .await;
    assert!(c.contains("information only"), "{c}");
    assert!(!allowed(&n.b, pre_bash(&n.repo_b, "cargo test")).await);
}

#[tokio::test]
async fn the_hub_refuses_empty_and_dot_paths() {
    let n = setup("src/**", json!(["cargo test"])).await;
    delegate(&n, "SB-1", json!({"paths": ["src/a.rs"], "exit": "done"}))
        .await
        .unwrap();
    for bad in ["", "./", "/", ".//"] {
        let e = delegate(&n, "SB-2", json!({"paths": [bad], "exit": "done"}))
            .await
            .unwrap_err();
        // "/" is refused by the daemon (outside the repository) before the hub sees it.
        assert!(
            e.contains("invalid") || e.contains("outside the repository"),
            "{bad:?}: {e}"
        );
    }
}
