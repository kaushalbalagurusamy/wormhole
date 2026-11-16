//! Bounded rollback and downgrade reporting (spec Amendment 1, ADR 0003 amendment). Real git
//! repositories in temporary directories and a fake build, as in tests/auto_update.rs.

mod common;

use common::*;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use wormhole::daemon::{self, DaemonHandle};
use wormhole::hub::HubHandle;
use wormhole::proto::{DaemonInfo, Request};
use wormhole::update::UpdateConfig;

const OLD_BIN: &str = "#!/bin/sh\necho \"wormhole OLD-BINARY\"\n";
const MISSING: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const BELOW_MIN: &str = "refused: below minimum safe commit";
const BELOW_FLOOR: &str = "refused: below local floor";

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn commit(dev: &Path, content: &str) -> String {
    std::fs::write(dev.join("f.txt"), content).unwrap();
    git(dev, &["add", "f.txt", ".gitignore"]);
    git(dev, &["commit", "-q", "-m", content]);
    git(dev, &["rev-parse", "HEAD"])
}

struct World {
    dir: PathBuf,
    src: PathBuf,
    bin: PathBuf,
    build_log: PathBuf,
    target_file: PathBuf,
    /// Four commits on main, the daemon's clone at the last.
    c: Vec<String>,
}

fn world() -> World {
    let dir = tmpdir();
    let (origin, dev, src) = (dir.join("origin.git"), dir.join("dev"), dir.join("src"));
    std::fs::create_dir_all(&dev).unwrap();
    git(&dir, &["init", "-q", "--bare", "origin.git"]);
    git(&origin, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    git(&dev, &["init", "-q"]);
    git(&dev, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    for (k, v) in [
        ("user.name", "Test Author"),
        ("user.email", "author@example.com"),
        ("commit.gpgsign", "false"),
    ] {
        git(&dev, &["config", k, v]);
    }
    std::fs::write(dev.join(".gitignore"), "target/\n").unwrap();
    let c: Vec<String> = ["one", "two", "three", "four"]
        .iter()
        .map(|n| commit(&dev, n))
        .collect();
    git(&dev, &["remote", "add", "origin", origin.to_str().unwrap()]);
    git(&dev, &["push", "-q", "origin", "main"]);
    git(&dir, &["clone", "-q", origin.to_str().unwrap(), "src"]);
    let bindir = dir.join("bin");
    std::fs::create_dir_all(&bindir).unwrap();
    let bin = bindir.join("wormhole");
    std::fs::write(&bin, OLD_BIN).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    World {
        build_log: dir.join("build.log"),
        target_file: dir.join("target"),
        dir,
        src,
        bin,
        c,
    }
}

fn build_count(w: &World) -> usize {
    std::fs::read_to_string(&w.build_log)
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

fn version(bin: &Path) -> String {
    let o = Command::new(bin).arg("version").output().unwrap();
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// A hub announcing `target`, and alice with an updater whose minimum is `min_safe` and whose
/// local floor is `floor`.
async fn start(
    w: &World,
    min_safe: &str,
    floor: Option<&str>,
    target: &str,
) -> (HubHandle, DaemonHandle) {
    std::fs::write(&w.target_file, format!("{target}\n")).unwrap();
    let hub = start_hub_with(
        &w.dir,
        &Opts {
            target_file: Some(w.target_file.clone()),
            ..Opts::default()
        },
    )
    .await;
    let mut c = daemon_config(
        &w.dir,
        format!("ws://{}/ws", hub.addr),
        "alice@machine-a",
        &Opts::default(),
    );
    let mut u = UpdateConfig::new(w.src.clone(), w.bin.clone());
    let log = w.build_log.display();
    u.build = Some(vec![
        "sh".into(),
        "-c".into(),
        format!(
            "echo built >> '{log}' && mkdir -p target/release && c=$(git rev-parse HEAD) && \
             printf '#!/bin/sh\\necho \"wormhole %s\"\\n' \"$c\" > target/release/wormhole && \
             chmod 755 target/release/wormhole"
        ),
    ]);
    u.min_interval = Duration::from_millis(300);
    u.quiet = Duration::from_millis(100);
    u.exit_after_install = false;
    u.min_safe = min_safe.to_string();
    u.floor = floor.map(str::to_string);
    c.auto_update = Some(u);
    let a = daemon::start(c).await.unwrap();
    wait_connected(&a).await;
    (hub, a)
}

async fn info(hub: &HubHandle, user: &str) -> Option<Value> {
    api_state(hub).await["daemons"]
        .as_array()?
        .iter()
        .find(|d| d["user"] == user)
        .cloned()
}

async fn wait_status(hub: &HubHandle, w: &World, prefix: &str) -> String {
    eventually(30, || async {
        let s = info(hub, "alice").await?["status"].as_str()?.to_string();
        assert!(
            !s.contains(w.dir.to_str().unwrap()),
            "status names a path: {s}"
        );
        s.starts_with(prefix).then_some(s)
    })
    .await
}

/// The refusal `want` for `target`, with the binary and the clone untouched and nothing built.
async fn refuses(w: &World, min_safe: &str, floor: Option<&str>, target: &str, want: &str) {
    let (hub, _a) = start(w, min_safe, floor, target).await;
    wait_status(&hub, w, want).await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    let s = info(&hub, "alice").await.unwrap()["status"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(s.starts_with(want), "{s}");
    assert_eq!(std::fs::read(&w.bin).unwrap(), OLD_BIN.as_bytes());
    assert!(!wormhole::update::prev_path(&w.bin).exists());
    assert_eq!(build_count(w), 0, "built a refused target");
    assert_eq!(
        git(&w.src, &["rev-parse", "HEAD"]),
        w.c[3],
        "checked out a refused target"
    );
}

async fn installs(
    w: &World,
    min_safe: &str,
    floor: Option<&str>,
    target: &str,
) -> (HubHandle, DaemonHandle) {
    let (hub, a) = start(w, min_safe, floor, target).await;
    wait_status(&hub, w, "installed").await;
    assert_eq!(version(&w.bin), format!("wormhole {target}"));
    (hub, a)
}

#[tokio::test]
async fn a_target_below_the_minimum_safe_commit_is_refused_and_one_at_or_above_installs() {
    let w = world();
    refuses(&w, &w.c[2], None, &w.c[1], BELOW_MIN).await;
    // Anything above the minimum is allowed (a fresh repository, so its own commits).
    let w2 = world();
    let (min, t) = (w2.c[1].clone(), w2.c[2].clone());
    installs(&w2, &min, None, &t).await;
}

#[tokio::test]
async fn the_minimum_itself_is_a_valid_target() {
    let w = world();
    let (min, t) = (w.c[1].clone(), w.c[1].clone());
    installs(&w, &min, None, &t).await;
}

#[tokio::test]
async fn a_minimum_that_is_not_a_commit_in_the_clone_fails_closed() {
    let w = world();
    refuses(&w, MISSING, None, &w.c[3], BELOW_MIN).await;
}

#[tokio::test]
async fn a_local_floor_above_the_target_refuses_and_without_it_the_target_installs() {
    let w = world();
    refuses(&w, &w.c[0], Some(&w.c[2]), &w.c[1], BELOW_FLOOR).await;
    let w2 = world();
    let t = w2.c[1].clone();
    installs(&w2, &w2.c[0].clone(), None, &t).await;
    // And a floor at or below the target does not stand in the way.
    let w3 = world();
    let (m, f, t) = (w3.c[0].clone(), w3.c[1].clone(), w3.c[1].clone());
    installs(&w3, &m, Some(&f), &t).await;
}

#[tokio::test]
async fn a_floor_below_the_minimum_does_not_lower_it() {
    let w = world();
    // c[1] is above the floor c[0] and below the minimum c[2]: the minimum's refusal wins.
    refuses(&w, &w.c[2], Some(&w.c[0]), &w.c[1], BELOW_MIN).await;
    // Both bounds apply: above the minimum but below the floor is the floor's refusal.
    let w = world();
    refuses(&w, &w.c[0], Some(&w.c[3]), &w.c[2], BELOW_FLOOR).await;
}

#[tokio::test]
async fn a_floor_that_is_not_a_commit_in_the_clone_refuses() {
    let w = world();
    refuses(&w, &w.c[0], Some(MISSING), &w.c[3], BELOW_FLOOR).await;
}

#[tokio::test]
async fn a_downgrade_is_reported_in_the_status_the_page_the_event_and_who() {
    let w = world();
    let t = w.c[1].clone();
    let (hub, a) = start(&w, &w.c[0], None, "").await;
    // No target yet: not a downgrade.
    wait_status(&hub, &w, "current").await;
    assert_ne!(info(&hub, "alice").await.unwrap()["downgrade"], true);
    assert!(!api_state(&hub).await["events"]
        .to_string()
        .contains("daemon.downgrade"));

    // The running commit is the real build, which this temporary repository does not contain, so
    // any target here is not a descendant of it.
    std::fs::write(&w.target_file, format!("{t}\n")).unwrap();
    let s = eventually(30, || async {
        let s = info(&hub, "alice").await?["status"].as_str()?.to_string();
        s.contains("downgrade").then_some(s)
    })
    .await;
    assert!(!s.contains(w.dir.to_str().unwrap()), "{s}");
    wait_status(&hub, &w, "installed").await;
    let i = info(&hub, "alice").await.unwrap();
    assert!(i["status"].as_str().unwrap().contains("downgrade"), "{i}");
    assert_eq!(i["downgrade"], true, "{i}");
    assert_eq!(version(&w.bin), format!("wormhole {t}"));

    let events: Vec<Value> = api_state(&hub).await["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "daemon.downgrade")
        .cloned()
        .collect();
    assert!(!events.is_empty(), "no daemon.downgrade event");
    for e in &events {
        assert_eq!(
            (e["user"].as_str(), e["machine"].as_str()),
            (Some("alice"), Some("machine-a"))
        );
        assert_eq!(e["data"]["commit"], wormhole::COMMIT);
        assert_eq!(e["data"]["target"], t);
        assert!(
            e["data"]["status"].as_str().unwrap().contains("downgrade"),
            "{e}"
        );
    }
    // The newest event carries the final status.
    assert_eq!(events.last().unwrap()["data"]["status"], i["status"]);

    let repo = make_repo(&w.dir.join("a/proj"));
    hook(&a, session_start(SA, &repo)).await;
    let who = tool(&a, SA, "who", json!({})).await.unwrap();
    let line = who
        .lines()
        .find(|l| l.contains("alice@machine-a") && l.contains("commit "))
        .unwrap_or_else(|| panic!("no daemon line: {who}"));
    assert!(line.contains("DOWNGRADE"), "{line}");
}

#[tokio::test]
async fn the_hub_emits_daemon_downgrade_once_per_change_under_the_connections_identity() {
    let hub = start_hub(&tmpdir()).await;
    let mut u = Raw::connect(hub.addr, "uma@machine-u", &["update"]).await;
    let (c, t) = ("1".repeat(40), "2".repeat(40));
    let events = |state: Value| -> Vec<Value> {
        state["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["kind"] == "daemon.downgrade")
            .cloned()
            .collect()
    };
    let report = |status: &str, downgrade: bool| {
        json!({"type": "daemon_status", "commit": c, "target": t, "status": status,
               "downgrade": downgrade, "user": "mallory", "machine": "evil"})
    };
    // Not a downgrade: no event.
    u.req(report("building", false)).await.unwrap();
    assert!(events(api_state(&hub).await).is_empty());

    u.req(report("building (downgrade)", true)).await.unwrap();
    let ev = events(api_state(&hub).await);
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!(
        (ev[0]["user"].as_str(), ev[0]["machine"].as_str()),
        (Some("uma"), Some("machine-u"))
    );
    assert_eq!(ev[0]["data"]["commit"], c);
    assert_eq!(ev[0]["data"]["target"], t);
    assert_eq!(ev[0]["data"]["status"], "building (downgrade)");

    // An identical repeat is not a change.
    u.req(report("building (downgrade)", true)).await.unwrap();
    assert_eq!(events(api_state(&hub).await).len(), 1);
    // A new status is.
    u.req(report("installed (downgrade)", true)).await.unwrap();
    let ev = events(api_state(&hub).await);
    assert_eq!(ev.len(), 2, "{ev:?}");
    assert_eq!(ev[1]["data"]["status"], "installed (downgrade)");
    // So is a new target.
    u.req(
        json!({"type": "daemon_status", "commit": c, "target": "3".repeat(40),
                 "status": "installed (downgrade)", "downgrade": true}),
    )
    .await
    .unwrap();
    assert_eq!(events(api_state(&hub).await).len(), 3);
    // The row is marked on the page's data.
    let d = api_state(&hub).await["daemons"][0].clone();
    assert_eq!(
        (d["user"].as_str(), d["downgrade"].as_bool()),
        (Some("uma"), Some(true))
    );
    // Leaving the downgrade clears the mark and adds no event.
    u.req(report("current", false)).await.unwrap();
    assert_eq!(events(api_state(&hub).await).len(), 3);
    assert_eq!(
        api_state(&hub).await["daemons"][0]["downgrade"].as_bool(),
        Some(false)
    );
}

#[test]
fn a_report_from_before_the_amendment_has_no_downgrade() {
    let old = r#"{"type":"daemon_status","commit":"a","target":"","status":"current"}"#;
    match serde_json::from_str::<Request>(old).unwrap() {
        Request::DaemonStatus { downgrade, .. } => assert!(!downgrade),
        other => panic!("{other:?}"),
    }
    let info: DaemonInfo = serde_json::from_str(
        r#"{"user":"a","machine":"m","commit":"c","target":"","status":"s","ts":1}"#,
    )
    .unwrap();
    assert!(!info.downgrade);
}
