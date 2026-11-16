//! Hub-announced target build and daemon self-update (slice team-log-v1, spec section F and ADR
//! 0003). Real git repositories (a bare origin, a developer clone and the daemon's own clone) in
//! temporary directories; the build is a fake argv that writes a shell script as the artifact.
//! Nothing here installs a real binary or lets a daemon exit: `exit_after_install` is false.

mod common;

use common::*;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use wormhole::daemon::{self, DaemonConfig, DaemonHandle};
use wormhole::delegation;
use wormhole::hub::HubHandle;
use wormhole::proto::Snapshot;
use wormhole::update::{self, UpdateConfig};

const OLD_BIN: &str = "#!/bin/sh\necho \"wormhole OLD-BINARY\"\n";
const SHA1: &str = "1111111111111111111111111111111111111111";
const SHA2: &str = "2222222222222222222222222222222222222222";
const SHA3: &str = "3333333333333333333333333333333333333333";
const SHA4: &str = "abcdefabcdefabcdefabcdefabcdefabcdefabcd";

/// Run git with no global or system configuration, so a developer's settings cannot leak in.
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
        "git {args:?} in {}: {}",
        dir.display(),
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
    origin: PathBuf,
    dev: PathBuf,
    src: PathBuf,
    bin: PathBuf,
    build_log: PathBuf,
    target_file: PathBuf,
    /// Commits one to three on main, the daemon's clone being at the third.
    c: Vec<String>,
}

fn write_bin(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn world() -> World {
    let dir = tmpdir();
    let origin = dir.join("origin.git");
    let dev = dir.join("dev");
    let src = dir.join("src");
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
    // The build writes target/, as cargo does; a real clone ignores it.
    std::fs::write(dev.join(".gitignore"), "target/\n").unwrap();
    let c = vec![
        commit(&dev, "one"),
        commit(&dev, "two"),
        commit(&dev, "three"),
    ];
    git(&dev, &["remote", "add", "origin", origin.to_str().unwrap()]);
    git(&dev, &["push", "-q", "origin", "main"]);
    git(&dir, &["clone", "-q", origin.to_str().unwrap(), "src"]);
    let bindir = dir.join("bin");
    std::fs::create_dir_all(&bindir).unwrap();
    let bin = bindir.join("wormhole");
    write_bin(&bin, OLD_BIN);
    World {
        build_log: dir.join("build.log"),
        target_file: dir.join("target"),
        dir,
        origin,
        dev,
        src,
        bin,
        c,
    }
}

/// A new commit on main, pushed to the origin.
fn push(w: &World, content: &str) -> String {
    let c = commit(&w.dev, content);
    git(&w.dev, &["push", "-q", "origin", "main"]);
    c
}

/// A commit that is on a side branch of the origin and not on main.
fn push_side(w: &World) -> String {
    git(&w.dev, &["checkout", "-q", "-b", "side"]);
    let c = commit(&w.dev, "side");
    git(&w.dev, &["push", "-q", "origin", "side"]);
    git(&w.dev, &["checkout", "-q", "main"]);
    c
}

fn set_target(w: &World, content: &str) {
    let tmp = w.dir.join("target.tmp");
    std::fs::write(&tmp, format!("{content}\n")).unwrap();
    std::fs::rename(tmp, &w.target_file).unwrap();
}

#[derive(Clone, Copy)]
enum Build {
    Ok,
    Fail,
    WrongCommit,
}

fn build_argv(kind: Build, log: &Path) -> Vec<String> {
    let log = log.display();
    let script = match kind {
        Build::Ok => format!(
            "echo built >> '{log}' && mkdir -p target/release && c=$(git rev-parse HEAD) && \
             printf '#!/bin/sh\\necho \"wormhole %s\"\\n' \"$c\" > target/release/wormhole && \
             chmod 755 target/release/wormhole"
        ),
        Build::Fail => format!("echo built >> '{log}'; exit 3"),
        Build::WrongCommit => format!(
            "echo built >> '{log}' && mkdir -p target/release && \
             printf '#!/bin/sh\\necho \"wormhole 0000000000000000000000000000000000000001\"\\n' > target/release/wormhole && \
             chmod 755 target/release/wormhole"
        ),
    };
    vec!["sh".into(), "-c".into(), script]
}

fn build_count(w: &World) -> usize {
    std::fs::read_to_string(&w.build_log)
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

fn daemon_for(
    w: &World,
    hub: &HubHandle,
    who: &str,
    build: Option<Build>,
    min_ms: u64,
    policy: Option<PathBuf>,
) -> DaemonConfig {
    let mut c = daemon_config(
        &w.dir,
        format!("ws://{}/ws", hub.addr),
        who,
        &Opts::default(),
    );
    c.delegation_policy = policy;
    if let Some(b) = build {
        let mut u = UpdateConfig::new(w.src.clone(), w.bin.clone());
        u.build = Some(build_argv(b, &w.build_log));
        u.min_interval = Duration::from_millis(min_ms);
        u.quiet = Duration::from_millis(100);
        u.exit_after_install = false;
        c.auto_update = Some(u);
    }
    c
}

/// A hub reading its target from `w.target_file`, and daemon alice with an updater.
async fn start(
    w: &World,
    build: Build,
    min_ms: u64,
    pre_target: Option<&str>,
) -> (HubHandle, DaemonHandle) {
    start_with(w, build, min_ms, pre_target, None).await
}

async fn start_with(
    w: &World,
    build: Build,
    min_ms: u64,
    pre_target: Option<&str>,
    policy: Option<PathBuf>,
) -> (HubHandle, DaemonHandle) {
    if let Some(t) = pre_target {
        set_target(w, t);
    }
    let hub = start_hub_with(
        &w.dir,
        &Opts {
            target_file: Some(w.target_file.clone()),
            ..Opts::default()
        },
    )
    .await;
    let a = daemon::start(daemon_for(
        w,
        &hub,
        "alice@machine-a",
        Some(build),
        min_ms,
        policy,
    ))
    .await
    .unwrap();
    wait_connected(&a).await;
    (hub, a)
}

/// The hub's record of `user`'s daemon.
async fn info(hub: &HubHandle, user: &str) -> Option<Value> {
    api_state(hub).await["daemons"]
        .as_array()?
        .iter()
        .find(|d| d["user"] == user)
        .cloned()
}

/// Wait until `user`'s status starts with `prefix`; a status that names a local path fails.
async fn wait_status(hub: &HubHandle, w: &World, user: &str, prefix: &str) -> String {
    eventually(30, || async {
        let s = info(hub, user).await?["status"].as_str()?.to_string();
        assert!(
            !s.contains(w.dir.to_str().unwrap()),
            "status names a local path: {s}"
        );
        s.starts_with(prefix).then_some(s)
    })
    .await
}

fn version(bin: &Path) -> String {
    let o = Command::new(bin).arg("version").output().unwrap();
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn bytes(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap()
}

fn untouched(w: &World) {
    assert_eq!(bytes(&w.bin), OLD_BIN.as_bytes(), "the binary was modified");
    assert!(
        !update::prev_path(&w.bin).exists(),
        "a .prev was written without a swap"
    );
    let mut names: Vec<String> = std::fs::read_dir(w.bin.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    assert_eq!(names, ["wormhole"], "stray files beside the binary");
}

fn short(s: &str) -> String {
    s.chars().take(12).collect()
}

#[tokio::test]
async fn a_new_main_commit_is_built_swapped_kept_and_reported() {
    let w = world();
    let t = push(&w, "four");
    let (hub, _a) = start(&w, Build::Ok, 300, None).await;
    // No target: nothing to do.
    wait_status(&hub, &w, "alice", "current").await;
    assert_eq!(build_count(&w), 0);
    untouched(&w);

    set_target(&w, &t);
    wait_status(&hub, &w, "alice", "installed").await;
    assert_eq!(build_count(&w), 1);
    assert_ne!(bytes(&w.bin), OLD_BIN.as_bytes());
    assert_eq!(version(&w.bin), format!("wormhole {t}"));
    // The previous binary is kept, byte for byte, and still runs.
    assert_eq!(bytes(&update::prev_path(&w.bin)), OLD_BIN.as_bytes());
    assert_eq!(version(&update::prev_path(&w.bin)), "wormhole OLD-BINARY");
    assert_eq!(
        std::fs::metadata(&w.bin).unwrap().permissions().mode() & 0o777,
        0o755
    );
    // Nothing but the binary and its .prev is left beside it (no temporary files).
    let mut names: Vec<String> = std::fs::read_dir(w.bin.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    assert_eq!(names, ["wormhole", "wormhole.prev"]);
    // The clone is at the target, detached.
    assert_eq!(git(&w.src, &["rev-parse", "HEAD"]), t);
    // The hub knows the running commit, the target and the status.
    let i = info(&hub, "alice").await.unwrap();
    assert_eq!(i["commit"], wormhole::COMMIT);
    assert_eq!(i["target"], t);
    assert_eq!(i["machine"], "machine-a");
}

#[tokio::test]
async fn a_target_that_is_already_on_the_hub_at_connect_time_is_followed_too() {
    let w = world();
    let t = push(&w, "four");
    let (hub, _a) = start(&w, Build::Ok, 300, Some(&t)).await;
    wait_status(&hub, &w, "alice", "installed").await;
    assert_eq!(version(&w.bin), format!("wormhole {t}"));
}

#[tokio::test]
async fn an_older_commit_on_main_installs_as_a_rollback() {
    let w = world();
    let (hub, _a) = start(&w, Build::Ok, 300, Some(&w.c[0])).await;
    wait_status(&hub, &w, "alice", "installed").await;
    assert_eq!(version(&w.bin), format!("wormhole {}", w.c[0]));
    assert_eq!(git(&w.src, &["rev-parse", "HEAD"]), w.c[0]);
    assert_eq!(bytes(&update::prev_path(&w.bin)), OLD_BIN.as_bytes());
}

/// Create a world, let `prep` change it and name the target, run the daemon on it and wait for a
/// status starting with `want`. The binary must be untouched.
async fn refused(
    prep: impl FnOnce(&World) -> String,
    build: Build,
    want: &str,
) -> (World, HubHandle, DaemonHandle) {
    let w = world();
    let target = prep(&w);
    let (hub, a) = start(&w, build, 300, Some(&target)).await;
    let s = wait_status(&hub, &w, "alice", want).await;
    // The status stays: nothing else happens to the binary afterwards either.
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        info(&hub, "alice").await.unwrap()["status"]
            .as_str()
            .unwrap()
            .starts_with(want),
        "{s}"
    );
    assert_eq!(bytes(&w.bin), OLD_BIN.as_bytes(), "the binary was modified");
    assert!(!update::prev_path(&w.bin).exists());
    (w, hub, a)
}

#[tokio::test]
async fn a_commit_that_is_not_on_origin_main_is_refused() {
    // On a side branch of the origin.
    let (w, _h, _a) = refused(|w| push_side(w), Build::Ok, "refused: not on origin/main").await;
    assert_eq!(build_count(&w), 0, "built a commit that is not on main");
    assert_eq!(git(&w.src, &["rev-parse", "HEAD"]), w.c[2], "checked it out");
    untouched(&w);
}

#[tokio::test]
async fn a_commit_the_clone_does_not_have_is_refused_the_same_way() {
    let (w, _h, _a) = refused(
        |_| "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        Build::Ok,
        "refused: not on origin/main",
    )
    .await;
    assert_eq!(build_count(&w), 0);
    untouched(&w);
}

#[tokio::test]
async fn a_dirty_clone_is_refused_and_left_as_it_was() {
    for how in ["untracked", "modified"] {
        let (w, _h, _a) = refused(
            |w| {
                match how {
                    "untracked" => std::fs::write(w.src.join("scratch.txt"), "mine").unwrap(),
                    _ => std::fs::write(w.src.join("f.txt"), "edited by hand").unwrap(),
                }
                push(w, "four")
            },
            Build::Ok,
            "refused: dirty clone",
        )
        .await;
        assert_eq!(build_count(&w), 0, "{how}: built a dirty clone");
        assert_eq!(git(&w.src, &["rev-parse", "HEAD"]), w.c[2], "{how}");
        match how {
            "untracked" => assert_eq!(std::fs::read_to_string(w.src.join("scratch.txt")).unwrap(), "mine"),
            _ => assert_eq!(std::fs::read_to_string(w.src.join("f.txt")).unwrap(), "edited by hand"),
        }
        untouched(&w);
    }
}

#[tokio::test]
async fn a_failing_build_keeps_the_binary() {
    let (w, _h, _a) = refused(|w| push(w, "four"), Build::Fail, "failed: build").await;
    assert_eq!(build_count(&w), 1);
    untouched(&w);
}

#[tokio::test]
async fn a_built_binary_that_reports_another_commit_is_not_installed() {
    let (w, _h, _a) = refused(
        |w| push(w, "four"),
        Build::WrongCommit,
        "failed: built binary reports another commit",
    )
    .await;
    assert_eq!(build_count(&w), 1);
    untouched(&w);
}

#[tokio::test]
async fn an_unreachable_origin_fails_the_fetch_before_anything_is_built() {
    let (w, _h, _a) = refused(
        |w| {
            let t = push(w, "four");
            let gone = w.dir.join("origin-moved.git");
            std::fs::rename(&w.origin, gone).unwrap();
            t
        },
        Build::Ok,
        "failed: fetch",
    )
    .await;
    assert_eq!(build_count(&w), 0);
    untouched(&w);
}

#[tokio::test]
async fn a_second_target_inside_the_minimum_interval_waits_and_then_proceeds() {
    let w = world();
    let t4 = push(&w, "four");
    let (hub, _a) = start(&w, Build::Ok, 4000, Some(&t4)).await;
    // The first attempt is immediate.
    wait_status(&hub, &w, "alice", "installed").await;
    assert_eq!(build_count(&w), 1);
    let after_first = bytes(&w.bin);

    let t5 = push(&w, "five");
    set_target(&w, &t5);
    wait_status(&hub, &w, "alice", "waiting").await;
    tokio::time::sleep(Duration::from_millis(1000)).await;
    assert_eq!(build_count(&w), 1, "a build started inside the interval");
    assert_eq!(bytes(&w.bin), after_first);
    assert_eq!(version(&w.bin), format!("wormhole {t4}"));

    // After the interval it goes ahead on its own.
    eventually(20, || async {
        (version(&w.bin) == format!("wormhole {t5}")).then_some(())
    })
    .await;
    assert!(build_count(&w) >= 2);
    assert_eq!(version(&update::prev_path(&w.bin)), format!("wormhole {t4}"));
}

#[tokio::test]
async fn an_unfinished_tool_call_delays_the_swap_until_its_post_tool_use() {
    let w = world();
    let t = push(&w, "four");
    let (hub, a) = start(&w, Build::Ok, 300, None).await;
    let repo = make_repo(&w.dir.join("a/proj"));
    hook(&a, session_start(SA, &repo)).await;
    let cmd = json!({"command": "ls"});
    hook(&a, pre_tool(SA, &repo, "Bash", cmd.clone(), "tu-1")).await;

    set_target(&w, &t);
    // It builds, then waits.
    let s = wait_status(&hub, &w, "alice", "waiting").await;
    assert!(!s.contains(w.dir.to_str().unwrap()));
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(info(&hub, "alice").await.unwrap()["status"]
        .as_str()
        .unwrap()
        .starts_with("waiting"));
    assert_eq!(bytes(&w.bin), OLD_BIN.as_bytes());
    assert!(!update::prev_path(&w.bin).exists());
    assert_eq!(build_count(&w), 1);

    // The end of some other tool call does not release it.
    hook(&a, post_tool(SA, &repo, "Bash", cmd.clone(), "tu-other")).await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(bytes(&w.bin), OLD_BIN.as_bytes());
    // Nor does the same id on another session.
    hook(&a, session_start(SB, &repo)).await;
    hook(&a, post_tool(SB, &repo, "Bash", cmd.clone(), "tu-1")).await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(bytes(&w.bin), OLD_BIN.as_bytes());

    // Its own PostToolUse does.
    hook(&a, post_tool(SA, &repo, "Bash", cmd, "tu-1")).await;
    wait_status(&hub, &w, "alice", "installed").await;
    assert_eq!(version(&w.bin), format!("wormhole {t}"));
    assert_eq!(bytes(&update::prev_path(&w.bin)), OLD_BIN.as_bytes());
}

#[tokio::test]
async fn without_an_updater_a_daemon_reports_disabled_and_changes_nothing() {
    let w = world();
    let t = push(&w, "four");
    set_target(&w, &t);
    let hub = start_hub_with(
        &w.dir,
        &Opts {
            target_file: Some(w.target_file.clone()),
            ..Opts::default()
        },
    )
    .await;
    let a = daemon::start(daemon_for(&w, &hub, "alice@machine-a", None, 300, None))
        .await
        .unwrap();
    wait_connected(&a).await;
    let s = wait_status(&hub, &w, "alice", "disabled").await;
    assert!(!s.is_empty());
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(info(&hub, "alice").await.unwrap()["target"], t);
    assert_eq!(build_count(&w), 0);
    untouched(&w);
    assert_eq!(git(&w.src, &["rev-parse", "HEAD"]), w.c[2]);
}

#[tokio::test]
async fn a_target_equal_to_the_running_commit_is_current() {
    if !update::valid_commit(wormhole::COMMIT) {
        return; // built outside a git checkout: there is no commit to equal
    }
    let w = world();
    let (hub, _a) = start(&w, Build::Ok, 300, Some(wormhole::COMMIT)).await;
    wait_status(&hub, &w, "alice", "current").await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(info(&hub, "alice").await.unwrap()["target"], wormhole::COMMIT);
    assert!(info(&hub, "alice").await.unwrap()["status"]
        .as_str()
        .unwrap()
        .starts_with("current"));
    assert_eq!(build_count(&w), 0);
    untouched(&w);
}

#[tokio::test]
async fn a_hold_file_stops_the_daemon_following_the_hub() {
    let w = world();
    let t = push(&w, "four");
    std::fs::write(update::hold_path(&w.bin), "").unwrap();
    let (hub, _a) = start(&w, Build::Ok, 300, Some(&t)).await;
    wait_status(&hub, &w, "alice", "held").await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(build_count(&w), 0);
    assert_eq!(bytes(&w.bin), OLD_BIN.as_bytes());
    assert!(!update::prev_path(&w.bin).exists());
    assert_eq!(git(&w.src, &["rev-parse", "HEAD"]), w.c[2]);
}

#[tokio::test]
async fn reverting_an_installed_update_holds_the_daemon_until_resumed() {
    let w = world();
    let t4 = push(&w, "four");
    let (hub, _a) = start(&w, Build::Ok, 300, Some(&t4)).await;
    wait_status(&hub, &w, "alice", "installed").await;

    update::revert(&w.bin).unwrap();
    assert_eq!(bytes(&w.bin), OLD_BIN.as_bytes());
    assert_eq!(version(&update::prev_path(&w.bin)), format!("wormhole {t4}"));
    assert!(update::hold_path(&w.bin).exists());

    let t5 = push(&w, "five");
    set_target(&w, &t5);
    wait_status(&hub, &w, "alice", "held").await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(build_count(&w), 1);
    assert_eq!(bytes(&w.bin), OLD_BIN.as_bytes());

    update::resume(&w.bin).unwrap();
    assert!(!update::hold_path(&w.bin).exists());
}

#[tokio::test]
async fn an_update_leaves_the_delegation_policy_and_its_side_files_alone() {
    let w = world();
    let policy = grant_policy("full-bypass");
    let pdir = policy.parent().unwrap().to_path_buf();
    let listing = |d: &Path| -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<_> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name().to_string_lossy().to_string(), std::fs::read(e.path()).unwrap_or_default())
            })
            .collect();
        v.sort();
        v
    };
    let t = push(&w, "four");
    let (hub, a) = start_with(&w, Build::Ok, 300, None, Some(policy.clone())).await;
    wait_status(&hub, &w, "alice", "current").await;
    let before = listing(&pdir);
    let revoked_before = delegation::revoked(&policy);
    let audit_before = delegation::audit_path(&policy).exists();

    set_target(&w, &t);
    wait_status(&hub, &w, "alice", "installed").await;
    assert_eq!(listing(&pdir), before, "the policy directory changed");
    assert_eq!(delegation::revoked(&policy), revoked_before);
    assert_eq!(delegation::audit_path(&policy).exists(), audit_before);
    let _ = a;
}

#[tokio::test]
async fn who_and_the_page_show_each_daemons_commit_target_and_status() {
    let w = world();
    let t = push(&w, "four");
    let (hub, a) = start(&w, Build::Ok, 300, None).await;
    let b = daemon::start(daemon_for(&w, &hub, "bob@machine-b", None, 300, None))
        .await
        .unwrap();
    wait_connected(&b).await;
    let repo = make_repo(&w.dir.join("a/proj"));
    hook(&a, session_start(SA, &repo)).await;
    wait_status(&hub, &w, "alice", "current").await;
    wait_status(&hub, &w, "bob", "disabled").await;

    let c12 = short(wormhole::COMMIT);
    let who = tool(&a, SA, "who", json!({})).await.unwrap();
    assert!(who.contains("Daemons:"), "{who}");
    for line in [
        format!("alice@machine-a commit {c12} target none: current"),
        format!("bob@machine-b commit {c12} target none: disabled"),
    ] {
        assert!(who.contains(&line), "{line} not in {who}");
    }

    set_target(&w, &t);
    wait_status(&hub, &w, "alice", "installed").await;
    // Bob's target arrives with the next report; wait for it.
    eventually(10, || async {
        (info(&hub, "bob").await?["target"] == t).then_some(())
    })
    .await;
    let who = tool(&a, SA, "who", json!({})).await.unwrap();
    let t12 = short(&t);
    for line in [
        format!("alice@machine-a commit {c12} target {t12}: installed"),
        format!("bob@machine-b commit {c12} target {t12}: disabled"),
    ] {
        assert!(who.contains(&line), "{line} not in {who}");
    }
    assert!(!who.contains(w.dir.to_str().unwrap()), "{who}");

    let state = api_state(&hub).await;
    let ds = state["daemons"].as_array().unwrap();
    assert_eq!(
        ds.iter().map(|d| d["user"].as_str().unwrap()).collect::<Vec<_>>(),
        ["alice", "bob"],
        "sorted by user"
    );
    for d in ds {
        assert_eq!(d["commit"], wormhole::COMMIT);
        assert_eq!(d["target"], t);
        assert!(d["ts"].as_u64().unwrap() > 0);
        assert!(d["machine"].as_str().unwrap().starts_with("machine-"));
    }
    // The page has a Daemons table.
    let id = ("x-wormhole-static-identity", "viewer@viewer-machine");
    let (s1, _, index) = http(hub.addr, "GET", "/", &[id], "").await;
    let (s2, _, js) = http(hub.addr, "GET", "/app.js", &[id], "").await;
    assert_eq!((s1, s2), (200, 200));
    assert!(
        format!("{index}{js}").contains("Daemons"),
        "the page does not mention Daemons"
    );
}

#[test]
fn revert_swaps_the_binaries_makes_a_hold_file_and_resume_removes_it() {
    let dir = tmpdir();
    let bin = dir.join("wormhole");
    let prev = update::prev_path(&bin);
    assert_eq!(prev, dir.join("wormhole.prev"));
    assert_eq!(update::hold_path(&bin), dir.join("wormhole.hold"));
    write_bin(&bin, "#!/bin/sh\necho NEW\n");
    write_bin(&prev, "#!/bin/sh\necho OLD\n");
    update::revert(&bin).unwrap();
    assert_eq!(version(&bin), "OLD");
    assert_eq!(version(&prev), "NEW");
    assert!(update::hold_path(&bin).exists());
    assert_ne!(std::fs::metadata(&bin).unwrap().permissions().mode() & 0o111, 0);
    // Reverting again swaps them back.
    update::revert(&bin).unwrap();
    assert_eq!(version(&bin), "NEW");
    assert!(update::hold_path(&bin).exists());
    update::resume(&bin).unwrap();
    assert!(!update::hold_path(&bin).exists());
    // Resuming with no hold is fine.
    update::resume(&bin).unwrap();
}

#[test]
fn revert_without_a_previous_binary_is_an_error_and_changes_nothing() {
    let dir = tmpdir();
    let bin = dir.join("wormhole");
    write_bin(&bin, "#!/bin/sh\necho NEW\n");
    let e = update::revert(&bin).unwrap_err();
    assert!(e.contains("no previous binary"), "{e}");
    assert_eq!(version(&bin), "NEW");
    assert!(!update::prev_path(&bin).exists());
}

#[test]
fn only_forty_lowercase_hex_characters_are_a_commit() {
    for ok in [SHA1, SHA4, "0000000000000000000000000000000000000000"] {
        assert!(update::valid_commit(ok), "{ok}");
    }
    for bad in [
        "",
        "unknown",
        &SHA4[..39],
        format!("{SHA4}0").as_str(),
        SHA4.to_uppercase().as_str(),
        "g111111111111111111111111111111111111111",
        format!("{SHA1}\n").as_str(),
        format!(" {SHA1}").as_str(),
        "--upload-pack=touch_pwned_aaaaaaaaaaaaaaaaaa",
        "HEAD",
        "main",
    ] {
        assert!(!update::valid_commit(bad), "{bad:?}");
    }
}

fn targets(r: &Raw) -> Vec<Value> {
    r.frames
        .iter()
        .filter(|f| f["op"] == "target")
        .map(|f| f["commit"].clone())
        .collect()
}

async fn wait_targets(r: &mut Raw, n: usize) -> Vec<Value> {
    let t = Instant::now();
    loop {
        r.drain(100).await;
        let v = targets(r);
        if v.len() >= n {
            return v;
        }
        assert!(t.elapsed() < Duration::from_secs(10), "target frames so far: {v:?}");
    }
}

#[tokio::test]
async fn the_hub_announces_only_a_valid_target_and_only_to_update_connections() {
    let dir = tmpdir();
    let tf = dir.join("target");
    std::fs::write(&tf, format!("  {SHA1}\n\n")).unwrap();
    let hub = start_hub_with(
        &dir,
        &Opts {
            target_file: Some(tf.clone()),
            ..Opts::default()
        },
    )
    .await;
    let mut u = Raw::connect(hub.addr, "uma@machine-u", &["update"]).await;
    let mut n = Raw::connect(hub.addr, "nat@machine-n", &[]).await;
    // The Welcome carries the target for an update connection only, trimmed.
    assert_eq!(u.welcome["target"], SHA1);
    assert!(n.welcome.get("target").is_none_or(|t| t.is_null()), "{}", n.welcome);
    for w in [&u.welcome, &n.welcome] {
        let caps: Vec<&str> = w["caps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        for want in ["delegation", "team-log", "update"] {
            assert!(caps.contains(&want), "{caps:?}");
        }
    }

    let base = targets(&u).len();
    let put = |content: Option<String>| match content {
        Some(c) => {
            let tmp = dir.join("target.tmp");
            std::fs::write(&tmp, c).unwrap();
            std::fs::rename(tmp, &tf).unwrap();
        }
        None => std::fs::remove_file(&tf).unwrap(),
    };
    // Valid and invalid contents alternate, so every step is a change.
    let steps: Vec<(Option<String>, Option<&str>)> = vec![
        (Some(SHA2.to_string()), Some(SHA2)),
        (Some("not-a-commit\n".to_string()), None),
        (Some(format!("{SHA3}\n")), Some(SHA3)),
        (Some(SHA4.to_uppercase()), None),
        (Some(SHA4.to_string()), Some(SHA4)),
        (Some(SHA4[..39].to_string()), None),
        (Some(format!("\n {SHA2} \n")), Some(SHA2)),
        (None, None),
    ];
    for (i, (content, want)) in steps.iter().enumerate() {
        put(content.clone());
        let v = wait_targets(&mut u, base + i + 1).await;
        let got = &v[base + i];
        match want {
            Some(w) => assert_eq!(got, w, "step {i}"),
            None => assert!(got.is_null(), "step {i}: {got}"),
        }
    }
    assert_eq!(targets(&u).len(), base + steps.len(), "extra target frames: {:?}", targets(&u));
    // The connection that did not advertise `update` never hears of any of it.
    n.drain(300).await;
    assert!(
        n.frames.iter().all(|f| f["op"] != "target"),
        "{:?}",
        n.frames
    );
}

async fn snapshot(r: &mut Raw) -> Snapshot {
    serde_json::from_value(r.req(json!({"type": "snapshot"})).await.unwrap()).unwrap()
}

#[tokio::test]
async fn the_hub_stores_what_a_daemon_reports_under_the_connections_identity_and_sanitised() {
    let hub = start_hub(&tmpdir()).await;
    let mut u = Raw::connect(hub.addr, "uma@machine-u", &["update"]).await;
    let before = wormhole::proto::now_ms();
    // Extra fields claiming another identity are ignored.
    u.req(json!({"type": "daemon_status", "commit": SHA1, "target": SHA2,
                 "status": "building", "user": "mallory", "machine": "evil"}))
        .await
        .unwrap();
    let s = snapshot(&mut u).await;
    assert_eq!(s.daemons.len(), 1, "{:?}", s.daemons);
    let d = &s.daemons[0];
    assert_eq!(
        (d.user.as_str(), d.machine.as_str(), d.commit.as_str(), d.target.as_str(), d.status.as_str()),
        ("uma", "machine-u", SHA1, SHA2, "building")
    );
    assert!(d.ts >= before && d.ts <= wormhole::proto::now_ms());

    // A later report replaces it; hostile values are reduced.
    let status = format!("line1\nline2\u{7} <i>{}", "y".repeat(500));
    u.req(json!({"type": "daemon_status", "commit": "ZZ <b>top</b>\nzz", "target": "A".repeat(100),
                 "status": status}))
        .await
        .unwrap();
    let s = snapshot(&mut u).await;
    assert_eq!(s.daemons.len(), 1, "{:?}", s.daemons);
    let d = &s.daemons[0];
    let hex = |v: &str| v.len() <= 40 && v.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'));
    assert!(hex(&d.commit) || d.commit == "unknown", "{:?}", d.commit);
    assert!(hex(&d.target), "{:?}", d.target);
    assert!(d.status.chars().count() <= 200, "{}", d.status.len());
    assert!(!d.status.contains('\n') && !d.status.chars().any(char::is_control), "{:?}", d.status);
    assert!(d.status.starts_with("line1 line2"), "{:?}", d.status);
    assert_eq!((d.user.as_str(), d.machine.as_str()), ("uma", "machine-u"));
}

fn raise_nofile() {
    // SAFETY: plain libc calls on a local struct.
    unsafe {
        let mut r = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) == 0 {
            let want = r.rlim_max.min(4096);
            if want > r.rlim_cur {
                r.rlim_cur = want;
                libc::setrlimit(libc::RLIMIT_NOFILE, &r);
            }
        }
    }
}

#[tokio::test]
async fn the_hub_keeps_at_most_500_daemons_sorted_by_user_then_machine() {
    raise_nofile();
    let hub = start_hub(&tmpdir()).await;
    let mut peers = Vec::new();
    for i in 0..502 {
        let mut r = Raw::connect(hub.addr, &format!("u{i:03}@m"), &["update"]).await;
        r.req(json!({"type": "daemon_status", "commit": SHA1, "target": "", "status": "current"}))
            .await
            .unwrap();
        peers.push(r);
    }
    let s = snapshot(&mut peers[0]).await;
    assert_eq!(s.daemons.len(), 500);
    let keys: Vec<(String, String)> = s
        .daemons
        .iter()
        .map(|d| (d.user.clone(), d.machine.clone()))
        .collect();
    assert!(keys.windows(2).all(|p| p[0] < p[1]), "not sorted");
    // The page gets the same list.
    let state = api_state(&hub).await;
    assert!(state["daemons"].as_array().unwrap().len() <= 500);
}
