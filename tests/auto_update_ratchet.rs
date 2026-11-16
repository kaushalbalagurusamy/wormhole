//! The floor ratchet (spec Amendment 3): the updater remembers every minimum it has run with in
//! `<bin>.floors`, so a floor commit's binary, which carries an older built-in minimum, cannot be
//! walked further back. Real git repositories and fake builds as in tests/auto_update.rs.

mod common;

use common::*;
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use wormhole::daemon::{self, DaemonHandle};
use wormhole::hub::HubHandle;
use wormhole::update::{self, UpdateConfig};

const OLD_BIN: &str = "#!/bin/sh\necho \"wormhole OLD-BINARY\"\n";
const MISSING: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const BELOW_MIN: &str = "refused: below minimum safe commit";

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

fn write_exec(p: &Path, text: &str) {
    std::fs::write(p, text).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
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
    write_exec(&bin, OLD_BIN);
    World {
        build_log: dir.join("build.log"),
        target_file: dir.join("target"),
        dir,
        src,
        bin,
        c,
    }
}

fn set_target(w: &World, content: &str) {
    let tmp = w.dir.join("target.tmp");
    std::fs::write(&tmp, format!("{content}\n")).unwrap();
    std::fs::rename(tmp, &w.target_file).unwrap();
}

fn build_count(w: &World) -> usize {
    std::fs::read_to_string(&w.build_log)
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

fn update_config(w: &World, min_safe: &str, floor: Option<&str>) -> UpdateConfig {
    let log = w.build_log.display();
    let mut u = UpdateConfig::new(w.src.clone(), w.bin.clone());
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
    u
}

async fn start_hub(w: &World) -> HubHandle {
    start_hub_with(
        &w.dir,
        &Opts {
            target_file: Some(w.target_file.clone()),
            ..Opts::default()
        },
    )
    .await
}

async fn start_daemon(w: &World, hub: &HubHandle, u: UpdateConfig) -> DaemonHandle {
    let mut c = daemon_config(
        &w.dir,
        format!("ws://{}/ws", hub.addr),
        "alice@machine-a",
        &Opts::default(),
    );
    c.auto_update = Some(u);
    let a = daemon::start(c).await.unwrap();
    wait_connected(&a).await;
    a
}

async fn info(hub: &HubHandle, user: &str) -> Option<Value> {
    api_state(hub).await["daemons"]
        .as_array()?
        .iter()
        .find(|d| d["user"] == user)
        .cloned()
}

async fn wait_status(hub: &HubHandle, prefix: &str) -> String {
    eventually(40, || async {
        let s = info(hub, "alice").await?["status"].as_str()?.to_string();
        s.starts_with(prefix).then_some(s)
    })
    .await
}

fn version(bin: &Path) -> String {
    let o = Command::new(bin).arg("version").output().unwrap();
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn floors(w: &World) -> Vec<String> {
    std::fs::read_to_string(update::floors_path(&w.bin))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

fn write_floors(w: &World, lines: &[&str]) {
    std::fs::write(update::floors_path(&w.bin), lines.join("\n") + "\n").unwrap();
}

/// The daemon with `min_safe`/`floor` refuses `target` with the minimum's refusal, builds nothing
/// and leaves the binary alone.
async fn refuses_below_minimum(w: &World, u: UpdateConfig, target: &str) {
    let hub = start_hub(w).await;
    set_target(w, target);
    let _a = start_daemon(w, &hub, u).await;
    wait_status(&hub, BELOW_MIN).await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(info(&hub, "alice").await.unwrap()["status"]
        .as_str()
        .unwrap()
        .starts_with(BELOW_MIN));
    assert_eq!(std::fs::read(&w.bin).unwrap(), OLD_BIN.as_bytes());
    assert!(!update::prev_path(&w.bin).exists());
    assert_eq!(build_count(w), 0, "built a refused target");
}

async fn installs(w: &World, u: UpdateConfig, target: &str) {
    let hub = start_hub(w).await;
    set_target(w, target);
    let _a = start_daemon(w, &hub, u).await;
    wait_status(&hub, "installed").await;
    assert_eq!(version(&w.bin), format!("wormhole {target}"));
}

#[tokio::test]
async fn starting_the_updater_records_its_minimums_privately_without_duplicates() {
    let w = world();
    assert_eq!(
        update::floors_path(&w.bin),
        w.bin.with_file_name("wormhole.floors")
    );
    let hub = start_hub(&w).await;
    let a = start_daemon(&w, &hub, update_config(&w, &w.c[0], Some(&w.c[1]))).await;
    eventually(10, || async {
        update::floors_path(&w.bin).exists().then_some(())
    })
    .await;
    let mut got = floors(&w);
    got.sort();
    let mut want = vec![w.c[0].clone(), w.c[1].clone()];
    want.sort();
    assert_eq!(got, want);
    assert_eq!(
        std::fs::metadata(update::floors_path(&w.bin))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    // A restart adds nothing; a new minimum adds one.
    a.shutdown().await;
    let a = start_daemon(&w, &hub, update_config(&w, &w.c[0], Some(&w.c[1]))).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(floors(&w).len(), 2, "{:?}", floors(&w));
    a.shutdown().await;
    let _a = start_daemon(&w, &hub, update_config(&w, &w.c[2], None)).await;
    eventually(10, || async { (floors(&w).len() == 3).then_some(()) }).await;
    assert!(floors(&w).contains(&w.c[2]));
    // Nothing else is in the directory beside the binary but the floors file.
    let mut names: Vec<String> = std::fs::read_dir(w.bin.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    assert_eq!(names, ["wormhole", "wormhole.floors"]);
}

#[tokio::test]
async fn the_ratchet_file_keeps_at_most_the_32_newest_lines() {
    let w = world();
    let old: Vec<String> = (0..40).map(|i| format!("{i:040x}")).collect();
    let refs: Vec<&str> = old.iter().map(String::as_str).collect();
    write_floors(&w, &refs);
    let hub = start_hub(&w).await;
    let _a = start_daemon(&w, &hub, update_config(&w, &w.c[0], None)).await;
    eventually(10, || async { floors(&w).contains(&w.c[0]).then_some(()) }).await;
    let got = floors(&w);
    assert!(got.len() <= 32, "{} lines", got.len());
    // The newest stay: the last old line and the new minimum; the oldest are dropped.
    assert!(got.contains(&old[39]), "{got:?}");
    assert!(!got.contains(&old[0]), "{got:?}");
}

#[tokio::test]
async fn a_remembered_minimum_refuses_a_lower_target_and_not_one_at_or_above_it() {
    let w = world();
    write_floors(&w, &[&w.c[2]]);
    refuses_below_minimum(&w, update_config(&w, &w.c[0], None), &w.c[1]).await;

    // The remembered commit itself, and anything above it, install.
    let w = world();
    write_floors(&w, &[&w.c[2]]);
    installs(&w, update_config(&w, &w.c[0], None), &w.c[2].clone()).await;
    let w = world();
    write_floors(&w, &[&w.c[2]]);
    installs(&w, update_config(&w, &w.c[0], None), &w.c[3].clone()).await;
}

#[tokio::test]
async fn a_remembered_minimum_missing_from_the_clone_fails_closed() {
    let w = world();
    write_floors(&w, &[MISSING]);
    refuses_below_minimum(&w, update_config(&w, &w.c[0], None), &w.c[3]).await;
}

#[tokio::test]
async fn lines_that_are_not_commits_are_ignored_not_refused() {
    let w = world();
    write_floors(
        &w,
        &[
            "garbage",
            "",
            "HEAD",
            "--upload-pack=x",
            &w.c[3].to_uppercase(),
            &w.c[3][..39],
            &format!("{} ", w.c[3]),
        ],
    );
    installs(&w, update_config(&w, &w.c[0], None), &w.c[1].clone()).await;
}

#[tokio::test]
async fn the_ratchet_stops_a_floor_binary_walking_the_hub_back_a_hop_at_a_time() {
    let w = world();
    // Hop one: the release binary carries minimum c[1] and is moved to c[1].
    let hub = start_hub(&w).await;
    set_target(&w, &w.c[1]);
    let a = start_daemon(&w, &hub, update_config(&w, &w.c[1], None)).await;
    wait_status(&hub, "installed").await;
    assert_eq!(version(&w.bin), format!("wormhole {}", w.c[1]));
    assert!(floors(&w).contains(&w.c[1]));
    let installed = std::fs::read(&w.bin).unwrap();
    a.shutdown().await;
    hub.shutdown().await;

    // Hop two: that binary's own built-in minimum is older (c[0]), but the file remembers c[1].
    let hub = start_hub(&w).await;
    set_target(&w, &w.c[0]);
    let _a = start_daemon(&w, &hub, update_config(&w, &w.c[0], None)).await;
    wait_status(&hub, BELOW_MIN).await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(std::fs::read(&w.bin).unwrap(), installed);
    assert!(floors(&w).contains(&w.c[1]));
    assert_eq!(build_count(&w), 1, "built the refused target");
}

#[test]
fn a_local_revert_leaves_the_ratchet_file_alone() {
    let dir = tmpdir();
    let bin = dir.join("wormhole");
    write_exec(&bin, "#!/bin/sh\necho NEW\n");
    write_exec(&update::prev_path(&bin), "#!/bin/sh\necho OLD\n");
    let floors_file = update::floors_path(&bin);
    let content = format!("{}\n{}\n", "1".repeat(40), "2".repeat(40));
    std::fs::write(&floors_file, &content).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_wormhole"))
            .args(args)
            // Never the real ~/.wormhole.
            .env("HOME", &dir)
            .output()
            .unwrap()
    };
    let out = run(&["update", "--revert", "--bin", bin.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(version(&bin), "OLD");
    assert!(update::hold_path(&bin).exists());
    assert_eq!(std::fs::read_to_string(&floors_file).unwrap(), content);
    let out = run(&["update", "--resume", "--bin", bin.to_str().unwrap()]);
    assert!(out.status.success());
    assert_eq!(std::fs::read_to_string(&floors_file).unwrap(), content);
}
