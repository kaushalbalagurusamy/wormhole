//! A whois lookup keeps its slot until its `tailscale` process is gone, when it times out and
//! when its requester goes away. Its own test binary: tokio reaps killed children from one
//! queue per process, so another test's runtime would reap them and hide a slot freed early.

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wormhole::hub::identity::{Identifier, IdentityConfig, Peer, WHOIS_LIMIT};

const WHOIS: &str =
    r#"{"Node":{"ComputedName":"laptop-a"},"UserProfile":{"LoginName":"alice@example.com"}}"#;

/// The two tests must not reap each other's children either.
static REAPING: Mutex<()> = Mutex::new(());

/// A fake `tailscale` that appends its pid to `pids` and records in `seen` how many listed
/// pids still exist (`kill -0` also sees a killed child not yet reaped). The first
/// `WHOIS_LIMIT` copies hang; later ones answer.
fn hanging_tailscale(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("answer"), WHOIS).unwrap();
    let bin = dir.join("tailscale");
    std::fs::write(
        &bin,
        format!(
            "#!/bin/sh\ncd '{d}'\necho $$ >> pids\nn=0\nfor p in $(cat pids); do kill -0 $p 2>/dev/null && n=$((n+1)); done\necho $n >> seen\nlines=$(wc -l < pids)\n[ $lines -le {WHOIS_LIMIT} ] && exec sleep 30\nexec cat answer\n",
            d = dir.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

fn most_seen(dir: &Path) -> Option<usize> {
    std::fs::read_to_string(dir.join("seen"))
        .unwrap()
        .lines()
        .map(|l| l.trim().parse::<usize>().unwrap())
        .max()
}

/// A runtime that turns its driver (and so reaps children) only when idle, so the window
/// `identify_slowly` opens is not closed early by a periodic turn.
fn single_turn_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .event_interval(u32::MAX)
        .build()
        .unwrap()
}

/// Runs a lookup, blocking the runtime for a moment after a second poll that leaves it
/// pending: for a queued lookup that is the poll that takes a freed permit and spawns. A
/// permit freed before its child is reaped then lets the new fake see that child.
async fn identify_slowly(id: &Identifier, peer: SocketAddr) -> Option<Peer> {
    let mut lookup = std::pin::pin!(id.identify(peer, None));
    let mut polls = 0;
    std::future::poll_fn(|cx| {
        let r = lookup.as_mut().poll(cx);
        polls += 1;
        if polls == 2 && r.is_pending() {
            std::thread::sleep(Duration::from_millis(300));
        }
        r
    })
    .await
}

fn setup(name: &str) -> (PathBuf, Arc<Identifier>, SocketAddr) {
    let dir = std::env::temp_dir().join(format!("wh-reap-{name}-{}", std::process::id()));
    let bin = hanging_tailscale(&dir);
    let id = Arc::new(Identifier::new(IdentityConfig::Tailscale { bin }));
    (dir, id, "100.64.0.5:4000".parse().unwrap())
}

#[test]
fn timed_out_lookups_hold_their_slot_until_the_child_is_gone() {
    let _one_at_a_time = REAPING.lock().unwrap_or_else(|e| e.into_inner());
    let (dir, id, peer) = setup("timeout");
    single_turn_runtime().block_on(async {
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..WHOIS_LIMIT * 2 {
            let id = id.clone();
            set.spawn(async move { identify_slowly(&id, peer).await });
        }
        let mut answered = 0;
        while let Some(r) = set.join_next().await {
            answered += r.unwrap().is_some() as usize;
        }
        // The hanging lookups time out and are refused; the queued ones then answer.
        assert_eq!(answered, WHOIS_LIMIT);
    });
    let most = most_seen(&dir);
    assert!(
        most <= Some(WHOIS_LIMIT),
        "{most:?} whois processes existed at once"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn dropped_lookups_hold_their_slot_until_the_child_is_gone() {
    let _one_at_a_time = REAPING.lock().unwrap_or_else(|e| e.into_inner());
    let (dir, id, peer) = setup("drop");
    single_turn_runtime().block_on(async {
        let mut hanging = Vec::new();
        for _ in 0..WHOIS_LIMIT {
            let id = id.clone();
            hanging.push(tokio::spawn(
                async move { identify_slowly(&id, peer).await },
            ));
        }
        // Wait until every hanging fake has started.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while std::fs::read_to_string(dir.join("pids")).map_or(0, |s| s.lines().count())
            < WHOIS_LIMIT
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "fakes never started"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut queued = tokio::task::JoinSet::new();
        for _ in 0..WHOIS_LIMIT {
            let id = id.clone();
            queued.spawn(async move { identify_slowly(&id, peer).await });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        // The clients go away mid-lookup.
        for h in &hanging {
            h.abort();
        }
        while let Some(r) = queued.join_next().await {
            assert_eq!(r.unwrap().unwrap().machine, "laptop-a");
        }
    });
    let most = most_seen(&dir);
    assert!(
        most <= Some(WHOIS_LIMIT),
        "{most:?} whois processes existed at once"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
