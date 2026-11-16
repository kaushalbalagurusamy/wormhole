//! Self-update on the daemon: follow the hub's target build, report the status, and, when
//! `auto_update` is set, fetch, verify, build and swap the binary (ADR 0003). Hook handling
//! feeds `Idle` so the swap waits for a quiet moment. This module never reads or writes the
//! delegation policy or its side files.

use super::Daemon;
use crate::proto::*;
use crate::update::{self, UpdateConfig};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A tool call whose `PostToolUse` never came stops counting as running after this.
const TOOL_CALL_STALE: Duration = Duration::from_secs(600);
const BUILD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const GIT_TIMEOUT: Duration = Duration::from_secs(120);

/// What the hooks have been doing, for choosing a quiet moment.
#[derive(Default)]
pub(crate) struct Idle {
    /// `PreToolUse` seen, no `PostToolUse` yet, by (session_id, tool_use_id).
    inflight: HashMap<(String, String), Instant>,
    last_hook: Option<Instant>,
}

impl Idle {
    pub(crate) fn touch(&mut self) {
        self.last_hook = Some(Instant::now());
    }

    pub(crate) fn tool_started(&mut self, session: &str, id: &str) {
        self.inflight
            .insert((session.into(), id.into()), Instant::now());
    }

    pub(crate) fn tool_finished(&mut self, session: &str, id: &str) {
        self.inflight.remove(&(session.to_string(), id.to_string()));
    }

    pub(crate) fn session_ended(&mut self, session: &str) {
        self.inflight.retain(|(s, _), _| s != session);
    }

    fn reason(&self, quiet: Duration) -> Option<&'static str> {
        if self
            .inflight
            .values()
            .any(|t| t.elapsed() < TOOL_CALL_STALE)
        {
            return Some("a tool call is running");
        }
        if self.last_hook.is_some_and(|t| t.elapsed() < quiet) {
            return Some("a hook was just handled");
        }
        None
    }
}

/// The updater's view: the target the hub announced and the status last decided.
#[derive(Default)]
pub(crate) struct UpdState {
    pub target: String,
    status: String,
    /// Connection generation, target and status last reported to the hub.
    reported: Option<(u64, String, String, bool)>,
    last_attempt: Option<Instant>,
    last_target: Option<String>,
    /// The target this daemon installed without exiting (`exit_after_install` off).
    installed: Option<String>,
    /// The target being worked on is not a descendant of the running commit.
    downgrade: bool,
}

impl Daemon {
    /// The hub announced a target (or none).
    pub(crate) fn set_target(&self, commit: Option<String>) {
        let t: String = commit.unwrap_or_default().chars().take(64).collect();
        self.upd.lock().unwrap().target = t;
    }

    fn target(&self) -> String {
        self.upd.lock().unwrap().target.clone()
    }

    /// Record the status and report it at once when the hub follows daemons.
    fn set_status(&self, s: &str) {
        {
            let mut u = self.upd.lock().unwrap();
            u.status = if u.downgrade {
                format!("{s} (downgrade)")
            } else {
                s.to_string()
            };
        }
        self.report();
    }

    /// Send the status if this connection has not carried it yet. Only on a connection
    /// whose `Welcome` listed `update`.
    pub(crate) fn report(&self) {
        if !self.link.connected.load(Ordering::SeqCst) || !self.link.update.load(Ordering::SeqCst) {
            return;
        }
        let gen = self.link.generation.load(Ordering::SeqCst);
        let mut u = self.upd.lock().unwrap();
        if u.status.is_empty() {
            return;
        }
        let key = (gen, u.target.clone(), u.status.clone(), u.downgrade);
        if u.reported.as_ref() == Some(&key) {
            return;
        }
        let target: String = u
            .target
            .chars()
            .filter(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            .take(40)
            .collect();
        let (status, downgrade) = (u.status.clone(), u.downgrade);
        u.reported = Some(key);
        drop(u);
        self.send_up(Up::Req {
            id: u64::MAX,
            req: Request::DaemonStatus {
                commit: crate::COMMIT.to_string(),
                target,
                status,
                downgrade,
            },
        });
    }
}

fn hold(cfg: &UpdateConfig) -> bool {
    update::hold_path(&cfg.bin).exists()
}

/// Follow the target and keep the hub told; attempt an update when one is due.
pub(crate) async fn run(d: Arc<Daemon>) {
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tick.tick().await;
        let target = d.target();
        let Some(cfg) = d.cfg.auto_update.clone() else {
            d.set_status("disabled");
            continue;
        };
        if target.is_empty() || target == crate::COMMIT {
            d.upd.lock().unwrap().downgrade = false;
            d.set_status("current");
            continue;
        }
        if hold(&cfg) {
            d.set_status("held");
            continue;
        }
        let (due, tried, installed) = {
            let u = d.upd.lock().unwrap();
            (
                u.last_attempt
                    .is_none_or(|t| t.elapsed() >= cfg.min_interval),
                u.last_target.as_deref() == Some(target.as_str()),
                u.installed.as_deref() == Some(target.as_str()),
            )
        };
        if installed {
            d.set_status("installed");
        } else if !due {
            // A failure stays visible until the next try; a new target waits its turn.
            if !tried {
                d.set_status("waiting: rate limit");
            } else {
                d.report();
            }
        } else {
            {
                let mut u = d.upd.lock().unwrap();
                u.last_attempt = Some(Instant::now());
                u.last_target = Some(target.clone());
            }
            attempt(&d, &cfg, &target).await;
        }
    }
}

/// Is `target` equal to or a descendant of `base`, both commits in the clone? Anything
/// else, including a `base` that is not a SHA or not present, is false.
async fn descends(src: &Path, base: &str, target: &str) -> bool {
    if !update::valid_commit(base) {
        return false;
    }
    let commit = format!("{base}^{{commit}}");
    let ok = |o: Option<std::process::Output>| o.is_some_and(|o| o.status.success());
    ok(update::git(src, &["cat-file", "-e", &commit], GIT_TIMEOUT).await)
        && ok(update::git(
            src,
            &["merge-base", "--is-ancestor", base, target],
            GIT_TIMEOUT,
        )
        .await)
}

/// One update, in the order of the spec; any failure before the swap leaves the binary alone.
async fn attempt(d: &Arc<Daemon>, cfg: &UpdateConfig, target: &str) {
    let ok = |o: &Option<std::process::Output>| o.as_ref().is_some_and(|o| o.status.success());
    d.upd.lock().unwrap().downgrade = false;
    if !update::valid_commit(target) {
        return d.set_status("refused: invalid target");
    }
    let st = update::git(&cfg.src, &["status", "--porcelain"], GIT_TIMEOUT).await;
    match &st {
        Some(o) if o.status.success() => {
            if !o.stdout.is_empty() {
                return d.set_status("refused: dirty clone");
            }
        }
        _ => return d.set_status("failed: status"),
    }
    if !ok(&update::git(&cfg.src, &["fetch", "--quiet", "origin"], GIT_TIMEOUT).await) {
        return d.set_status("failed: fetch");
    }
    let commit = format!("{target}^{{commit}}");
    if !ok(&update::git(&cfg.src, &["cat-file", "-e", &commit], GIT_TIMEOUT).await)
        || !ok(&update::git(
            &cfg.src,
            &["merge-base", "--is-ancestor", target, "origin/main"],
            GIT_TIMEOUT,
        )
        .await)
    {
        return d.set_status("refused: not on origin/main");
    }
    // Both minimums always apply; a missing object fails closed.
    for (min, why) in [
        (
            Some(cfg.min_safe.as_str()),
            "refused: below minimum safe commit",
        ),
        (cfg.floor.as_deref(), "refused: below local floor"),
    ] {
        let Some(min) = min else { continue };
        if !descends(&cfg.src, min, target).await {
            return d.set_status(why);
        }
    }
    // A target that does not contain the running commit is a downgrade; say so from here on.
    if !descends(&cfg.src, crate::COMMIT, target).await {
        d.upd.lock().unwrap().downgrade = true;
    }
    if !ok(&update::git(
        &cfg.src,
        &["checkout", "--quiet", "--detach", target],
        GIT_TIMEOUT,
    )
    .await)
    {
        return d.set_status("failed: checkout");
    }
    d.set_status("building");
    let argv: Vec<String> = cfg.build.clone().unwrap_or_else(|| {
        ["build", "--release", "--locked"]
            .iter()
            .map(|s| s.to_string())
            .fold(
                vec![cfg.cargo.to_string_lossy().into_owned()],
                |mut v, s| {
                    v.push(s);
                    v
                },
            )
    });
    let Some((prog, rest)) = argv.split_first() else {
        return d.set_status("failed: build");
    };
    let rest: Vec<&str> = rest.iter().map(String::as_str).collect();
    let cargo_dir = cfg
        .cargo
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf);
    if !ok(&update::run(
        Path::new(prog),
        &rest,
        &cfg.src,
        BUILD_TIMEOUT,
        cargo_dir.as_deref(),
    )
    .await)
    {
        return d.set_status("failed: build");
    }
    let artifact = cfg.src.join(&cfg.artifact);
    let ver = update::run(
        &artifact,
        &["version"],
        &cfg.src,
        Duration::from_secs(30),
        None,
    )
    .await;
    if !ver
        .is_some_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains(target))
    {
        return d.set_status("failed: built binary reports another commit");
    }
    // Swap only at a quiet moment, and only for the target still wanted.
    loop {
        if d.target() != target {
            return d.set_status("waiting: the target changed");
        }
        if hold(cfg) {
            return d.set_status("held");
        }
        let why = if !d.deleg.lock().unwrap().is_empty() {
            Some("a delegated task is open")
        } else {
            d.idle.lock().unwrap().reason(cfg.quiet)
        };
        match why {
            Some(w) => d.set_status(&format!("waiting: {w}")),
            None => break,
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    if update::install(&cfg.bin, &artifact).is_err() {
        return d.set_status("failed: install");
    }
    d.upd.lock().unwrap().installed = Some(target.to_string());
    d.set_status("installed");
    if cfg.exit_after_install {
        d.set_status("restarting");
        // Let the status frame leave before the process goes.
        tokio::time::sleep(Duration::from_millis(500)).await;
        std::process::exit(75);
    }
}
