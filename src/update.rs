//! Daemon self-update, the parts that do not need a running daemon: configuration, the
//! hold file, the swap, and the commands the updater runs. See docs/adr/0003-auto-update.md.
//! Nothing here reads or writes the delegation policy or its side files.

use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

/// The last security-relevant commit on `main` at release time. A daemon never moves to a
/// target that is not this commit or a descendant of it. Raised when a security fix lands.
pub const MIN_SAFE_COMMIT: &str = "949e46761e4577336cdcdacfabd221138cc25365";

/// What `wormhole daemon --auto-update` needs.
#[derive(Clone, Debug)]
pub struct UpdateConfig {
    /// The daemon's own clone.
    pub src: PathBuf,
    /// The installed binary that the service runs.
    pub bin: PathBuf,
    /// The cargo to build with; its directory goes first on `PATH` for the build.
    pub cargo: PathBuf,
    /// Argv run in `src`; `None`: `[cargo, build, --release, --locked]`.
    pub build: Option<Vec<String>>,
    /// The built binary, relative to `src`.
    pub artifact: PathBuf,
    /// Least time between attempts.
    pub min_interval: Duration,
    /// How long no hook may have been handled before the swap.
    pub quiet: Duration,
    /// Exit with status 75 after installing, so the service manager starts the new binary.
    pub exit_after_install: bool,
    /// Targets must descend from this commit; the built-in default cannot be set from the CLI.
    pub min_safe: String,
    /// A local minimum on top of `min_safe`: both always apply.
    pub floor: Option<String>,
    /// The commit treated as running for the downgrade decision and `current`; `None` is
    /// `crate::COMMIT`. Not settable from the CLI.
    pub running: Option<String>,
}

impl UpdateConfig {
    pub fn new(src: PathBuf, bin: PathBuf) -> UpdateConfig {
        UpdateConfig {
            src,
            bin,
            cargo: PathBuf::from("cargo"),
            build: None,
            artifact: PathBuf::from("target/release/wormhole"),
            min_interval: Duration::from_secs(300),
            quiet: Duration::from_secs(3),
            exit_after_install: true,
            min_safe: MIN_SAFE_COMMIT.to_string(),
            floor: None,
            running: None,
        }
    }
}

fn beside(bin: &Path, ext: &str) -> PathBuf {
    let mut s = bin.as_os_str().to_owned();
    s.push(ext);
    PathBuf::from(s)
}

/// `<bin>.prev`: the binary before the last swap.
pub fn prev_path(bin: &Path) -> PathBuf {
    beside(bin, ".prev")
}

/// `<bin>.hold`: while it exists the daemon ignores the hub's target.
pub fn hold_path(bin: &Path) -> PathBuf {
    beside(bin, ".hold")
}

/// `<bin>.floors`: every minimum this daemon has run with, one commit id per line. Each is
/// a minimum for targets like `min_safe`, so a binary moved back to an older floor cannot
/// walk further back.
pub fn floors_path(bin: &Path) -> PathBuf {
    beside(bin, ".floors")
}

/// The valid commit ids in the ratchet file, oldest first, without duplicates.
pub fn read_floors(bin: &Path) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for l in std::fs::read_to_string(floors_path(bin))
        .unwrap_or_default()
        .lines()
    {
        let l = l.trim();
        if valid_commit(l) && !out.iter().any(|x| x == l) {
            out.push(l.to_string());
        }
    }
    out
}

/// Add `shas` to the ratchet file when missing, keeping the newest 32, mode 0600.
pub fn record_floors(bin: &Path, shas: &[&str]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut all = read_floors(bin);
    for s in shas.iter().filter(|s| valid_commit(s)) {
        if !all.iter().any(|x| x == s) {
            all.push(s.to_string());
        }
    }
    let skip = all.len().saturating_sub(32);
    let body: String = all[skip..].iter().map(|l| format!("{l}\n")).collect();
    let tmp = beside(bin, ".floors.tmp");
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, floors_path(bin)).map_err(|e| e.to_string())
}

/// A full commit id: 40 characters of `[0-9a-f]`.
pub fn valid_commit(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Swap `<bin>` and `<bin>.prev` and create the hold file, so the daemon stays on the
/// older binary until `resume`.
pub fn revert(bin: &Path) -> Result<(), String> {
    let prev = prev_path(bin);
    if !prev.is_file() {
        return Err("no previous binary".into());
    }
    let tmp = beside(bin, ".swap");
    let e = |what: &str, x: std::io::Error| format!("{what}: {x}");
    std::fs::rename(bin, &tmp).map_err(|x| e("move the current binary aside", x))?;
    if let Err(x) = std::fs::rename(&prev, bin) {
        let _ = std::fs::rename(&tmp, bin);
        return Err(e("restore the previous binary", x));
    }
    std::fs::rename(&tmp, &prev).map_err(|x| e("keep the replaced binary", x))?;
    std::fs::write(hold_path(bin), "held by wormhole update --revert\n")
        .map_err(|x| e("create the hold file", x))
}

/// Remove the hold file. Fine if there is none.
pub fn resume(bin: &Path) -> Result<(), String> {
    match std::fs::remove_file(hold_path(bin)) {
        Ok(()) => Ok(()),
        Err(x) if x.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(x) => Err(format!("remove the hold file: {x}")),
    }
}

/// Copy `bin` to `<bin>.prev` and the built `artifact` over `bin`, each through a temporary
/// file and a rename. A failure before the last rename leaves `bin` as it was; a missing
/// `bin` is a failure too, since there would be nothing to revert to.
pub fn install(bin: &Path, artifact: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = beside(bin, ".prev.tmp");
    std::fs::copy(bin, &tmp).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, prev_path(bin)).map_err(|e| e.to_string())?;
    let new = beside(bin, ".new");
    std::fs::copy(artifact, &new).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    std::fs::rename(&new, bin).map_err(|e| e.to_string())
}

/// Run `program` with explicit `args` in `dir`, no stdin, killed after `timeout`. With
/// `path_first`, that directory leads `PATH`. `None` when it could not run or timed out.
pub async fn run(
    program: &Path,
    args: &[&str],
    dir: &Path,
    timeout: Duration,
    path_first: Option<&Path>,
) -> Option<Output> {
    let mut c = tokio::process::Command::new(program);
    c.args(args)
        .current_dir(dir)
        .stdin(std::process::Stdio::null())
        .env("GIT_TERMINAL_PROMPT", "0")
        .kill_on_drop(true);
    if let Some(p) = path_first {
        let mut dirs = vec![p.to_path_buf()];
        dirs.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        if let Ok(joined) = std::env::join_paths(dirs) {
            c.env("PATH", joined);
        }
    }
    tokio::time::timeout(timeout, c.output()).await.ok()?.ok()
}

/// `git <args>` in `src`.
pub async fn git(src: &Path, args: &[&str], timeout: Duration) -> Option<Output> {
    run(Path::new("git"), args, src, timeout, None).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commits_are_forty_lowercase_hex() {
        assert!(valid_commit(&"a1".repeat(20)));
        assert!(!valid_commit(&"A1".repeat(20)));
        assert!(!valid_commit(&"a1".repeat(19)));
        assert!(!valid_commit(&format!("{}-", "a".repeat(39))));
    }

    #[test]
    fn floors_dedupe_keep_32_and_skip_junk() {
        let d = std::env::temp_dir().join(format!("wh-floors-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let bin = d.join("wormhole");
        let a = "a".repeat(40);
        std::fs::write(floors_path(&bin), format!("junk\n{a}\n")).unwrap();
        record_floors(&bin, &[&a, "nope"]).unwrap();
        assert_eq!(read_floors(&bin), [a.clone()]);
        for i in 0..40 {
            record_floors(&bin, &[&format!("{i:040x}")]).unwrap();
        }
        let f = read_floors(&bin);
        assert_eq!(f.len(), 32);
        assert_eq!(f[31], format!("{:040x}", 39));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn install_keeps_prev_and_revert_holds() {
        let d = std::env::temp_dir().join(format!("wh-upd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let (bin, art) = (d.join("wormhole"), d.join("built"));
        std::fs::write(&bin, "old").unwrap();
        std::fs::write(&art, "new").unwrap();
        assert_eq!(revert(&bin).unwrap_err(), "no previous binary");
        install(&bin, &art).unwrap();
        assert_eq!(std::fs::read_to_string(&bin).unwrap(), "new");
        assert_eq!(std::fs::read_to_string(prev_path(&bin)).unwrap(), "old");
        revert(&bin).unwrap();
        assert_eq!(std::fs::read_to_string(&bin).unwrap(), "old");
        assert_eq!(std::fs::read_to_string(prev_path(&bin)).unwrap(), "new");
        assert!(hold_path(&bin).exists());
        resume(&bin).unwrap();
        resume(&bin).unwrap();
        assert!(!hold_path(&bin).exists());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
