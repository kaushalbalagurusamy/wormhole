//! Embeds the commit the binary is built from, so `wormhole version` and the daemon's
//! update status can name it.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let o = Command::new("git").args(args).output().ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn main() {
    let commit = git(&["rev-parse", "HEAD"])
        .filter(|c| c.len() == 40 && c.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=WORMHOLE_COMMIT={commit}");
    // Rebuild when the checked-out commit moves.
    if let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={head}");
    }
    if let Some(r) = git(&["symbolic-ref", "-q", "HEAD"]) {
        if let Some(p) = git(&["rev-parse", "--git-path", &r]) {
            println!("cargo:rerun-if-changed={p}");
        }
    }
    println!("cargo:rerun-if-changed=build.rs");
}
