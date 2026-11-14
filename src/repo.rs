//! Map local paths to a repository id shared across machines, and to repo-relative paths.
//! Reads `.git` directly; does not run git.

use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq)]
pub struct RepoInfo {
    /// The origin remote, normalised (`host/owner/name`), or `local:<dir name>` without one.
    pub id: String,
    pub root: PathBuf,
    pub branch: String,
}

/// Find the repository containing `dir`.
pub fn find(dir: &Path) -> Option<RepoInfo> {
    let mut cur = Some(dir);
    while let Some(d) = cur {
        let dotgit = d.join(".git");
        if let Some(gitdir) = git_dir(&dotgit) {
            // A linked worktree keeps its config in the common dir.
            let common = std::fs::read_to_string(gitdir.join("commondir"))
                .map(|c| gitdir.join(c.trim()))
                .unwrap_or_else(|_| gitdir.clone());
            let config = std::fs::read_to_string(common.join("config")).unwrap_or_default();
            let id = origin_url(&config)
                .map(|u| normalize_remote(&u))
                .unwrap_or_else(|| {
                    format!(
                        "local:{}",
                        d.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default()
                    )
                });
            let head = std::fs::read_to_string(gitdir.join("HEAD")).unwrap_or_default();
            let head = head.trim();
            let branch = head
                .strip_prefix("ref: refs/heads/")
                .map(str::to_string)
                .unwrap_or_else(|| {
                    format!("detached {}", head.chars().take(12).collect::<String>())
                });
            return Some(RepoInfo {
                id,
                root: d.to_path_buf(),
                branch,
            });
        }
        cur = d.parent();
    }
    None
}

fn git_dir(dotgit: &Path) -> Option<PathBuf> {
    if dotgit.is_dir() {
        return Some(dotgit.to_path_buf());
    }
    let s = std::fs::read_to_string(dotgit).ok()?;
    let p = PathBuf::from(s.trim().strip_prefix("gitdir:")?.trim());
    Some(if p.is_absolute() {
        p
    } else {
        dotgit.parent()?.join(p)
    })
}

fn origin_url(config: &str) -> Option<String> {
    let mut in_origin = false;
    for line in config.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            in_origin = l == "[remote \"origin\"]";
        } else if in_origin {
            if let Some((k, v)) = l.split_once('=') {
                if k.trim() == "url" {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

/// `git@github.com:Owner/Repo.git` and `https://github.com/Owner/Repo` both become
/// `github.com/Owner/Repo`.
pub fn normalize_remote(url: &str) -> String {
    let mut u = url.trim().trim_end_matches('/');
    let had_scheme = u.contains("://");
    if let Some((_, rest)) = u.split_once("://") {
        u = rest;
    }
    // Drop user info.
    if let Some((before, after)) = u.split_once('@') {
        if !before.contains('/') {
            u = after;
        }
    }
    let u = u.strip_suffix(".git").unwrap_or(u);
    let s = if had_scheme {
        u.to_string()
    } else {
        // scp-like host:path
        u.replacen(':', "/", 1)
    };
    match s.split_once('/') {
        Some((host, path)) => format!(
            "{}/{}",
            host.to_lowercase().split(':').next().unwrap_or(""),
            path
        ),
        None => s,
    }
}

/// Repo-relative form of `file` (absolute, or relative to `cwd`), with `/` separators.
/// `None` if it lies outside `root`.
pub fn relative(root: &Path, cwd: &Path, file: &str) -> Option<String> {
    use std::path::Component;
    let joined = cwd.join(file);
    let mut parts: Vec<String> = Vec::new();
    let mut root_parts: Vec<String> = Vec::new();
    for (src, out) in [(root, &mut root_parts), (joined.as_path(), &mut parts)] {
        for c in src.components() {
            match c {
                Component::Normal(s) => out.push(s.to_string_lossy().to_string()),
                Component::ParentDir => {
                    out.pop()?;
                }
                _ => {}
            }
        }
    }
    if parts.len() <= root_parts.len() || parts[..root_parts.len()] != root_parts[..] {
        return None;
    }
    Some(parts[root_parts.len()..].join("/"))
}

/// Like `relative`, but resolved on disk: symlinks and `..` are followed for every
/// component that exists, so `link/x` and `a/../x` name the file they really are. The
/// result must lie under the canonical root. Missing trailing components (a file about to
/// be created) are appended as written, and may not contain `..`.
pub fn canonical_relative(root: &Path, cwd: &Path, file: &str) -> Option<String> {
    use std::path::Component;
    let root = std::fs::canonicalize(root).ok()?;
    let abs = cwd.join(file);
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = abs.clone();
    let base = loop {
        if let Ok(c) = std::fs::canonicalize(&cur) {
            break c;
        }
        match cur.components().next_back()? {
            Component::Normal(n) => tail.push(n.to_os_string()),
            Component::CurDir => {}
            _ => return None,
        }
        cur = cur.parent()?.to_path_buf();
    };
    let mut full = base;
    for n in tail.iter().rev() {
        full.push(n);
    }
    let rel = full.strip_prefix(&root).ok()?;
    let parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// Does the filesystem holding `root` ignore case? (macOS and Windows defaults do.)
pub fn case_insensitive(root: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(root) = std::fs::canonicalize(root) else {
        return false;
    };
    let Some(name) = root.file_name().map(|n| n.to_string_lossy().to_string()) else {
        return false;
    };
    let flipped: String = name
        .chars()
        .map(|c| {
            if c.is_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    if flipped == name {
        return false;
    }
    match (
        std::fs::metadata(&root),
        std::fs::metadata(root.with_file_name(flipped)),
    ) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remotes_normalise_to_one_id() {
        for u in [
            "git@github.com:Owner/Repo.git",
            "https://github.com/Owner/Repo",
            "https://user@github.com/Owner/Repo.git/",
            "ssh://git@github.com/Owner/Repo.git",
        ] {
            assert_eq!(normalize_remote(u), "github.com/Owner/Repo", "{u}");
        }
    }

    #[test]
    fn relative_rejects_escapes() {
        let root = Path::new("/w/repo");
        let cwd = Path::new("/w/repo/src");
        assert_eq!(
            relative(root, cwd, "/w/repo/src/a.rs").as_deref(),
            Some("src/a.rs")
        );
        assert_eq!(relative(root, cwd, "b.rs").as_deref(), Some("src/b.rs"));
        assert_eq!(
            relative(root, cwd, "../c/./d.rs").as_deref(),
            Some("c/d.rs")
        );
        assert_eq!(relative(root, cwd, "../../etc/passwd"), None);
        assert_eq!(relative(root, cwd, "/w/repository/x"), None);
        assert_eq!(relative(root, cwd, "/w/repo"), None);
    }

    #[test]
    fn finds_repo_from_git_dir() {
        let base = std::env::temp_dir().join(format!("wh-repo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join(".git")).unwrap();
        std::fs::create_dir_all(base.join("src/deep")).unwrap();
        std::fs::write(
            base.join(".git/config"),
            "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = git@example.com:team/proj.git\n",
        )
        .unwrap();
        std::fs::write(base.join(".git/HEAD"), "ref: refs/heads/feature/x\n").unwrap();
        let r = find(&base.join("src/deep")).unwrap();
        assert_eq!(r.id, "example.com/team/proj");
        assert_eq!(r.branch, "feature/x");
        assert_eq!(r.root, base);
        std::fs::remove_dir_all(&base).unwrap();
    }
}
