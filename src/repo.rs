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
    let _ = dir;
    todo!()
}

/// `git@github.com:Owner/Repo.git` and `https://github.com/Owner/Repo` both become
/// `github.com/Owner/Repo`.
pub fn normalize_remote(url: &str) -> String {
    let _ = url;
    todo!()
}

/// Repo-relative form of `file` (absolute, or relative to `cwd`), with `/` separators.
/// `None` if it lies outside `root`.
pub fn relative(root: &Path, cwd: &Path, file: &str) -> Option<String> {
    let _ = (root, cwd, file);
    todo!()
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
        assert_eq!(relative(root, cwd, "/w/repo/src/a.rs").as_deref(), Some("src/a.rs"));
        assert_eq!(relative(root, cwd, "b.rs").as_deref(), Some("src/b.rs"));
        assert_eq!(relative(root, cwd, "../c/./d.rs").as_deref(), Some("c/d.rs"));
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
