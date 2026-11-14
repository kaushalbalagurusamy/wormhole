//! Lease scopes: a repo-relative path, a path glob (`*` within a segment, `**` across
//! segments), or a named area (`area:<name>`).

/// Does `path` match `pattern`?
pub fn matches(pattern: &str, path: &str) -> bool {
    let p: Vec<&str> = pattern.split('/').collect();
    let s: Vec<&str> = path.split('/').collect();
    match_segments(&p, &s)
}

fn match_segments(p: &[&str], s: &[&str]) -> bool {
    match p.split_first() {
        None => s.is_empty(),
        Some((&"**", rest)) => (0..=s.len()).any(|i| match_segments(rest, &s[i..])),
        Some((first, rest)) => {
            !s.is_empty()
                && match_segment(first.as_bytes(), s[0].as_bytes())
                && match_segments(rest, &s[1..])
        }
    }
}

// Greedy wildcard match with one backtrack point: O(len(p) * len(s)), no recursion.
fn match_segment(p: &[u8], s: &[u8]) -> bool {
    let (mut pi, mut si) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, si));
            pi += 1;
        } else if pi < p.len() && p[pi] == s[si] {
            pi += 1;
            si += 1;
        } else if let Some((sp, ss)) = star {
            pi = sp + 1;
            si = ss + 1;
            star = Some((sp, ss + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

/// Patterns the hub accepts: bounded `**` count, so matching stays cheap.
pub fn valid(pattern: &str) -> bool {
    pattern.split('/').filter(|s| *s == "**").count() <= 4
}

fn is_glob(s: &str) -> bool {
    s.contains('*')
}

/// Path segments before the first one containing a wildcard.
fn literal_prefix(glob: &str) -> Vec<&str> {
    glob.split('/')
        .take_while(|seg| !seg.contains('*'))
        .collect()
}

/// Does `outer` cover everything `inner` can name? Conservative: false when unsure.
pub fn covers(outer: &str, inner: &str) -> bool {
    if outer == inner {
        return true;
    }
    if outer.starts_with("area:") || inner.starts_with("area:") {
        return false;
    }
    let segment_prefix = |a: &[&str], b: &[&str]| a.len() <= b.len() && a == &b[..a.len()];
    let outer_dir: Vec<&str> = outer.split('/').collect();
    match (is_glob(outer), is_glob(inner)) {
        // A plain scope may name a directory, so the glob must also cover what is under it.
        (true, false) => matches(outer, inner) && matches(outer, &format!("{inner}/x")),
        (false, false) => segment_prefix(&outer_dir, &inner.split('/').collect::<Vec<_>>()),
        // A glob inside a directory, or inside `<dir>/**`.
        (false, true) => segment_prefix(&outer_dir, &literal_prefix(inner)),
        (true, true) => {
            // Only `**` or `<literal dirs>/**` is a recursive glob; `src/a**` is not.
            let base: Vec<&str> = if outer == "**" {
                vec![]
            } else if let Some(b) = outer.strip_suffix("/**") {
                b.split('/').collect()
            } else {
                return false;
            };
            !base.iter().any(|s| s.contains('*')) && segment_prefix(&base, &literal_prefix(inner))
        }
    }
}

/// A directory scope (`src/auth`) overlaps a glob under it (`src/auth/**`).
fn overlaps_glob_prefix(glob: &str, path: &str) -> bool {
    let (g, p): (Vec<&str>, Vec<&str>) = (literal_prefix(glob), path.split('/').collect());
    p.len() <= g.len() && g[..p.len()] == p[..]
}

/// Do two lease scopes overlap? Equal scopes overlap; a glob overlaps a path it matches.
/// Named areas overlap only when equal. Two globs overlap when one's literal prefix is a
/// segment-prefix of the other's: conservative, so `src/a*` and `src/b*` count as
/// overlapping. A false positive only adds a warning.
pub fn overlaps(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    if a.starts_with("area:") || b.starts_with("area:") {
        return false;
    }
    match (is_glob(a), is_glob(b)) {
        (true, false) => matches(a, b) || overlaps_glob_prefix(a, b),
        (false, true) => matches(b, a) || overlaps_glob_prefix(b, a),
        (true, true) => {
            let (pa, pb) = (literal_prefix(a), literal_prefix(b));
            let n = pa.len().min(pb.len());
            pa[..n] == pb[..n]
        }
        // A path scope covers what is under it: `src/auth` overlaps `src/auth/login.rs`.
        (false, false) => {
            let (pa, pb): (Vec<&str>, Vec<&str>) = (a.split('/').collect(), b.split('/').collect());
            let n = pa.len().min(pb.len());
            pa[..n] == pb[..n]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_and_star() {
        assert!(matches("src/lib.rs", "src/lib.rs"));
        assert!(!matches("src/lib.rs", "src/lib.rsx"));
        assert!(matches("src/*.rs", "src/lib.rs"));
        assert!(!matches("src/*.rs", "src/a/lib.rs"));
        assert!(matches("*", "README.md"));
    }

    #[test]
    fn double_star() {
        assert!(matches("src/**", "src/a/b/c.rs"));
        assert!(matches("src/**", "src/c.rs"));
        assert!(matches("**/*.rs", "src/a/c.rs"));
        assert!(matches("**/*.rs", "c.rs"));
        assert!(matches("secrets/**/key", "secrets/key"));
        assert!(!matches("src/**", "srcx/c.rs"));
    }

    #[test]
    fn overlap_rules() {
        assert!(overlaps("src/a.rs", "src/a.rs"));
        assert!(overlaps("src/**", "src/a.rs"));
        assert!(overlaps("src/a.rs", "src/**"));
        assert!(!overlaps("src/a.rs", "src/b.rs"));
        assert!(overlaps("area:auth", "area:auth"));
        assert!(!overlaps("area:auth", "area:billing"));
        assert!(!overlaps("area:*", "area:auth"));
    }

    #[test]
    fn covers_is_containment_not_overlap() {
        assert!(covers("src/hub/*", "src/hub/a.rs"));
        assert!(covers("src/**", "src/hub/*"));
        assert!(covers("src/**", "src/hub/a.rs"));
        assert!(covers("src", "src/a.rs"));
        assert!(covers("src", "src/hub/**"));
        // Plain scopes are files; a directory scope ends with `/` (the lease tool adds it for an
        // existing directory). A glob covers a file it matches, and a directory only if it
        // covers everything under it.
        assert!(covers("src/*.rs", "src/a.rs"));
        assert!(covers("src/*", "src/hub"));
        assert!(!covers("src/*", "src/hub/"));
        assert!(covers("src/**", "src/hub/"));
        assert!(covers("src/**", "src/a/b"));
        assert!(covers("src/", "src/a.rs"));
        assert!(covers("src/", "src/hub/"));
        assert!(!covers("src/hub/", "src/"));
        assert!(covers("**", "x"));
        // `a**` is not a recursive glob.
        assert!(!covers("src/a**", "src/a/b"));
        assert!(!covers("src/a**", "src/a/*"));
        assert!(covers("x", "x"));
        assert!(!covers("src/hub/*", "src/**"));
        assert!(!covers("src/hub/a.rs", "src/hub/*"));
        assert!(!covers("src/a*", "src/b*"));
        assert!(!covers("src/*", "src/hub/*"));
        assert!(!covers("area:auth", "area:auth/x"));
    }

    #[test]
    fn a_directory_scope_covers_what_is_under_it() {
        assert!(overlaps("src/auth/", "src/auth/login.rs"));
        assert!(overlaps("src/auth/login.rs", "src/auth/"));
        assert!(overlaps("src/auth/", "src/auth/**"));
        assert!(overlaps("src/auth/", "src/"));
        assert!(!overlaps("src/auth/", "src/authz/x.rs"));
        // A plain scope is a file.
        assert!(!overlaps("src/auth", "src/auth/login.rs"));
        assert!(!overlaps("src/a.rs", "src/a.rs.bak"));
    }

    #[test]
    fn globs_overlap_conservatively() {
        assert!(overlaps("src/**", "src/hub/*"));
        assert!(overlaps("src/hub/*", "src/**"));
        assert!(overlaps("src/*.rs", "src/**"));
        assert!(overlaps("src/*", "src/**"));
        assert!(overlaps("**", "docs/*.md"));
        assert!(!overlaps("docs/**", "src/**"));
        assert!(!overlaps("src/hub/*", "src/daemon/*"));
        // Same directory, different name patterns: reported as overlapping (a false
        // positive is only an extra warning).
        assert!(overlaps("src/a*", "src/b*"));
    }
}
