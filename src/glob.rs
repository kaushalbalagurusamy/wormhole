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

/// Path segments of a plain scope, without the trailing `/` of a directory scope.
fn segments(scope: &str) -> Vec<&str> {
    scope.trim_end_matches('/').split('/').collect()
}

/// A directory scope ends with `/`; any other plain scope names a file.
fn is_dir(scope: &str) -> bool {
    scope.ends_with('/')
}

/// `a` is `b` or an ancestor of it, segment by segment.
fn segment_prefix(a: &[&str], b: &[&str]) -> bool {
    a.len() <= b.len() && a == &b[..a.len()]
}

/// The literal directories of a recursive glob (`**` or `<dirs>/**`), or `None` if the
/// glob is not recursive (`src/a**` is not).
fn recursive_base(glob: &str) -> Option<Vec<&str>> {
    let base: Vec<&str> = if glob == "**" {
        vec![]
    } else {
        glob.strip_suffix("/**")?.split('/').collect()
    };
    (!base.iter().any(|s| s.contains('*'))).then_some(base)
}

/// Does `outer` cover everything `inner` can name? Conservative: false when unsure, so a
/// transfer that relies on it is refused rather than dropping a lease.
pub fn covers(outer: &str, inner: &str) -> bool {
    if outer == inner {
        return true;
    }
    if outer.starts_with("area:") || inner.starts_with("area:") {
        return false;
    }
    match (is_glob(outer), is_glob(inner)) {
        // A file: a glob that matches it, or an enclosing directory scope.
        (true, false) if !is_dir(inner) => matches(outer, inner),
        // A directory: only a recursive glob over it covers everything under it.
        (true, false) => {
            recursive_base(outer).is_some_and(|b| segment_prefix(&b, &segments(inner)))
        }
        (false, false) => is_dir(outer) && segment_prefix(&segments(outer), &segments(inner)),
        (false, true) => is_dir(outer) && segment_prefix(&segments(outer), &literal_prefix(inner)),
        (true, true) => {
            recursive_base(outer).is_some_and(|b| segment_prefix(&b, &literal_prefix(inner)))
        }
    }
}

/// Do two lease scopes overlap? Equal scopes overlap; a glob overlaps a file it matches and
/// a directory its literal prefix is compatible with; a directory scope (ending in `/`)
/// overlaps what is under it. Named areas overlap only when equal. Two globs overlap when
/// one's literal prefix is a segment-prefix of the other's: conservative, so `src/a*` and
/// `src/b*` count as overlapping. A false positive only adds a warning.
pub fn overlaps(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    if a.starts_with("area:") || b.starts_with("area:") {
        return false;
    }
    let compatible = |x: &[&str], y: &[&str]| segment_prefix(x, y) || segment_prefix(y, x);
    match (is_glob(a), is_glob(b)) {
        (true, false) | (false, true) => {
            let (g, p) = if is_glob(a) { (a, b) } else { (b, a) };
            if is_dir(p) {
                compatible(&literal_prefix(g), &segments(p))
            } else {
                matches(g, p)
            }
        }
        (true, true) => compatible(&literal_prefix(a), &literal_prefix(b)),
        (false, false) => match (is_dir(a), is_dir(b)) {
            (false, false) => false,
            (true, false) => segment_prefix(&segments(a), &segments(b)),
            (false, true) => segment_prefix(&segments(b), &segments(a)),
            (true, true) => compatible(&segments(a), &segments(b)),
        },
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
        assert!(!covers("src", "src/a.rs"));
        assert!(covers("src/", "src/hub/**"));
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
