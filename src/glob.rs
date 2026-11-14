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

/// Do two lease scopes overlap? Equal scopes overlap; a glob overlaps a path it matches.
/// Named areas overlap only when equal. shortcut: two different globs are treated as not
/// overlapping; upgrade if teams start leasing overlapping globs.
pub fn overlaps(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    if a.starts_with("area:") || b.starts_with("area:") {
        return false;
    }
    match (is_glob(a), is_glob(b)) {
        (true, false) => matches(a, b),
        (false, true) => matches(b, a),
        _ => false,
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
        assert!(!overlaps("src/*", "src/**"));
    }
}
