//! Lease scopes: a repo-relative path, a path glob (`*` within a segment, `**` across
//! segments), or a named area (`area:<name>`).

/// Does `path` match `pattern`?
pub fn matches(pattern: &str, path: &str) -> bool {
    let _ = (pattern, path);
    todo!()
}

/// Do two lease scopes overlap? Equal scopes overlap; a glob overlaps a path it matches.
/// Named areas overlap only when equal. shortcut: two different globs are treated as not
/// overlapping; upgrade if teams start leasing overlapping globs.
pub fn overlaps(a: &str, b: &str) -> bool {
    let _ = (a, b);
    todo!()
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
