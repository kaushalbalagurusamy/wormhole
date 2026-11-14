//! Reduce a hook body to what wormhole needs, while it streams in. Every JSON string longer
//! than `KEEP` bytes (file contents, tool output) is replaced by `""`; everything else is
//! copied. Memory stays bounded whatever the body size, and the event name, session, cwd,
//! tool name and file path survive.

/// Strings up to this many bytes are kept.
const KEEP: usize = 4096;
/// Most bytes of reduced output; more means the body is not a plausible hook input.
const MAX_OUT: usize = 1024 * 1024;

#[derive(Default)]
pub(crate) struct Shrinker {
    out: Vec<u8>,
    cur: Vec<u8>,
    in_str: bool,
    esc: bool,
    long: bool,
    overflow: bool,
}

impl Shrinker {
    fn keep(&mut self, b: u8) {
        if self.long {
            return;
        }
        if self.cur.len() < KEEP {
            self.cur.push(b);
        } else {
            self.long = true;
            self.cur.clear();
        }
    }

    pub fn feed(&mut self, chunk: &[u8]) {
        for &b in chunk {
            if self.overflow {
                return;
            }
            if self.in_str {
                if self.esc {
                    self.esc = false;
                    self.keep(b);
                } else if b == b'\\' {
                    self.esc = true;
                    self.keep(b);
                } else if b == b'"' {
                    self.in_str = false;
                    self.out.push(b'"');
                    if !self.long {
                        self.out.extend_from_slice(&self.cur);
                    }
                    self.out.push(b'"');
                    self.cur.clear();
                    self.long = false;
                } else {
                    self.keep(b);
                }
            } else if b == b'"' {
                self.in_str = true;
            } else {
                self.out.push(b);
            }
            if self.out.len() > MAX_OUT {
                self.overflow = true;
            }
        }
    }

    /// The reduced body, or `None` if it was too large or ended inside a string.
    pub fn finish(self) -> Option<Vec<u8>> {
        (!self.overflow && !self.in_str).then_some(self.out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn shrink(s: &str, chunk: usize) -> Option<Value> {
        let mut sh = Shrinker::default();
        for c in s.as_bytes().chunks(chunk) {
            sh.feed(c);
        }
        serde_json::from_slice(&sh.finish()?).ok()
    }

    #[test]
    fn drops_long_strings_keeps_short_ones() {
        let v = json!({"hook_event_name": "PreToolUse", "tool_input": {
            "file_path": "/r/a \"q\" \\ é.rs", "content": "x\"\\".repeat(10_000)}, "n": [1, 2.5, true, null]});
        for chunk in [1, 7, 4096, 1 << 20] {
            let r = shrink(&v.to_string(), chunk).unwrap();
            assert_eq!(r["hook_event_name"], "PreToolUse");
            assert_eq!(r["tool_input"]["file_path"], "/r/a \"q\" \\ é.rs");
            assert_eq!(r["tool_input"]["content"], "");
            assert_eq!(r["n"], json!([1, 2.5, true, null]));
        }
    }

    #[test]
    fn rejects_oversized_or_unterminated_input() {
        assert!(shrink(&format!("[{}0]", "1,".repeat(MAX_OUT)), 4096).is_none());
        assert!(shrink("{\"a\": \"never closed", 3).is_none());
    }
}
