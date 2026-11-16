//! The receiving owner's delegation policy: who may hand this machine's sessions tasks, at
//! what permission level, inside which boundary, and what is never allowed. The file is
//! local; nothing in a request can raise a level. See docs/adr/0001-delegation.md.

use crate::glob;
use crate::proto::Contract;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    Off,
    Inform,
    ScopedInstruction,
    ScopedBypass,
    FullBypass,
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Off => "off",
            Level::Inform => "inform",
            Level::ScopedInstruction => "scoped-instruction",
            Level::ScopedBypass => "scoped-bypass",
            Level::FullBypass => "full-bypass",
        }
    }

    pub fn parse(s: &str) -> Option<Level> {
        [
            Level::Off,
            Level::Inform,
            Level::ScopedInstruction,
            Level::ScopedBypass,
            Level::FullBypass,
        ]
        .into_iter()
        .find(|l| l.as_str() == s)
    }
}

pub const DEFAULT_DENY_KINDS: &[&str] = &[
    "force-push",
    "delete-branch",
    "delete-data",
    "deploy",
    "merge-pr",
    "publish",
    "external-message",
    "secrets",
];

pub const DEFAULT_DENY_COMMANDS: &[&str] = &[
    "push --force",
    "push -f",
    "--force-with-lease",
    "push --delete",
    "push origin :",
    "branch -d",
    "git reset --hard",
    "git clean -f",
    "rm -rf",
    "rm -fr",
    "drop table",
    "drop database",
    "truncate table",
    "gh pr merge",
    "git merge",
    "deploy",
    "kubectl",
    "terraform apply",
    "npm publish",
    "cargo publish",
    "twine upload",
    "gh release",
    "curl ",
    "wget ",
    "ssh ",
    "scp ",
    "sendmail",
    "mail ",
    "printenv",
    "security find-",
    "gpg --export-secret",
    "cat .env",
];

pub const DEFAULT_DENY_PATHS: &[&str] = &[
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/secrets/**",
    "**/.git/**",
    "**/.ssh/**",
];

/// Longest a contract may stay open whatever the grant says.
const MAX_TTL_SECS: u64 = 14_400;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGrant {
    #[serde(default)]
    from: Vec<String>,
    #[serde(default)]
    repos: Vec<String>,
    #[serde(default = "star")]
    task_ids: Vec<String>,
    level: String,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    kinds: Vec<String>,
    #[serde(default)]
    commands: Vec<String>,
    #[serde(default = "default_ttl")]
    max_ttl_secs: u64,
    #[serde(default = "default_steps")]
    max_steps: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDeny {
    #[serde(default = "yes")]
    enabled: bool,
    kinds: Option<Vec<String>>,
    commands: Option<Vec<String>>,
    paths: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    #[serde(default)]
    grants: Vec<RawGrant>,
    denylist: Option<RawDeny>,
}

fn star() -> Vec<String> {
    vec!["*".into()]
}
fn default_ttl() -> u64 {
    3600
}
fn default_steps() -> u64 {
    200
}
fn yes() -> bool {
    true
}

struct Grant {
    from: Vec<String>,
    repos: Vec<String>,
    task_ids: Vec<String>,
    level: Level,
    paths: Vec<String>,
    kinds: Vec<String>,
    commands: Vec<String>,
    max_ttl_secs: u64,
    max_steps: u64,
}

/// Lists are lowercased and whitespace-collapsed at load.
struct Deny {
    kinds: Vec<String>,
    commands: Vec<String>,
    paths: Vec<String>,
}

pub struct Policy {
    grants: Vec<Grant>,
    deny: Option<Deny>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    pub level: Level,
    pub accepted: bool,
    pub reason: String,
    pub ttl_secs: u64,
    pub max_steps: u64,
}

fn collapse(s: &str) -> String {
    s.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn no(level: Level, reason: impl Into<String>) -> Decision {
    Decision {
        level,
        accepted: false,
        reason: reason.into(),
        ttl_secs: 0,
        max_steps: 0,
    }
}

impl Policy {
    pub fn load(path: &Path) -> Result<Policy, String> {
        let s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Policy::parse(&s)
    }

    pub fn parse(json: &str) -> Result<Policy, String> {
        let raw: RawPolicy = serde_json::from_str(json).map_err(|e| e.to_string())?;
        let deny = match raw.denylist {
            Some(d) if !d.enabled => None,
            d => {
                let d = d.unwrap_or(RawDeny {
                    enabled: true,
                    kinds: None,
                    commands: None,
                    paths: None,
                });
                let list = |v: Option<Vec<String>>, default: &[&str]| -> Vec<String> {
                    v.unwrap_or_else(|| default.iter().map(|s| s.to_string()).collect())
                };
                Some(Deny {
                    kinds: list(d.kinds, DEFAULT_DENY_KINDS)
                        .iter()
                        .map(|k| k.to_lowercase())
                        .collect(),
                    commands: list(d.commands, DEFAULT_DENY_COMMANDS)
                        .iter()
                        .map(|c| collapse(c))
                        .filter(|c| !c.is_empty())
                        .collect(),
                    paths: list(d.paths, DEFAULT_DENY_PATHS)
                        .iter()
                        .map(|p| p.to_lowercase())
                        .collect(),
                })
            }
        };
        let mut grants = Vec::new();
        for (i, g) in raw.grants.into_iter().enumerate() {
            let n = i + 1;
            let level = Level::parse(&g.level)
                .ok_or_else(|| format!("grant {n}: unknown level {:?}", g.level))?;
            if g.from.is_empty() || g.from.iter().any(|f| f.is_empty() || f.contains('*')) {
                return Err(format!(
                    "grant {n}: `from` must name senders exactly (user or user@machine), no wildcards"
                ));
            }
            if g.repos.is_empty() || g.repos.iter().any(String::is_empty) {
                return Err(format!("grant {n}: `repos` must not be empty"));
            }
            if level == Level::ScopedInstruction || level == Level::ScopedBypass {
                if g.paths.is_empty() {
                    return Err(format!("grant {n}: a scoped level needs `paths`"));
                }
                if g.kinds.is_empty() {
                    return Err(format!("grant {n}: a scoped level needs `kinds`"));
                }
            }
            if level > Level::Inform {
                if let Some(k) = deny
                    .as_ref()
                    .and_then(|d| g.kinds.iter().find(|k| d.kinds.contains(&k.to_lowercase())))
                {
                    return Err(format!("grant {n}: denylisted kind {k:?}"));
                }
            }
            grants.push(Grant {
                from: g.from,
                repos: g.repos,
                task_ids: g.task_ids,
                level,
                paths: g.paths,
                kinds: g.kinds,
                commands: g.commands,
                max_ttl_secs: g.max_ttl_secs,
                max_steps: g.max_steps,
            });
        }
        Ok(Policy { grants, deny })
    }

    /// Decide a request from the hub-stamped sender. The level comes from a grant, never
    /// from the request.
    pub fn evaluate(
        &self,
        from_user: &str,
        from_machine: &str,
        repo: &str,
        c: &Contract,
    ) -> Decision {
        let who = format!("{from_user}@{from_machine}");
        let mut hits: Vec<&Grant> = self
            .grants
            .iter()
            .filter(|g| {
                g.from.iter().any(|f| f == from_user || *f == who)
                    && g.repos.iter().any(|r| r == "*" || r == repo)
                    && g.task_ids.iter().any(|t| glob::wildcard(t, &c.task_id))
            })
            .collect();
        if hits.is_empty() {
            return no(
                Level::Off,
                "no grant matches this sender, repository and task id",
            );
        }
        if hits.iter().any(|g| g.level == Level::Off) {
            return no(Level::Off, "declined by an off grant");
        }
        hits.sort_by_key(|g| std::cmp::Reverse(g.level));
        let mut first_refusal: Option<String> = None;
        for g in hits {
            if g.level == Level::Inform {
                first_refusal.get_or_insert_with(|| "inform".into());
                continue;
            }
            match self.fits(g, c) {
                Ok(()) => {
                    let cap = |want: u64, max: u64| if want == 0 { max } else { want.min(max) };
                    return Decision {
                        level: g.level,
                        accepted: true,
                        reason: format!("within the {} grant", g.level.as_str()),
                        ttl_secs: cap(c.ttl_secs, g.max_ttl_secs).min(MAX_TTL_SECS),
                        max_steps: cap(c.max_steps, g.max_steps),
                    };
                }
                Err(why) => {
                    first_refusal.get_or_insert(why);
                }
            }
        }
        no(
            Level::Inform,
            first_refusal.unwrap_or_else(|| "inform".into()),
        )
    }

    /// Does the contract fit this grant's boundary? The error says what it exceeds.
    fn fits(&self, g: &Grant, c: &Contract) -> Result<(), String> {
        if c.task_id.is_empty() {
            return Err("the contract has no task id".into());
        }
        if g.level != Level::FullBypass {
            if c.kind.is_empty() || !(g.kinds.iter().any(|k| k == "*" || *k == c.kind)) {
                return Err(format!("kind {:?} is outside the grant", c.kind));
            }
            if c.paths.is_empty() {
                return Err("the contract names no paths".into());
            }
            if let Some(p) = c
                .paths
                .iter()
                .find(|p| !g.paths.iter().any(|gp| glob::covers(gp, p)))
            {
                return Err(format!("path {p:?} is outside the grant"));
            }
        }
        if g.level >= Level::ScopedBypass && c.exit.trim().is_empty() {
            return Err("a bypass level needs an exit condition".into());
        }
        if g.level == Level::ScopedBypass {
            if let Some(x) = c
                .commands
                .iter()
                .find(|x| !g.commands.iter().any(|gc| gc == "*" || gc == *x))
            {
                return Err(format!("command {x:?} is outside the grant"));
            }
        }
        if let Some(d) = &self.deny {
            if d.kinds.contains(&c.kind.to_lowercase()) {
                return Err(format!("kind {:?} is denylisted", c.kind));
            }
            for p in &c.paths {
                if let Some(hit) = self.denied_path(p) {
                    return Err(format!("path {p:?} matches denylisted glob {hit}"));
                }
            }
            let texts = [&c.text, &c.exit, &c.spec]
                .into_iter()
                .chain(c.commands.iter());
            for t in texts {
                if let Some(hit) = self.denied_command(t) {
                    return Err(format!(
                        "denylisted command pattern {hit:?} appears in the contract"
                    ));
                }
            }
        }
        Ok(())
    }

    /// The denylisted kinds, empty when the module is off.
    pub fn deny_kinds(&self) -> Vec<String> {
        self.deny
            .as_ref()
            .map(|d| d.kinds.clone())
            .unwrap_or_default()
    }

    /// The denylisted command pattern in `command`, if the module is on.
    pub fn denied_command(&self, command: &str) -> Option<String> {
        let d = self.deny.as_ref()?;
        // A trailing space lets patterns such as `curl ` match a bare `curl`.
        let hay = format!("{} ", collapse(command));
        d.commands
            .iter()
            .find(|p| hay.contains(p.as_str()))
            .cloned()
    }

    /// The denylisted path glob that matches `rel`, if the module is on.
    pub fn denied_path(&self, rel: &str) -> Option<String> {
        let d = self.deny.as_ref()?;
        let rel = rel.to_lowercase();
        d.paths.iter().find(|g| glob::matches(g, &rel)).cloned()
    }
}

fn beside(policy: &Path, suffix: &str) -> PathBuf {
    let mut name = policy.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    policy.with_file_name(name)
}

/// Where the audit log of a policy lives.
pub fn audit_path(policy: &Path) -> PathBuf {
    beside(policy, ".audit.jsonl")
}

fn kill_path(policy: &Path) -> PathBuf {
    beside(policy, ".revoked")
}

/// Set the kill switch: every request becomes information only and open contracts close.
pub fn revoke(policy: &Path) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let p = kill_path(policy);
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)
        .map(|_| ())
        .map_err(|e| format!("create {}: {e}", p.display()))
}

pub fn resume(policy: &Path) -> Result<(), String> {
    match std::fs::remove_file(kill_path(policy)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
        _ => Ok(()),
    }
}

pub fn revoked(policy: &Path) -> bool {
    std::fs::symlink_metadata(kill_path(policy)).is_ok()
}

/// Append one JSON line to the audit log (mode 0600). Best effort: a full disk must not
/// turn a refusal into an allow, and an allow is only given after this runs.
pub fn audit(policy: &Path, event: &str, seq: u64, session: &str, level: &str, extra: Value) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut line = json!({
        "ts": crate::proto::now_ms(), "event": event, "seq": seq,
        "session": session, "level": level,
    });
    if let (Some(l), Value::Object(x)) = (line.as_object_mut(), extra) {
        l.extend(x);
    }
    let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(audit_path(policy))
    else {
        return;
    };
    let _ = writeln!(f, "{line}");
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"{"grants": [
      {"from": ["alice@machine-a"], "repos": ["example.com/team/proj"], "task_ids": ["T-*"],
       "level": "scoped-bypass", "paths": ["src/**"], "kinds": ["tests", "fix"],
       "commands": ["cargo test*"], "max_ttl_secs": 600, "max_steps": 5},
      {"from": ["alice"], "repos": ["*"], "level": "scoped-instruction",
       "paths": ["src/**", "docs/"], "kinds": ["*"]},
      {"from": ["carol"], "repos": ["*"], "level": "inform"},
      {"from": ["dave"], "repos": ["*"], "level": "off"},
      {"from": ["dave", "erin"], "repos": ["*"], "level": "full-bypass"}
    ]}"#;

    fn contract() -> Contract {
        Contract {
            task_id: "T-12".into(),
            kind: "tests".into(),
            paths: vec!["src/glob.rs".into()],
            commands: vec!["cargo test*".into()],
            exit: "tests pass".into(),
            text: "add tests".into(),
            ..Default::default()
        }
    }

    fn eval(p: &Policy, user: &str, c: &Contract) -> Decision {
        p.evaluate(user, "machine-a", "example.com/team/proj", c)
    }

    #[test]
    fn the_highest_fitting_grant_applies_and_limits_are_clamped() {
        let p = Policy::parse(POLICY).unwrap();
        let d = eval(&p, "alice", &contract());
        assert_eq!((d.level, d.accepted), (Level::ScopedBypass, true));
        assert_eq!((d.ttl_secs, d.max_steps), (600, 5));
        let mut c = contract();
        c.ttl_secs = 60;
        c.max_steps = 9000;
        let d = eval(&p, "alice", &c);
        assert_eq!((d.ttl_secs, d.max_steps), (60, 5));
        // A command outside the grant drops to the next grant that fits.
        c.commands = vec!["cargo build".into()];
        let d = eval(&p, "alice", &c);
        assert_eq!((d.level, d.accepted), (Level::ScopedInstruction, true));
        // Outside every boundary: information only, with the refusal as the reason.
        c.paths = vec!["Cargo.toml".into()];
        let d = eval(&p, "alice", &c);
        assert_eq!((d.level, d.accepted), (Level::Inform, false));
        assert!(d.reason.contains("outside"), "{}", d.reason);
    }

    #[test]
    fn senders_are_named_exactly_and_off_wins() {
        let p = Policy::parse(POLICY).unwrap();
        let d = eval(&p, "mallory", &contract());
        assert_eq!((d.level, d.accepted), (Level::Off, false));
        assert!(d.reason.contains("no grant"));
        assert_eq!(eval(&p, "dave", &contract()).level, Level::Off);
        assert_eq!(eval(&p, "erin", &contract()).level, Level::FullBypass);
        let d = eval(&p, "carol", &contract());
        assert_eq!(
            (d.level, d.accepted, d.reason.as_str()),
            (Level::Inform, false, "inform")
        );
        // The machine part must match when the grant names one.
        let d = p.evaluate("alice", "machine-b", "example.com/team/proj", &contract());
        assert_eq!(d.level, Level::ScopedInstruction);
        // A task id outside the pattern does not use that grant.
        let mut c = contract();
        c.task_id = "X-1".into();
        assert_eq!(eval(&p, "alice", &c).level, Level::ScopedInstruction);
    }

    #[test]
    fn denylist_refuses_kinds_paths_and_commands_and_can_be_edited_or_off() {
        let p = Policy::parse(POLICY).unwrap();
        let mut c = contract();
        c.text = "then run cargo  PUBLISH to finish".into();
        let d = eval(&p, "alice", &c);
        assert!(!d.accepted && d.reason.contains("cargo publish"), "{d:?}");
        let mut c = contract();
        c.paths = vec![".git/config".into()];
        assert!(!eval(&p, "alice", &c).accepted);
        let off = Policy::parse(
            r#"{"grants":[{"from":["a"],"repos":["*"],"level":"full-bypass"}],
                "denylist":{"enabled":false}}"#,
        )
        .unwrap();
        let mut c = contract();
        c.text = "rm -rf target".into();
        assert!(off.evaluate("a", "m", "r", &c).accepted);
        assert!(off.denied_command("rm -rf /").is_none());
        let edited = Policy::parse(
            r#"{"grants":[{"from":["a"],"repos":["*"],"level":"full-bypass"}],
                "denylist":{"commands":["make clean"],"paths":["build/**"],"kinds":[]}}"#,
        )
        .unwrap();
        assert!(edited.denied_command("make   CLEAN").is_some());
        assert!(edited.denied_command("rm -rf /").is_none());
        assert_eq!(edited.denied_path("build/x.o").as_deref(), Some("build/**"));
        assert!(edited.denied_path(".env").is_none());
        let on = Policy::parse(POLICY).unwrap();
        assert!(on.denied_path("a/b/.env").is_some() && on.denied_path("src/a.rs").is_none());
        assert!(on.denied_command("git push --force origin x").is_some());
        assert!(on.denied_command("cargo test --lib").is_none());
    }

    #[test]
    fn load_errors_name_the_problem() {
        let err = |j: &str| Policy::parse(j).err().expect("should fail");
        let g = |body: &str| format!(r#"{{"grants":[{{{body}}}]}}"#);
        assert!(err(&g(r#""from":["a"],"repos":["*"],"level":"root""#)).contains("unknown level"));
        assert!(err(&g(r#""from":["*"],"repos":["*"],"level":"inform""#)).contains("from"));
        assert!(err(&g(r#""from":[],"repos":["*"],"level":"inform""#)).contains("from"));
        assert!(err(&g(r#""from":["a"],"repos":[],"level":"inform""#)).contains("repos"));
        let scoped = r#""from":["a"],"repos":["*"],"level":"scoped-bypass""#;
        assert!(err(&g(&format!(r#"{scoped},"kinds":["x"]"#))).contains("paths"));
        assert!(err(&g(&format!(r#"{scoped},"paths":["src/**"]"#))).contains("kinds"));
        assert!(err(&g(&format!(
            r#"{scoped},"paths":["src/**"],"kinds":["deploy"]"#
        )))
        .contains("denylisted kind"));
        assert!(!err("not json").is_empty());
        assert!(!err(r#"{"grants":[],"extra":1}"#).is_empty());
        assert!(Policy::parse(r#"{"grants":[]}"#).is_ok());
    }

    #[test]
    fn kill_switch_and_audit_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("wh-deleg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("policy.json");
        assert!(!revoked(&p));
        revoke(&p).unwrap();
        assert!(revoked(&p));
        assert!(dir.join("policy.json.revoked").exists());
        resume(&p).unwrap();
        resume(&p).unwrap();
        assert!(!revoked(&p));
        audit(&p, "request", 7, "s", "inform", json!({"accepted": false}));
        audit(&p, "close", 7, "s", "inform", json!({"reason": "ttl"}));
        let a = audit_path(&p);
        assert_eq!(a, dir.join("policy.json.audit.jsonl"));
        assert_eq!(
            std::fs::metadata(&a).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let lines: Vec<Value> = std::fs::read_to_string(&a)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["event"], "request");
        assert_eq!(lines[1]["reason"], "ttl");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
