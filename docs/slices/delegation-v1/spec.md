# Slice delegation-v1: delegated tasks between trusted sessions

Source: `docs/requirements/delegation.md`. Decisions: `docs/adr/0001-delegation.md`. This spec pins the public
surface so tests can be written before the code. Names, strings marked **pinned** and JSON shapes here are the
contract; anything not stated is the implementer's choice.

## UX stories

1. Alice's session hands Bob's session a task ("add tests for the glob module", paths `src/glob.rs`, kind
   `tests`, task id `T-12`). Bob's owner granted Alice `scoped-instruction` for `src/**`. Bob's session is told the
   task is its user's instruction inside that boundary, holds the leases on the paths, works with its normal
   prompts, and posts a result. Alice's session sees the acknowledgement and the result as notices and in
   `wormhole_who`.
2. Same, with a `scoped-bypass` grant and a contract with commands `cargo test*`, an exit condition, a TTL and a
   step budget. Bob's edits inside `src/**` and `cargo test --lib` run without a prompt until the contract ends.
   `cargo test; rm -rf ~` and edits outside the paths prompt as usual.
3. A sender Bob never granted, a request outside the grant, or a request while the kill switch is set, reaches
   Bob's session as information only (or not at all for `off`), and Alice's session is told why.
4. Bob runs `wormhole delegation revoke --policy FILE`; every open contract closes, its leases are released, the
   senders are told, and no further bypass answer is given until `wormhole delegation resume`.
5. A machine without a policy, an old daemon or an old hub behaves exactly as before.

## A. Wire protocol (`src/proto.rs`)

    pub const CAP_DELEGATION: &str = "delegation";

    // Changed variants (new fields default to empty, so old frames parse):
    Up::Resume   { from: Option<u64>, #[serde(default)] caps: Vec<String> }
    Down::Welcome{ user, machine, head, #[serde(default)] caps: Vec<String> }
    Snapshot     { sessions, leases, #[serde(default)] delegations: Vec<DelegationInfo> }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
    pub struct Contract {
        pub task_id: String,
        pub kind: String,
        #[serde(default)] pub spec: String,          // spec or slice reference
        #[serde(default)] pub paths: Vec<String>,    // repo-relative files, dirs ending '/', or globs
        #[serde(default)] pub commands: Vec<String>, // command patterns, '*' matches any characters
        #[serde(default)] pub exit: String,          // what done means
        #[serde(default)] pub ttl_secs: u64,         // 0: the grant's maximum
        #[serde(default)] pub max_steps: u64,        // 0: the grant's maximum
        #[serde(default)] pub result_fields: Vec<String>, // keys a `done` result must carry
        pub text: String,                            // task text
    }

    // New Request variants:
    Delegate       { session: String, to: String, repo: String, contract: Contract }
    DelegateAck    { session: String, request: u64, accept: bool, level: String, reason: String, ttl_ms: u64 }
    DelegateResult { session: String, request: u64, status: String, summary: String,
                     #[serde(default)] fields: serde_json::Map<String, serde_json::Value> }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
    pub struct DelegationInfo {
        pub seq: u64, pub from_session: String, pub from_user: String, pub from_machine: String,
        pub to_session: String, pub to_user: String, pub to_machine: String, pub repo: String,
        pub task_id: String, pub kind: String, pub status: String, pub level: String,
        pub summary: String, pub ts: u64,
    }

Compatibility rules: a daemon sends `caps: ["delegation"]` only when it was started with a valid delegation
policy; the hub always sends `caps: ["delegation"]`. A daemon never sends `Delegate`, `DelegateAck` or
`DelegateResult` unless the hub's `Welcome` on the current connection listed `"delegation"`.

## B. Hub (`src/hub/`)

Statuses (**pinned** strings): `pending`, `accepted`, `informed`, `declined`, `expired`, `done`, `failed`,
`partial`, `revoked`. Levels (**pinned**): `off`, `inform`, `scoped-instruction`, `scoped-bypass`, `full-bypass`.

`Delegate` (sender must own `session`):
- validation: `to` a field; `repo` a field; `task_id` 1 to 128 chars; `kind` 1 to 64 chars of `[a-z0-9-]`;
  at most `MAX_PATHS` paths, each a valid field and glob, not `area:`, not absolute, no `..` segment; at most
  16 commands, each 1 to 512 bytes with no control characters; `text` non-empty and at most `MAX_BODY` bytes;
  `spec` and `exit` at most 1000 chars; `ttl_secs` at most 14400; at most 16 `result_fields`.
- errors (**pinned** substrings): unknown target `no such session`; target equals sender
  `cannot delegate to this session`; target's daemon did not advertise the capability
  `does not accept delegated tasks`; target session's repo differs `different repository`.
- effect: row in a `delegations` table with status `pending`; event `delegation.request` with data
  `{to, to_user, to_machine, repo, contract}`; returns `{"seq": <request id>}`. The request id is the event seq.

`DelegateAck` (only by the request's target session, else error `not the recipient`; unknown id
`no such request`; pending for more than 10 minutes `expired`, and the status becomes `expired`):
- `accept: true` requires a level among `scoped-instruction`, `scoped-bypass`, `full-bypass`. In one transaction
  the hub releases the sender session's own leases that the contract paths cover (each with a
  `lease.released` event), and acquires a lease on each contract path for the target session with `ttl_ms`
  (clamped as other TTLs). If any path overlaps a lease of a third session, or a sender lease broader than the
  path, nothing changes and the error starts with `conflict:`; the status stays `pending`.
- `accept: false` with level `off` sets `declined`; with `inform` sets `informed`.
- returns `{"fresh": bool, "status": s, "level": l, "leases": [LeaseInfo...]}`. An ack on a request that is no
  longer pending returns the stored status with `fresh: false` and changes nothing. A fresh ack emits
  `delegation.ack` with data `{request, to, to_user, to_machine, task_id, accept, status, level, reason,
  scopes}`, where `to*` name the original sender.

`DelegateResult` (only by the target session; request status `accepted` or `informed`, else
`no open request`): `status` one of `done`, `failed`, `partial`, `revoked`; `summary` non-empty, at most
`MAX_BODY` bytes; for `done`, every name in `result_fields` must be a key of `fields` (error
`missing result field <name>`); `fields` serialised at most `MAX_BODY` bytes. Sets the status, releases the
target session's leases on the contract paths, emits `delegation.result` with data `{request, to, to_user,
to_machine, task_id, status, summary, fields}`, returns `{}`.

Visibility: events whose kind starts with `delegation.` reach only the event's own machine
(`user`, `machine`) and the machine named by `to_user`, `to_machine`. The activity page shows no `text`,
`summary`, `spec`, `exit`, `commands` or `fields` of any `delegation.*` event (it may show ids, kind, status,
level, paths and sizes).

Snapshot: `delegations` holds up to 50 newest requests whose sender or target machine is the asking peer's.

`HubHandle::sweep_at(t)` also marks requests pending for more than 10 minutes at `t` as `expired`.

## C. Policy module (`src/delegation.rs`, `pub mod delegation` in `lib.rs`)

    #[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(rename_all = "kebab-case")]
    pub enum Level { Off, Inform, ScopedInstruction, ScopedBypass, FullBypass }
    impl Level { pub fn as_str(&self) -> &'static str; pub fn parse(s: &str) -> Option<Level>; }

    pub struct Policy { /* private */ }
    impl Policy {
        pub fn parse(json: &str) -> Result<Policy, String>;
        pub fn load(path: &Path) -> Result<Policy, String>;
        pub fn evaluate(&self, from_user: &str, from_machine: &str, repo: &str, c: &Contract) -> Decision;
        pub fn denied_command(&self, command: &str) -> Option<String>; // the pattern hit, if the module is on
        pub fn denied_path(&self, rel: &str) -> Option<String>;        // the glob hit, if the module is on
    }
    #[derive(Clone, Debug, PartialEq)]
    pub struct Decision { pub level: Level, pub accepted: bool, pub reason: String, pub ttl_secs: u64, pub max_steps: u64 }

    pub const DEFAULT_DENY_KINDS: &[&str];    // force-push, delete-branch, delete-data, deploy, merge-pr,
                                              // publish, external-message, secrets
    pub const DEFAULT_DENY_COMMANDS: &[&str]; // see below
    pub const DEFAULT_DENY_PATHS: &[&str];    // see below
    pub fn audit_path(policy: &Path) -> PathBuf;   // "<policy file name>.audit.jsonl" beside it
    pub fn revoke(policy: &Path) -> Result<(), String>; // creates "<policy file name>.revoked" (mode 0600)
    pub fn resume(policy: &Path) -> Result<(), String>; // removes it; Ok if absent
    pub fn revoked(policy: &Path) -> bool;

Policy file (JSON, unknown keys are an error):

    {
      "grants": [
        {
          "from": ["alice@machine-a"],            // exact "user" or "user@machine"; no '*'; non-empty
          "repos": ["example.com/team/proj"],     // repo ids, or "*"; non-empty
          "task_ids": ["T-*"],                    // '*' wildcard patterns; default ["*"]
          "level": "scoped-bypass",
          "paths": ["src/**"],                    // required (non-empty) for scoped levels
          "kinds": ["tests", "fix"],              // required (non-empty) for scoped levels; "*" allowed
          "commands": ["cargo test*"],            // patterns a bypass contract may list; "*" allows any
          "max_ttl_secs": 3600,                   // default 3600, at most 14400
          "max_steps": 200                        // default 200
        }
      ],
      "denylist": { "enabled": true, "kinds": [...], "commands": [...], "paths": [...] }
    }

Each `denylist` list, when given, replaces its default; `"denylist": {"enabled": false}` switches the module
off. Load errors (**pinned** substrings): unknown level `unknown level`; wildcard or empty sender
`from`; empty repos `repos`; scoped grant without paths or kinds `paths` / `kinds`; a grant naming a
denylisted kind while the module is on `denylisted kind`; malformed JSON or unknown key: any error.

Default denylist (case-insensitive; command patterns are substrings after collapsing whitespace):
- commands: `push --force`, `push -f`, `--force-with-lease`, `push --delete`, `push origin :`, `branch -d`,
  `git reset --hard`, `git clean -f`, `rm -rf`, `rm -fr`, `drop table`, `drop database`, `truncate table`,
  `gh pr merge`, `git merge`, `deploy`, `kubectl`, `terraform apply`, `npm publish`, `cargo publish`,
  `twine upload`, `gh release`, `curl `, `wget `, `ssh `, `scp `, `sendmail`, `mail `, `printenv`,
  `security find-`, `gpg --export-secret`, `cat .env`.
- paths (globs as in `src/glob.rs`): `**/.env`, `**/.env.*`, `**/*.pem`, `**/*.key`, `**/id_rsa*`,
  `**/id_ed25519*`, `**/secrets/**`, `**/.git/**`, `**/.ssh/**`.

`evaluate` rules:
1. Grants match when `from` contains `from_user` or `from_user@from_machine`, `repos` contains `repo` or `*`,
   and a `task_ids` pattern matches `c.task_id`. No match: level `off`, not accepted, reason contains `no grant`.
2. A matching `off` grant wins: level `off`, not accepted.
3. Otherwise try matching grants from the highest level down; the first whose boundary the contract fits gives
   `accepted: true` and that level. If none fits, the result is level `inform`, not accepted, with the reason the
   highest grant refused (an `inform` grant alone gives `inform` with reason `inform`).
4. Boundary for `scoped-instruction`: `task_id` and `kind` non-empty; `kind` in `kinds` (or `kinds` has `*`);
   `paths` non-empty and each covered by a grant path (`glob::covers(grant_path, path)`).
5. `scoped-bypass`: as 4, plus `exit` non-empty and every contract command equal to a grant command (or the grant
   lists `*`).
6. `full-bypass`: `task_id` and `exit` non-empty. No path, kind or command limit.
7. Denylist module on, all levels above `inform`: `kind` in the deny kinds, a contract path that a deny glob
   matches (`glob::matches(deny, path)`), or a deny command pattern found in `text`, `exit`, `spec` or any
   contract command, refuses the boundary (reason names the hit). This text screen is a tripwire: free text can
   be reworded; bypass answers are checked again per tool call (section D).
8. `ttl_secs` = min(contract value or the grant maximum, grant `max_ttl_secs`, 14400); `max_steps` likewise.

## D. Daemon (`src/daemon/`)

`DaemonConfig` gains `pub delegation_policy: Option<PathBuf>` (default `None`). With a path, `daemon::start`
loads it and fails with an error containing `delegation policy` if it is invalid; the daemon then advertises the
capability. CLI: `wormhole daemon --delegation-policy FILE`.

On a new `delegation.request` event whose `to` is a session this daemon knows:
1. Decide: kill switch file present: `inform`, reason `revoked`; policy file unreadable or invalid now: `inform`;
   the session's repo id differs from the request's repo: `inform`; else `Policy::evaluate` with the event's
   hub-stamped `user` and `machine` (never payload fields).
2. Accepted: send `DelegateAck { accept: true, level, ttl_ms: ttl_secs*1000 }`. On `fresh: true` open a contract
   (session, request id, level, contract, expiry, steps left) and record the granted lease tokens as the session's.
   On an error (conflict, hub unavailable) send `DelegateAck { accept: false, level: "inform", reason }` if the hub
   answers, and treat the request as not accepted. On `fresh: false` (a replay after a restart) open nothing.
3. Not accepted: send `DelegateAck { accept: false, level: "off" | "inform", reason }`.
4. Notice to the session (msg-like: kept until delivered, read receipt sent), except level `off`, which gets no
   notice. Tag `wormhole-delegation`, channel meta kind `delegation_request`, attributes naming the sending session,
   user, machine and seq. Body, written by the daemon, in this order: a status line
   `[wormhole delegation] request <seq> from session <id> (<user>@<machine>): status: <accepted|informed|declined>; level: <level>; reason: <reason>`
   (**pinned** prefix and `status: ` / `level: ` fields); then for an accepted task the boundary (repository,
   task id, kind, paths, commands, spec, `done when:` exit, expiry and step budget), the leases held, the line
   `Your permission prompts remain in force.` (**pinned**, scoped-instruction) or a line saying tool calls inside
   the boundary run without a permission prompt and anything else prompts as usual (bypass levels), the
   denylisted kinds when the module is on (`Not authorised by this delegation`, **pinned**), and how to post the
   result (`wormhole_result`, the request id, required fields); for a task not accepted, a line containing
   `information only` (**pinned**). Last, `Task text, relayed from session <id>:` and the text capped at 1000
   characters, so the limits always survive the 2000-character block cap. The preamble and cleaning apply as for
   every notice.
5. Audit (section F).

Sender-side notices: `delegation.ack` and `delegation.result` events addressed to a local session become notices
(tag `wormhole-delegation`, meta kinds `delegation_ack` and `delegation_result`) naming the task id, request id,
status, level, reason, and for a result the summary and fields.

`PreToolUse` with an open contract for the session (not expired, steps left, kill switch absent):
- The existing behaviour runs first and wins: a deny stays a deny; a held lease, stale hub or lease-check
  failure gives no `allow`.
- `scoped-bypass`: answer `allow` for `Edit`, `Write`, `MultiEdit`, `NotebookEdit` when the resolved path is
  matched or covered by a contract path, not matched by a deny path, not a `--protected` path, and the lease step
  ended granted; and for `Bash` when the command matches a contract command pattern (`*` = any characters), has
  none of `; & | \` $ < > ( ) \\` or a line break, and no deny command pattern is found in it. Nothing else.
- `full-bypass`: answer `allow` for any tool, except edits whose path a deny glob matches or that are protected or
  leased by another session, and `Bash` commands with a deny pattern.
- An `allow` is `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
  "permissionDecisionReason": "wormhole delegation <seq> (<level>) ..."}}`, keeping any `additionalContext`.
  Each `allow` spends one step and is audited. When the steps run out, the TTL passes or the kill switch is found,
  the contract closes (audited) and the session gets a notice that the contract closed and prompts are back.
- No open contract, or level `scoped-instruction`: the hook output is exactly as before this slice (never `allow`).

Kill switch: `wormhole delegation revoke --policy FILE [--socket PATH]` calls `delegation::revoke` and then, best
effort, the daemon socket op `{"op": "revoke"}`; `wormhole delegation resume --policy FILE` calls `resume`. On
the socket op, or when a hook or request finds the file, the daemon closes every open contract and posts
`DelegateResult { status: "revoked", summary: "revoked by the receiving machine's owner" }` for each.

## E. MCP tools (`src/mcp.rs`, daemon socket `tool` op)

- `wormhole_delegate`: arguments `to_session` (required), `task_id` (required), `kind` (required), `text`
  (required), `paths` (array), `commands` (array), `spec`, `exit`, `ttl_seconds`, `max_steps`,
  `result_fields` (array). Daemon tool name `delegate`, args as given (`to_session` is renamed `to` as for
  `grant`). Paths are resolved as lease scopes are. Without the hub capability the tool fails with
  `does not support delegation` (**pinned**) and sends nothing to the hub. Success text contains the request seq.
- `wormhole_result`: arguments `request` (integer, required), `status` (required), `summary` (required),
  `fields` (object). Daemon tool name `result`. Closes the local contract. Hub errors are returned as tool errors.
- `wormhole_who` output gains a `Delegations:` section listing requests from the snapshot that involve this
  session, each with request id, task id, kind, the other session, status and level.

## F. Audit log

JSON lines appended to `delegation::audit_path(policy)` (created mode 0600). Each line has `ts`, `event`, `seq`,
`session` and `level`; `event` is one of `request` (every decision, with `accepted` and `reason`), `allow` (with
`tool` and `path` or `command`), `close` (with `reason`), `revoke`, `result`.

## G. Docs

`docs/design.md` (messages table, Trust and safety, what is built), `README.md` (a short delegation section),
`SECURITY.md` (scope and not-covered), each level's risk beside it as in ADR 0001.

## MECE test and eval surface (what the dashboard would show)

| Part | Cases |
|---|---|
| A wire | old frames parse as new; new optional fields parse as old (frozen `main` copy of `src/proto.rs` at `tests/fixtures/proto_v0.rs`); new request variants do not parse as old ones (why gating is needed) |
| B hub | routing and every pinned error; visibility to third machines; page redaction; idempotent ack; atomic lease hand-off and conflict; result validation and lease release; expiry |
| C policy | parse errors; each level's boundary; highest fitting grant; `off` wins; denylist on, edited and off; TTL and step clamping; no wildcard senders |
| D daemon | end to end per level; notice markers and order; sender notices; bypass allow and every refusal (outside paths, metacharacters, deny pattern, protected, held lease, hub down); step limit, TTL, kill switch; restart does not reopen; no `allow` without an open bypass contract |
| E tools | delegate, result, who listing; old hub (fake) gets no delegation frames |
| F audit | lines for request, allow, close, revoke |

Error conditions to trace: every pinned hub error, policy load errors, conflict on acceptance, hub unavailable
during acceptance, kill switch. No model calls are made, so there are no LLM traces.

## Protected test files (the implementer must not read them)

`tests/delegation.rs`, `tests/delegation_policy.rs`, `tests/delegation_compat.rs`, `tests/fixtures/`. The test
author may add helpers to `tests/common/mod.rs`; the implementer may read `tests/common/mod.rs`.

## Amendment 1 (2026-11-15, from security review findings; supersedes the parts of C rule 7 and D it names)

Findings: (S1, high) the path denylist could be passed by a wildcard or directory contract path that is not
itself a denied literal; (S2, medium) substring command matching is evaded by flag spellings, `+refspec`,
quoting, environment prefixes, `sh -c` and similar. The substring list stays only as defence in depth.

### S1: paths

- Normalise every contract path before any check, in the hub and in the policy: strip leading `./`, collapse
  repeated `/`, refuse `..` segments and absolute paths (already refused). A path that is empty after this, or
  is `/`, is refused by the hub (`invalid path`).
- Deny-glob comparisons are case-insensitive: both the glob and the path are lowercased (macOS and Windows
  filesystems are case-insensitive, so `.ENV` is `.env`).
- `Policy::denied_path(rel)` applies this to a concrete path. At acceptance (`evaluate`, denylist on, levels
  above `inform`) a contract path is refused when a deny glob matches its text (so `secrets/**`, `.git/`,
  `src/*/.env` are refused) **or** when it has no literal leading segment (its first segment contains `*`, as in
  `**`, `*`, `*.rs`, `**/x`), since such a scope reaches every denied file. Reason names the path.
- At tool-call time the bypass hook (both bypass levels) checks the resolved concrete path with `denied_path`
  and gives no `allow` on a hit, whatever the contract said. This is the enforcement point; the acceptance check
  is coarse by design (a scope such as `src/**` is accepted and `src/secrets/x` is still refused per call).

### S2: commands at the bypass levels

- Contract `commands` and grant `commands` are **argv prefixes**, not wildcard patterns: `"cargo test"` allows
  `cargo test` and `cargo test --lib`, not `cargo testx` or `cargo build`. There are no wildcards in a prefix;
  the grant value `"*"` (alone) still means any contract prefix is acceptable at acceptance time. At acceptance a
  contract prefix must tokenise cleanly (below), must not start with a wrapper program, and must extend or equal
  some grant prefix token by token.
- New public function `pub fn tokenize(command: &str) -> Result<Vec<String>, String>` in `wormhole::delegation`:
  POSIX-shell-words rules for whitespace, single quotes and double quotes (backslash escapes `"`, `\`, `$`,
  `` ` `` inside double quotes; outside quotes a backslash escapes the next character). It returns `Err` for an
  unterminated quote, a line break, any unquoted `;`, `&`, `|`, `<`, `>`, `(`, `)`, `` ` ``, `$`, `{`, `}`, and
  any `$` or `` ` `` inside double quotes (substitution). Empty input is `Err`.
- New public function `pub fn command_allowed(prefixes: &[String], command: &str) -> Result<(), String>`: `Ok` only
  when `tokenize` succeeds, the first token does not contain `=` (no environment prefix), the program's base name
  (after the last `/`) is not a wrapper, and the token list starts with the tokens of one of `prefixes`.
  Wrappers (**pinned**, refused always): `sh`, `bash`, `zsh`, `dash`, `ksh`, `fish`, `csh`, `tcsh`, `eval`,
  `exec`, `env`, `xargs`, `sudo`, `doas`, `su`, `nohup`, `time`, `command`, `builtin`, `source`, `.`, `nice`,
  `timeout`, `watch`, `script`, `parallel`, `python`, `python3`, `perl`, `ruby`, `node`, `osascript`.
- New public function `pub fn denied_argv(&self, command: &str) -> Option<String>` on `Policy` (module on only):
  argv-aware destructive checks on the tokenised command. For program `git` (subcommand found after skipping
  global options `-C <dir>`, `-c <k=v>`, `--git-dir=…`, `--work-tree=…`, `--no-pager`): `push` with any of `-f`,
  `--force`, `--force-with-lease…`, `--force-if-includes`, `--delete`, `-d`, `--mirror`, `--prune`, a short-flag
  cluster containing `f` or `d` (e.g. `-fu`), or a refspec starting with `+` or `:`; `branch` with `-d`, `-D`,
  `--delete`, or a cluster containing `d`/`D`; `reset` with `--hard`; `clean` with `-f`/`--force` or a cluster
  containing `f`; `merge`; `filter-branch`; `update-ref -d`. For `gh`: `pr merge`, `release`, `repo delete`.
  Also programs `rm` with a cluster containing `r` and `f` (or `-r`/`-R`/`--recursive` with `-f`/`--force`),
  `kubectl`, `terraform`, `helm`, `npm publish`, `cargo publish`, `twine upload`, `curl`, `wget`, `ssh`, `scp`,
  `sendmail`, `mail`, `printenv`, `security`. An untokenisable command counts as denied (`Some`).
- Bypass `Bash` rule (replaces the D rule): under `scoped-bypass`, `allow` only when `command_allowed(contract
  commands, cmd)` is `Ok` and, with the module on, neither `denied_argv` nor `denied_command` hits. Under
  `full-bypass` with the module on, `allow` only when `tokenize` succeeds, the program is not a wrapper, the
  first token has no `=`, and neither deny check hits; with the module off, as before (any command). Everything
  else gets the ordinary prompt.
- The substring `denied_command` list remains, documented as a defence-in-depth tripwire, not a boundary.

### Tests for this amendment (protected, written before the fix)

`tests/delegation_amend1.rs`: tokenizer cases (quotes, escapes, every refused metacharacter, substitution in
double quotes, unterminated quotes); `command_allowed` (prefix extension, `cargo testx`, env prefix, wrappers by
base name such as `/bin/sh -c`, `sh -c '…'`); `denied_argv` (`git push -f`, `git push --force-with-lease`,
`git push origin +main`, `git push origin :main`, `git -C x push -fu`, `"git" push --force`, `git branch -D x`,
`rm -fr x`, `rm -r -f x`); `denied_path` and acceptance with `secrets/**`, `.git/`, `**`, `*.rs`, `./`, `SECRETS/x`,
`src/.ENV`; end to end: under scoped-bypass with a `src/**` contract the hook gives no `allow` for `src/secrets/a.rs`
and `src/.ENV`, and none for `git push -f` even with grant and contract prefix `git push`.

## Amendment 2 (2026-11-15, second security review; supersedes Amendment 1's prefix semantics and the D tool rules it names)

Findings: (S3, high) the runtime Bash check relied on the substring list; (S4, medium) allowlist entries matched as
a wildcard over the raw string, so `git status *` absorbed `; rm -rf …` or extra flags; (S5, medium) under
`full-bypass` any other tool was allowed without a path check.

### S4: scoped-bypass commands are exact argv patterns (replaces "argv prefixes")

- A command pattern is tokenised with `tokenize`. Each token is a literal, except that the **last** token may be
  `*`, meaning one or more further arguments, none starting with `-` and none containing `*`, `?`, `[` or `]`.
  No other wildcard exists. A pattern whose first token is a wrapper, has an environment prefix, or does not
  tokenise is invalid (refused at acceptance).
- `command_allowed(patterns, command)` returns `Ok` only when: the raw command contains no quote (`'`, `"`),
  backslash, `*`, `?`, `[` or `]`; `tokenize` succeeds; the first token has no `=` and is not a wrapper (by base
  name); and some pattern matches token by token: same count with every literal equal, or, for a trailing `*`,
  the literal tokens equal and at least one further token, each satisfying the `*` rule. `cargo test` matches only
  `cargo test`; `cargo test *` matches `cargo test glob_tests` but not `cargo test --release x` or
  `cargo test`.
- At acceptance each contract pattern must equal a grant pattern token for token, or the grant lists `"*"` alone.

### S3: every Bash allow at a bypass level

- `scoped-bypass`: `allow` only when `command_allowed(contract patterns, cmd)` is `Ok` and, with the denylist on,
  `denied_argv` and `denied_command` both return `None`.
- `full-bypass`, denylist on: `allow` only when `tokenize` succeeds, the program is not a wrapper, the first token
  has no `=`, and `denied_argv` and `denied_command` both return `None`.
- `full-bypass`, denylist off: any command (the owner switched the module off).

### S5: tools under full-bypass

- `full-bypass` answers `allow` only for this pinned tool list: `Bash`, `Edit`, `Write`, `MultiEdit`,
  `NotebookEdit`, `Read`. Every other tool, MCP tools included, gets the ordinary prompt.
- For `Edit`, `Write`, `MultiEdit`, `NotebookEdit` and `Read` the path (`file_path` or `notebook_path`) must
  resolve inside the session's repository; it is refused if it is a `--protected` path, if `denied_path` hits
  (denylist on), or, for edits, if the lease step did not end granted. `scoped-bypass` keeps its edit rule and
  never allows `Read` or other tools.

### What still applies under full-bypass with the denylist module off

The tool list above; paths inside the repository; `--protected` paths; another session's lease on the path; a
stale or unreachable hub (no `allow`); the contract's TTL, step budget, result and the kill switch; and the
user's own Claude Code settings deny and ask rules and plan mode, which win over any hook `allow`.

### Tests for this amendment (protected, written before the fix)

`tests/delegation_amend2.rs`, plus updates to the earlier delegation test files where they relied on prefix
semantics.

## Amendment 3 (2026-11-15, third security review; supersedes the Bash rules of amendments 1 and 2 for the scoped levels)

Findings: unquoted `*`, `?`, `[` and a leading `~` passed `tokenize`; the wrapper check was case-sensitive (`SH`,
`/bin/Bash`); git global options (`-c alias.x=!…`, `core.sshCommand`, `core.pager`, `--config-env`) were not
parsed; gh flag values were counted as positionals (`-R owner/repo pr merge`); and programs that run other code
(`find -exec`, `awk`, `make`, `npx`, `cargo --config`, `git -c`) were missing. A denylist of programs cannot be
complete, so the design changes: **the contract's command allowlist is the boundary**, and anything outside it
gets the normal local prompt (never a silent allow, never a silent deny).

### Tokenizer (`tokenize`, tightened)

In addition to the Amendment 1 refusals, `Err` for any unquoted `*`, `?`, `[`, `]`, `{`, `}`, `#` at the start of
a token, and any token starting with an unquoted `~`.

### Safe programs

- `pub const DEFAULT_SAFE_PROGRAMS: &[&str]` (**pinned**): `ls`, `cat`, `head`, `tail`, `wc`, `grep`, `rg`,
  `diff`, `stat`, `pwd`, `echo`, `true`, `false`, `sort`, `uniq`, `cut`, `tr`, `basename`, `dirname`,
  `realpath`, `git`, `cargo`, `rustfmt`. They are named because their usual forms do not hand control to an
  arbitrary program; `git` and `cargo` still run project code (hooks, build scripts, tests) and are only as safe as
  the paths the contract lets the agent write. Deliberately absent: shells, interpreters, `env`, `xargs`, `find`,
  `awk`, `sed`, `make`, `npx`, `npm`, `sudo`, and every wrapper in Amendment 1.
- The policy may add programs with a top-level `"safe_programs": [...]` key (extends the defaults; names must match
  `[A-Za-z0-9._/-]+`). Additions are the owner's call and are documented as such.
- New method `Policy::safe_program(&self, name: &str) -> bool` (exact, case-sensitive match against defaults plus
  additions).

### Command patterns and `command_allowed` (replaces Amendment 2's definition)

- Signature becomes a `Policy` method: `pub fn command_allowed(&self, patterns: &[String], command: &str) ->
  Result<(), String>`. (The free function of the same name is removed.)
- A pattern is valid only when it tokenises (the tightened tokenizer, except that a final whole token `*` is
  permitted in a pattern), its first token is a literal program name in `[A-Za-z0-9._/-]+` that `safe_program`
  accepts, and, when the program's base name is `git` or `cargo`, no token is `-c` or starts with `--config`,
  `--exec`, `--upload-pack` or `--receive-pack`. Grant patterns are checked at load (error
  `not a safe program` or `unsafe option`); contract patterns at acceptance (boundary refused, request becomes
  `inform`).
- `command_allowed` is `Ok` only when: the raw command has no quote, backslash, `*`, `?`, `[`, `]`, `{`, `}` or
  `~`; it tokenises; and some valid pattern matches token by token, argv[0] included, exactly: equal token count
  with every literal equal, or for a trailing `*` the literal tokens equal and one or more further tokens, none
  starting with `-`. The git/cargo option rule applies to the command's tokens as well.

### Bash at each level

- `scoped-instruction`: never `allow` (unchanged).
- `scoped-bypass`: `allow` only when `command_allowed(contract patterns, cmd)` is `Ok`. With the denylist module
  on, `denied_argv` and `denied_command` must also return `None` (defence in depth).
- `full-bypass`: unchanged from Amendment 2. **Bash at this level is not bounded by any parser.** It is a trust
  decision about the sender. With the module on, the tokenizer, wrapper, `denied_argv` and `denied_command` checks
  are a speed bump, not a guarantee.

### Denylist, demoted to defence in depth

`denied_argv` lowercases tokens and compares base names (`/bin/Bash` → `bash`), and skips git global options
with their values (`-C <v>`, `-c <v>`, `--config-env=…`, `--git-dir…`, `--work-tree…`, `--namespace…`,
`--exec-path…`, `--no-pager`, `-p`, `--paginate`, `--bare`) before finding the subcommand, treating `-c` itself
as denied when its value names `alias.`, `core.sshcommand`, `core.pager`, `core.editor`, `core.hookspath` or
`core.fsmonitor`; for `gh` it skips `-R <v>`, `--repo <v>`, `--hostname <v>` before reading the subcommand. Its
tests are examples, not claims of completeness.

### Tests for this amendment (protected)

`tests/delegation_amend3.rs`, plus updates to earlier delegation test files that used `command_allowed` as a free
function or relied on programs or characters now refused.

## Amendment 4 (2026-11-15, fourth security review; supersedes Amendment 3's safe-program list)

Finding (S6, high): the safe-program check looked at argv[0] only, but listed programs have options that run other
code: `rg --pre`/`--pre-glob`, `sort --compress-program`, `git difftool -x`/`--extcmd`, `git submodule foreach`,
`git bisect run`, `git config` writes, `git -C`, and cargo's `--config`, `-Z`, `+toolchain`, `--manifest-path`.

- `DEFAULT_SAFE_PROGRAMS` (**pinned**, replaces Amendment 3's list) holds only programs with no option that runs
  another program: `ls`, `cat`, `head`, `tail`, `wc`, `grep`, `diff`, `stat`, `pwd`, `echo`, `true`, `false`,
  `uniq`, `cut`, `tr`, `basename`, `dirname`, `realpath`. Removed: `rg`, `sort`, `git`, `cargo`, `rustfmt` (which
  writes files outside any scope).
- `git` and `cargo` are not defaults. When the owner adds either to `safe_programs`, it is usable only with a
  built-in subcommand allowlist (**pinned** constants): `pub const GIT_SUBCOMMANDS: &[&str] = &["status", "log",
  "diff", "show"]` and `pub const CARGO_SUBCOMMANDS: &[&str] = &["test", "check", "build"]`. A git or cargo pattern
  or command is valid only when its second token is one of these (no option before the subcommand) and no token
  is refused:
  - git: `-c`, anything starting with `-C`, `--exec`, `--ext-diff`, `--textconv`, `--output`, `--git-dir`,
    `--work-tree`, `--config`, `--upload-pack`, `--receive-pack`;
  - cargo: anything starting with `--config`, `-Z`, `+`, `--manifest-path`.
  `cargo test` and `cargo build` still run project code (build scripts, tests); that is the owner's choice when they
  add `cargo`, and it is documented beside the level risk.
- A pattern with a trailing `*` must have no literal token starting with `-` (error at load `unsafe option`; at
  acceptance the boundary is refused).
- Programs the owner adds through `safe_programs`, other than `git` and `cargo`, are the owner's responsibility;
  the docs say to add only programs with no exec, config or alias escape.

Tests (protected, written before the fix): `tests/delegation_amend4.rs`, plus updates to earlier delegation test
files whose policies or patterns use `git`, `cargo`, `rg`, `sort` or `rustfmt`.

## Amendment 5 (2026-11-15, adversarial review of the amendment-3 code; adds to Amendment 4)

Findings R1 to R6 confirmed by the slice reviewer, plus suspicions accepted as cheap to close.

- **R1 (high) Bash operands.** Under `scoped-bypass`, every argument token of an allowed command other than argv[0],
  the git or cargo subcommand, and allowlisted option tokens is treated as a path: it is refused (no `allow`) if
  it is absolute, contains a `..` segment, or, resolved against the session's cwd with the same rules as edit
  paths (symlinks followed), falls outside the repository, is a `--protected` path, or is matched by a deny glob.
  Option tokens containing `=` are refused. `uniq` is removed from `DEFAULT_SAFE_PROGRAMS` (it writes its second
  operand).
- **R2 and R3 (high, medium) git and cargo options.** Amendment 4's refused-option lists are replaced by option
  allowlists (**pinned**): `pub const GIT_OPTIONS: &[&str] = &["--oneline", "--stat", "--name-only",
  "--name-status", "--short", "--porcelain", "--cached", "--staged", "--no-color"]` and `pub const CARGO_OPTIONS:
  &[&str] = &["--lib", "--bins", "--tests", "--doc", "--all-targets", "--workspace", "--release", "--locked",
  "--offline", "--quiet", "-q", "--no-fail-fast"]`. Any other token starting with `-` in a git or cargo pattern
  or command is refused (this covers abbreviations such as `--ha`, valued globals such as `--attr-source`, and
  `--`). Subcommands remain `GIT_SUBCOMMANDS` and `CARGO_SUBCOMMANDS`, which must be literal in the pattern (a
  pattern `git *` or `cargo *` is invalid).
- **R4 (medium) audit fails closed.** Writing an audit line returns a `Result`. If the line for a bypass answer
  cannot be written, no `allow` is given; if the line for an acceptance cannot be written, the request is not
  accepted (`inform`, reason `audit log unavailable`). An existing audit file that is not a regular file owned by
  this user with no group or other access is refused the same way.
- **R5 (medium) repository.** A Bash `allow` also requires the session's current repository id to equal the
  contract's.
- **R6 (medium) symlinks.** Under either bypass level, an edit or `Read` path (or a Bash operand) whose final
  component, or first existing ancestor, is a symlink that does not resolve gets no `allow`.
- **Star patterns with the denylist on.** The acceptance-time denylist screen of a contract pattern ignores a
  trailing `*` token, so `ls *` and `cargo test *` can be accepted.
- **Tool input keys.** The path key is chosen by tool (`notebook_path` for `NotebookEdit`, `file_path` for the
  others); an input carrying both keys gets no `allow`. A `Bash` input with `dangerouslyDisableSandbox: true` gets
  no `allow`.
- **Capability on every send.** `DelegateResult` from the kill switch and the result tool is sent only while the
  hub advertises the capability (else the tool fails with `does not support delegation`).
- **Policy narrowing.** Before each bypass answer the contract is re-evaluated against the current policy file;
  if it is no longer accepted at the same or a higher level, the contract closes (audited) and no `allow` is
  given.
- **Deny paths.** `DEFAULT_DENY_PATHS` gains `**/.aws/**`, `**/.kube/**`, `**/.npmrc`, `**/.netrc`,
  `**/.git-credentials`, `**/.envrc`, `**/*.p12`, `**/*.pfx`.

Not done here (recorded for the owner): a per-sender rate limit on `Delegate`; posting a result when a contract
closes on TTL or steps (the leases expire with the contract TTL); `lease.*` events from a hand-off are visible to
all machines like every lease event; a login containing `@` makes `user@machine` grants ambiguous.

Tests (protected, written before the fix): `tests/delegation_amend5.rs`, plus updates to earlier files.

## Clarifications (2026-11-15, from the first separate test run)

- Every delegation notice to the receiving session names the task id and kind, accepted or not (the status line
  is followed by `task <id>; kind <kind>` in all cases).
- `denied_argv` also returns `Some` for a wrapper program (Amendment 1 list), compared by lowercased base name.

## Amendment 6 (2026-11-15, fifth security review)

- **S7 (medium) git can print denied files.** `git show HEAD:secrets/x`, `git diff` and `git log -p -- secrets/`
  print denied contents while each operand passes the path check. Chosen fix (the simpler one): while the denylist
  module is on, git is usable only with `status` (new **pinned** constant `pub const GIT_SUBCOMMANDS_DENYLIST_ON:
  &[&str] = &["status"]`); `log`, `diff` and `show` are available only with the module off. Patterns naming
  them are refused at load and at acceptance while the module is on, and commands are refused per call.
- **S7b (same class, found by the orchestrator) recursive reads.** A Bash operand that is an existing directory is
  allowed only for `ls`, `stat`, `realpath`, `basename` and `dirname`; for every other program (for example
  `grep -r x src`, `diff -r a b`) a directory operand gets no `allow`, since it can read denied files below it.
- **S8 (medium) tightening the policy shrinks open contracts.** Each open contract records its acceptance time and
  steps used. When the per-call re-evaluation still grants it, `expires = min(expires, accepted_at + new ttl)` and
  `steps_left = min(steps_left, new max_steps - steps_used)` (saturating); if either is used up the contract closes
  (audited, reason `policy tightened`) and no `allow` is given.

Tests (protected, written before the fix): `tests/delegation_amend6.rs`, plus updates to earlier files that use
`git log`, `git diff` or `git show` with the module on.
