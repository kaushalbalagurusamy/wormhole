# Minesweeper trap register

- Brief: `/Users/kaushal/Projects/wormhole/docs/minesweep/2026-11-14-wormhole-docs/brief.md` (sha256 `ce894ed3d5f1`)
- Run: 2026-11-14, mode full, skill ?
- Calibrated: **NO: uncalibrated lenses, treat findings as leads**
- Lenses: accessibility 0.1.0 (uncalibrated), licensing 0.1.0 (uncalibrated), privacy-regulated-data 0.1.0 (uncalibrated), provider-terms 0.1.0 (uncalibrated), security-ethics 0.1.0 (uncalibrated), agent-orchestration 0.2.0 (uncalibrated), agent-security 0.1.0 (uncalibrated), supply-chain 0.1.0 (uncalibrated), databases 0.1.0 (uncalibrated), distributed-systems 0.1.0 (uncalibrated), os-systems 0.1.0 (uncalibrated), performance 0.1.0 (uncalibrated), realtime-transport 0.1.0 (uncalibrated)
- Loop: 1 pass(es), stop: iteration-cap; open: F-001, F-002, F-005, F-008, F-010, F-011, F-012, F-013, F-014, F-015, F-017, F-020, F-025

## Findings

| Id | Tier | Status | Lens / trap | Disposition | Underlying problem |
|---|---|---|---|---|---|
| F-001 | high | confirmed | agent-orchestration / agent-orchestration.irreversible-action-without-gate | ask-owner | Give the model the holder's details before it commits a conflicting edit, without turning advisory leases into hard locks. |
| F-002 | high | plausible | agent-orchestration / novel | comply-safely | The channel server must negotiate a revision on which Claude Code registers channels. |
| F-003 | high | confirmed | distributed-systems / distributed-systems.exactly-once-delivery | comply-safely | Acknowledge to the hub only what has been delivered to a session, so restart replays the rest. |
| F-004 | high | confirmed | databases / novel | comply-safely | Daemons must detect a hub log that is behind their cursor and resume from the hub's head. |
| F-005 | medium | plausible | databases / novel | comply-safely | All checkouts of one repository must map to one id, or the user must be told they do not. |
| F-006 | medium | confirmed | distributed-systems / novel | comply-safely | Lease scopes must cover what they name, expire visibly, transfer cleanly, and tell a session when its lease was lost. |
| F-007 | medium | confirmed | agent-security / novel | reframe | State plainly that protected paths are a guard on the edit tools while the hub is reachable, not access control. |
| F-008 | medium | plausible | agent-security / agent-security.confused-deputy | comply-safely | The hub should accept only the users or tags the owner names, not every identifiable node. |
| F-009 | medium | confirmed | agent-security / agent-security.local-server-command-execution | comply-safely | Keep the hook secret unreadable by other local users, and offer a transport that does not trust a TCP port. |
| F-010 | medium | plausible | agent-security / agent-security.untrusted-content-drives-tools | reframe | Treat peer text as data: say so, keep the user's permission prompts in force, and never relay permissions. |
| F-011 | medium | plausible | agent-orchestration / agent-orchestration.non-idempotent-retry | comply-safely | Tell the model the seq identifies a message so it acts once per seq. |
| F-012 | medium | plausible | agent-orchestration / agent-orchestration.unbounded-agent-loop | comply-safely | Bound message rate per session and hub storage, so an accidental loop is shed rather than stored forever. |
| F-013 | medium | plausible | performance / performance.percentile-slo-without-load-model | comply-safely | Measure the cross-machine path before relying on the 800 ms budget. |
| F-014 | medium | plausible | realtime-transport / novel | comply-safely | Serve requests while replaying. |
| F-015 | medium | plausible | agent-orchestration / novel | comply-safely | SessionStart must show this repository's leases first. |
| F-025 | medium | plausible | supply-chain / supply-chain.autonomous-agent-install | comply-safely | Applying a peer patch needs the user's confirmation. |
| F-017 | low | plausible | provider-terms / novel | comply-safely | State channel availability by plan and provider, and that relayed text is model input under each user's agreement. |
| F-020 | low | plausible | privacy-regulated-data / privacy-regulated-data.collect-all-keep-forever | comply-safely | State retention and provide pruning. |

### F-001: agent-orchestration.irreversible-action-without-gate

- Claims: C-012, C-035, C-058; route: retrieval (The hooks reference states where PreToolUse context lands; one real session observed it.)
- Evidence (quote, primary, 2026-11-14): https://code.claude.com/docs/en/hooks.md L1174 "PreToolUse, PostToolUse, PostToolUseFailure, and PostToolBatch: next to the tool result"
- Evidence (quote, primary, 2026-11-14): https://code.claude.com/docs/en/hooks.md L2007 "For "deny", shown to Claude."
- Evidence (note, -, 2026-11-14): docs/design.md (real claude -p run, 2026-11-14)  "the model read the WARNING only after the write"
- Severity high: first yes = Would the deliverable fail under the production conditions the brief itself implies (load, faults, adversaries, scale)?
- Skeptic: upheld: Both hooks.md quotes are live and accurate (L1174: PreToolUse additionalContext lands next to the tool result; L2007: a deny reason is shown to Claude). The brief contradicts itself: C-012 promises a warning before the edit and C-058 admits it arrives after. A deny-once-with-reason is the documented pre-edit channel, so the fix exists but is not stated. Caveat: the trap id 'irreversible-action-without-gate' overstates it, since an edit can be undone; the real problem is a broken promise to coordinate before the edit.
- **Owner question:** Which pre-edit policy: (a) deny once per (session, path, holder token) with the warning as the reason, then allow the retry; (b) warn earlier, when a leased file is Read, from a local lease mirror; (c) both; (d) permissionDecision ask; (e) keep warn-only?
- Spec section that must answer it: `product-scope`

### F-002: novel finding

- Claims: C-023, C-013; route: retrieval (The MCP page states the protocol-revision rule for channel servers.)
- Evidence (quote, primary, 2026-11-14): https://code.claude.com/docs/en/mcp.md Push messages with channels "On the v2 runtime, a channel server that negotiates MCP protocol revision 2026-07-28 can't deliver channel messages, so Claude Code doesn't register it as a channel."
- Evidence (quote, primary, 2026-11-14): https://code.claude.com/docs/en/mcp.md Push messages with channels "Claude Code asks stdio servers for that revision by default."
- Evidence (check, -, 2026-11-14): src/mcp.rs (before e7b1acb)  "initialize echoed the client's requested protocolVersion"
- Severity high: first yes = Would the deliverable fail under the production conditions the brief itself implies (load, faults, adversaries, scale)?
- Skeptic: downgraded: The mcp.md quotes are accurate, but the defect is already fixed at HEAD: commit e7b1acb pins PROTOCOL_VERSIONS to 2025-06-18 and older, and a test asserts that 2026-07-28 is answered with 2025-06-18. The cited commit '2d50a1f' does not exist in the repo, so the locator is wrong. What remains is a documentation item: the brief should record the pinned revision and the MCP_PROTOCOL_NEGOTIATION=legacy fallback. It would be settled by a channel registering on a real v2-runtime session.
- Spec section that must answer it: `product-scope`

### F-003: distributed-systems.exactly-once-delivery

- Claims: C-029, C-030, C-043, C-108; route: check (Traced in code: ack timing and in-memory inbox.)
- Evidence (check, -, 2026-11-14): src/daemon/mod.rs run_connection  "Ack{seq} sent as soon as an event is applied, before delivery to the session"
- Evidence (check, -, 2026-11-14): src/daemon/state.rs  "inbox held in memory only"
- Evidence (note, -, 2026-11-14): review  "independent review (Fable agent, 2026-11-14), traced from code: a daemon restart before delivery loses the message"
- Severity high: first yes = Would the deliverable fail under the production conditions the brief itself implies (load, faults, adversaries, scale)?
- Skeptic: upheld: At HEAD, run_connection sends Ack{seq} right after apply(), and the inbox is memory-only, so a daemon restart loses messages that were applied but not delivered. That breaks C-029/C-043. An uncommitted fix (ack_point) is in progress in the working tree, but it is not committed. It also leaves a gap: after a restart, the replayed broadcast and user messages fan out to self.sessions.keys(), which is empty until sessions say hello again, so those messages still reach nobody.
- Spec section that must answer it: `trust-consensus`

### F-004: novel finding

- Claims: C-025, C-026, C-043; route: check (Traced in code: daemon dedupes by seq and ignores Welcome.head; hub uses WAL with synchronous=NORMAL.)
- Evidence (check, -, 2026-11-14): src/daemon/state.rs apply  "drops every event with seq <= last_seq"
- Evidence (check, -, 2026-11-14): src/hub/store.rs SCHEMA  "PRAGMA synchronous = NORMAL (WAL): the last commits can roll back on power loss"
- Evidence (note, -, 2026-11-14): review  "independent review (Fable agent, 2026-11-14), traced from code: deleting the hub database leaves running daemons ignoring every new event"
- Severity high: first yes = Would the deliverable fail under the production conditions the brief itself implies (load, faults, adversaries, scale)?
- Skeptic: upheld: At HEAD, apply() drops every seq <= last_seq, and the daemon ignores the head sent in Welcome. A hub database reset, or a WAL commit lost on power failure under synchronous=NORMAL (which really is non-durable on power loss), therefore makes the daemon silently drop new events. An uncommitted fix that resets last_seq to the head is in the working tree. Residual risk: if the hub has already grown past the daemon's old cursor before it reconnects, the reused seqs in between are still dropped.
- Spec section that must answer it: `trust-consensus`

### F-005: novel finding

- Claims: C-056; route: check (Traced in normalize_remote.)
- Evidence (check, -, 2026-11-14): src/repo.rs normalize_remote  "path case kept; ssh host aliases kept; local:<dir> for no origin"
- Evidence (note, -, 2026-11-14): review  "independent review (Fable agent, 2026-11-14), traced from code: git@github-work:Owner/Repo and https://github.com/owner/repo give different ids"
- Severity medium: first yes = Is it a correctness, measurement, statistical or design flaw that a principal-level reviewer would reject?
- Skeptic: downgraded: The code matches the finding: host is lowercased, path case is kept, and ssh host aliases are not resolved. But the common forms that matter do agree: git@github.com:owner/repo and https://github.com/owner/repo both normalise to github.com/owner/repo. The trap bites only checkouts that use differently-cased paths or custom ssh aliases. It would be settled by checking the remotes the team actually uses. Either way, the brief should state the limit instead of 'shared across checkouts'.
- Spec section that must answer it: `trust-consensus`

### F-006: novel finding

- Claims: C-030, C-031, C-035; route: check (Traced in glob.rs, store.rs transfer and daemon hooks.)
- Evidence (check, -, 2026-11-14): src/glob.rs overlaps  "area: and bare directory scopes overlap no file path"
- Evidence (check, -, 2026-11-14): src/hub/store.rs transfer  "conflict check counts the grantor's own sub-lease"
- Evidence (check, -, 2026-11-14): src/daemon/state.rs  "lease.expired not reported to the holder; explicit leases lapse silently"
- Evidence (check, -, 2026-11-14): src/daemon/hooks.rs pre_tool_use  "stale token re-acquired silently when the path is free"
- Severity medium: first yes = Is it a correctness, measurement, statistical or design flaw that a principal-level reviewer would reject?
- Skeptic: upheld: Three of the four sub-claims hold in the code. (1) In pre_tool_use, a renew rejected for a stale token is followed by a fresh acquire, and on a grant the 'lost' flag is never shown, so the session is not told it lost the lease, which defeats the fencing promise in C-031. (2) The hub emits lease.expired, but state.rs has no handler for it, so expiry is silent. (3) In transfer(), the conflict check counts the grantor's own sub-lease. The area: sub-claim is by design: areas are advertised as named, advisory scopes. The bare-directory point stands, though: scope() accepts 'src' or 'src/' without complaint and it overlaps no file.
- Spec section that must answer it: `trust-consensus`

### F-007: novel finding

- Claims: C-010, C-042, C-044, C-050, C-051, C-059; route: retrieval (The hooks reference defines refused HTTP hooks as non-blocking; the docs list the watcher as not built.)
- Evidence (quote, primary, 2026-11-14): https://code.claude.com/docs/en/hooks.md L804 "The action goes ahead, except for hooks whose failure blocks the action"
- Evidence (note, -, 2026-11-14): docs/design.md  "Not built yet: the working-tree watcher and git pre-commit check"
- Severity medium: first yes = Is it a correctness, measurement, statistical or design flaw that a principal-level reviewer would reject?
- Skeptic: upheld: hooks.md L804 is accurate: a failed hook lets the action go ahead unless onFailure is block, and install.rs sets no onFailure (a test asserts this). Protected paths are also enforced only for edit tools, and only when the hub answers. The brief contradicts itself: C-044 describes a working-tree watcher and a pre-commit check, while C-059 says they are not built. Calling 'protected' paths a deny is an overclaim at the trust level the brief states.
- Spec section that must answer it: `crypto-agent-security`

### F-008: agent-security.confused-deputy

- Claims: C-006, C-016, C-028, C-066; route: retrieval (Tailscale semantics for shared-in and tagged nodes need the tailnet's ACLs to decide exposure.)
- Evidence (check, -, 2026-11-14): src/hub/identity.rs parse_whois  "any node whois identifies is accepted; tagged nodes use their first tag"
- Severity medium: first yes = Is it a correctness, measurement, statistical or design flaw that a principal-level reviewer would reject?
- Spec section that must answer it: `crypto-agent-security`

### F-009: agent-security.local-server-command-execution

- Claims: C-009, C-071, C-093; route: check (Traced: fixed loopback port; token in a file whose mode Claude Code sets.)
- Evidence (check, -, 2026-11-14): src/main.rs Daemon --http default 127.0.0.1:7421  "another local user can bind the port while the daemon is down and read the token from hook requests"
- Evidence (check, -, 2026-11-14): install output  "token pasted into .claude/settings.local.json with the default umask"
- Severity medium: first yes = Is it a correctness, measurement, statistical or design flaw that a principal-level reviewer would reject?
- Skeptic: upheld: The brief's own security scope (C-064) includes local endpoint misuse, and the bearer token only makes sense if other local principals exist. A squatter on 127.0.0.1:7421 while the daemon is down gets more than the token: it receives every hook body, including UserPromptSubmit prompts and edit tool_input. A settings.local.json written with the default umask is readable by other members of the staff group under a default macOS home directory. Severity is moderate on single-user machines.
- Spec section that must answer it: `crypto-agent-security`

### F-010: agent-security.untrusted-content-drives-tools

- Claims: C-001, C-038, C-065, C-097, C-098; route: check (Wrapping is the only control; tools stay available while peer text is in context.)
- Evidence (check, -, 2026-11-14): src/text.rs block  "wraps and escapes, does not restrict tools"
- Evidence (check, -, 2026-11-14): src/mcp.rs  "permission relay never declared"
- Evidence (quote, primary, 2026-11-14): https://code.claude.com/docs/en/channels-reference.md L496 "Only declare the capability if your channel authenticates the sender"
- Severity medium: first yes = Is it a correctness, measurement, statistical or design flaw that a principal-level reviewer would reject?
- Skeptic: downgraded: The code already does what the underlying problem asks for. A PREAMBLE says relayed blocks are information, not instructions. The permission relay is never declared, which matches C-039 and the channels-reference L496 advice. Hooks never return allow, so the user's permission prompts stay in force. Malicious trusted peers are out of scope (C-065). What remains is the wording in C-038: 'cannot pass as the user's instruction' promises more than wrapping can guarantee against a peer agent that has itself been injected. It would be settled by rewording C-038 as a mitigation, not a guarantee.
- Spec section that must answer it: `crypto-agent-security`

### F-011: agent-orchestration.non-idempotent-retry

- Claims: C-054, C-029; route: check (Push and pull both deliver; blocks carry seq.)
- Evidence (check, -, 2026-11-14): src/daemon/hooks.rs take_inbox  "push does not mark read; pull redelivers"
- Severity medium: first yes = Is it a correctness, measurement, statistical or design flaw that a principal-level reviewer would reject?
- Skeptic: downgraded: The brief already discloses the duplicate (C-054), every block already carries a seq attribute (from_attrs), and the duplicate happens only when channels are enabled. Relayed text is framed as information, so a duplicate usually costs nothing. What is missing is only one line in the preamble telling the model to act once per seq. It would be settled by a real session that receives a duplicated request and either repeats the action or does not.
- Spec section that must answer it: `product-scope`

### F-012: agent-orchestration.unbounded-agent-loop

- Claims: C-034, C-059, C-062, C-065, C-091; route: check (No rate limit or retention in code.)
- Evidence (check, -, 2026-11-14): src/hub/mod.rs  "no per-connection send limit; events never pruned"
- Evidence (check, -, 2026-11-14): src/daemon/state.rs  "inbox capped at 100 per session; context capped at 8,000 characters"
- Severity medium: first yes = Is it a correctness, measurement, statistical or design flaw that a principal-level reviewer would reject?
- Skeptic: downgraded: The brief already lists no rate limits and no event pruning as known gaps (C-059, C-062), and puts trusted-peer DoS out of scope (C-065). Each session is bounded at 100 inbox notices and 8,000 characters of context, and idle-session wake (asyncRewake) is unverified, so an agent-to-agent loop moves forward only while both sessions are active. That makes this a storage and token-cost bound, not a runaway. It would be settled by a two-session auto-reply test that measures growth.
- Spec section that must answer it: `capacity-physics`

### F-013: performance.percentile-slo-without-load-model

- Claims: C-004, C-032, C-033, C-034, C-046, C-047, C-049, C-060, C-112, C-113, C-115, C-116; route: experiment (Only a two-machine measurement settles cross-machine latency.)
- Evidence (note, -, 2026-11-14): docs/design.md Measured  "localhost only, 300 sequential samples, one client"
- Severity medium: first yes = Is it a correctness, measurement, statistical or design flaw that a principal-level reviewer would reject?
- Spec section that must answer it: `capacity-physics`

### F-014: novel finding

- Claims: C-026; route: check (Traced: replay runs before requests are read.)
- Evidence (check, -, 2026-11-14): src/hub/mod.rs connection  "replay is awaited before the request loop and inside the Lagged arm"
- Severity medium: first yes = Is it a correctness, measurement, statistical or design flaw that a principal-level reviewer would reject?
- Skeptic: downgraded: The code matches the finding: hub.replay() is awaited before the select loop and inside the Lagged arm, so requests wait while the hub replays. The only effect is fail-open: lease checks pass their 800 ms deadline and return a stale notice. Replay is capped at 100,000 events in batches of 500, and on localhost it takes milliseconds. It would be settled by timing a worst-case replay over a real tailnet.
- Spec section that must answer it: `capacity-physics`

### F-015: novel finding

- Claims: C-012, C-036; route: check (Traced: the state block is cut at 2,000 characters with sessions before leases.)
- Evidence (check, -, 2026-11-14): src/daemon/hooks.rs who_text; src/text.rs MAX_BLOCK  "leases are listed after up to 30 sessions from all repos"
- Severity medium: first yes = Is it a correctness, measurement, statistical or design flaw that a principal-level reviewer would reject?
- Skeptic: downgraded: Real but conditional. who_text lists up to 30 sessions from every repo before this repo's leases, and block() cuts the body at MAX_BLOCK, 2,000 characters. At roughly 100-150 characters per session line, leases fall off only past about 12-15 other sessions, which is unlikely for a small trusted tailnet. It would be settled by the expected session count. Listing this repo's leases first is still a cheap fix.
- Spec section that must answer it: `product-scope`

### F-025: supply-chain.autonomous-agent-install

- Claims: C-003, C-101; route: none (Patch and blob passing are not built.)
- Evidence (note, -, 2026-11-14): docs/design.md  "file passing and patches listed under Later"
- Severity medium: first yes = Is it a correctness, measurement, statistical or design flaw that a principal-level reviewer would reject?
- Spec section that must answer it: `crypto-agent-security`

### F-017: novel finding

- Claims: C-023, C-083, C-085, C-086, C-087; route: retrieval (The channels page states auth, provider and org requirements.)
- Evidence (quote, primary, 2026-11-14): https://code.claude.com/docs/en/channels.md L11 "They require Anthropic authentication through claude.ai or a Console API key, and are not available on Amazon Bedrock, Google Cloud's Agent Platform, or Microsoft Foundry. Team and Enterprise organizations must explicitly enable them."
- Severity low: first yes = Is it operational friction, weaker maintainability, or minor inefficiency?
- Skeptic: downgraded: The channels.md L11 quote is accurate, and the brief leaves out the Bedrock, Agent Platform and Foundry exclusion and the auth requirement. But channels are optional (C-018) and hooks deliver the same content, so users on those providers lose push, not function. The brief already notes research preview and the admin enablement. What remains is one sentence on availability and that relayed text is model input under each user's agreement.
- Spec section that must answer it: `legal-terms`

### F-020: privacy-regulated-data.collect-all-keep-forever

- Claims: C-059, C-062, C-082, C-084; route: check (No pruning in code.)
- Evidence (check, -, 2026-11-14): src/hub/store.rs  "events (with message bodies) never deleted"
- Severity low: first yes = Is it operational friction, weaker maintainability, or minor inefficiency?
- Skeptic: downgraded: store.rs never deletes events, so message bodies are kept indefinitely. But the brief already lists retention as not built (C-059), and the hub is self-hosted on the owner's own tailnet with no third-party processor. This is a documentation and pruning gap, not regulated-data exposure. It conflicts mildly with C-041's 'paths and one-line summaries', which does not cover msg bodies. It would be settled by a stated retention period plus a prune command.
- Spec section that must answer it: `legal-terms`

## Poisoned-instruction autopsy

| Brief locator | Quarantined text | Findings | Reason | Replaced by |
|---|---|---|---|---|
| L36 | a warning before editing a file another session holds | F-001 | PreToolUse context lands next to the tool result, after the edit. | The warning reaches the model when it edits a held file; a pre-edit policy is the owner's open decision (F-001). |
| L97 | delivered in order and at least once | F-003, F-004, F-011 | A daemon restart lost undelivered messages; replay window and broadcast limits apply. | Session messages are replayed until shown; duplicates possible under the same seq; broadcast and user messages reach sessions known at arrival; replay window 100,000 events. |
| L111 | the pre-edit check rejects writes that carry a stale token | F-006 | The hub rejects stale renew/release; the hook then re-acquires and warns or reports the lapse; files are not checked. | Stale tokens are rejected by the hub and reported to the session at its next edit. |
| L138 | Daemon reconnects resume from the last sequence number, so no event is lost. | F-003, F-004 | Not true across daemon restarts or a reset hub log before the fixes; bounded by the replay window after. | Resume from the hub cursor kept before the oldest undelivered message; follow a hub log that went back. |
| L139 | the daemon also watches the working tree and a git pre-commit check reports conflicts | F-007 | Neither is built. | Shell-command edits are not checked; watcher and pre-commit check are later. |
| L131 | channel permission relay is off by default | F-010 | wormhole never declares the capability; it cannot be enabled. | Permission relay is never declared. |

## Dismissed

- F-016 (agent-orchestration / novel): The brief states these semantics correctly (seconds, non-blocking failures, SessionStart command-only); no trap.
- F-018 (licensing / novel): Every dependency is permissively licensed or dual-licensed with a permissive option; compatible with Apache-2.0.
- F-019 (supply-chain / supply-chain.unpinned-dependencies): Dependencies are pinned: Cargo.lock is committed, and CI runs clippy and test with --locked. The finding's evidence leaves that out. A plain 'cargo build --release' still honours the committed lockfile; --locked only turns drift into a failure instead of a silent update. An unpinned stable toolchain and the first-party actions/checkout@v4 tag are hygiene issues, not an unpinned-dependency trap. Optional polish: add --locked to the README.
- F-021 (agent-security / novel): Cross-site WebSocket hijacking is blocked: the hub refuses any request with an Origin header on /ws.
- F-022 (agent-security / novel): No single block can exceed the budget, so the truncation branch never cuts a wrapper in practice.
- F-023 (databases / databases.isolation-anomaly): Acquire's check-then-insert is serialised by the hub's single store mutex; no concurrent writer exists.
- F-024 (accessibility / accessibility.information-by-single-sense): Read-only text tables; no state is conveyed by colour and nothing needs pointer operation.

_Not legal advice. The skill flags and cites; the owner decides._

