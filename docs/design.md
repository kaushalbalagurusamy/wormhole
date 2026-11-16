# Design

Status: first slice built and tested on one machine (2026-11-14). Numbers marked "estimate" are not measured. Localhost measurements are under "Measured"; cross-machine numbers are not yet measured.

## Problem

Agents in separate sessions act on a stale view of the repo. A 2026 study of independent coding agents with no coordinator (ParallACT, see related-work.md) found that on conflicting tasks Claude Code's pass rate fell from 62% to 16%, and that only 21–23% of messages between agents were read before the recipient's first edit. When agents knew each other's tasks and agreed who owned the contested code, conflicts fell from 67% to 18%. The failure is timing, so delivery has to happen at edit time, not in an inbox the agent might check later.

## How a session receives outside input

A Claude Code session takes in outside input at two points:

1. Between tool calls, through hooks. `SessionStart`, `UserPromptSubmit`, `PreToolUse` and `PostToolUse` hooks can inject text as a system reminder (`additionalContext`, up to 10,000 characters). `PreToolUse` can deny a tool call with a reason. Hooks can be commands or HTTP calls. Generally available.
2. At any time, through a channel: an MCP server that declares the `claude/channel` capability and sends `notifications/claude/channel`. The event appears in the session as a tagged block. Research preview: enabled per session with a launch flag, and on Team or Enterprise plans by an admin setting (`channelsEnabled`). Channels require Anthropic authentication (a claude.ai account or a Console API key) and are not available on Amazon Bedrock, Google Cloud or Microsoft Foundry (channels docs, read 2026-11-14); without them wormhole still delivers everything through hooks, only later.

Claude Code's own cross-session messaging (`ListAgents`, `SendMessage`) uses the same two entry points but only reaches sessions on the same account. wormhole provides the relay across accounts and machines.

## Components

```
 developer machine A                      hub machine                          developer machine B
 Claude Code sessions                     hub                                  Claude Code sessions
   channel MCP server  <-unix socket->     ordered event log (SQLite)            channel MCP server
   hooks (HTTP)           daemon <-WS->    presence, leases, inboxes, blobs  <-WS-> daemon <-unix socket->
                                           supervision fan-out                     hooks (HTTP)
```

- **hub**: one process. Holds the ordered event log, presence and leases (content-addressed blobs are later). Listens on the private network only.
- **daemon**: one process per developer machine. Keeps one WebSocket to the hub, resumes from the last sequence number after a disconnect, and serves local sessions over a Unix socket.
- **channel server**: a stdio MCP server Claude Code starts per session; it forwards between the session and the local daemon and pushes inbound events into the session.
- **hooks**: HTTP hooks to the local daemon for the synchronous paths (lease check before an edit, activity after a tool call, context at session start).

Identity: the hub identifies each connection by the private network's own identity (for Tailscale, `tailscale whois` on the peer address), which names the tailnet login and node, not the operating-system account. No shared tokens.

## Messages

All messages are JSON and carry a hub-assigned sequence number. Each daemon receives them in order. A message to a session is kept in the hub's log and replayed to that session's daemon after a disconnect or a daemon restart until the session has been shown it, so it can arrive more than once (push and pull, or a replay); the `seq` attribute identifies it. A broadcast or user message reaches the sessions known on each machine when it arrives. A daemon offline for more than 100,000 events is not replayed the gap.

| Kind | Fields | Purpose |
|---|---|---|
| `hello`, `heartbeat`, `bye` | session id, user, machine, repo, branch, task | presence and discovery |
| `event` | kind (edit, command, commit, push, pr), paths, one-line summary, ref | activity stream |
| `msg` | from, to (session, user or broadcast), body, reply_to | messaging |
| `lease.acquire`, `lease.renew`, `lease.release` | scope (path glob or named area), ttl, fencing token | mutual exclusion |
| `lease.request_transfer`, `lease.grant`, `lease.deny` | scope, from, to, reason | handing a lease to another session |
| `blob.offer`, `blob.fetch` | content hash, size, name | file passing |
| `patch.propose` | base ref, diff, target session | proposing a change to another session |
| `watch`, `unwatch` | session id, detail level | supervision subscription |
| `delegation.request`, `delegation.ack`, `delegation.result` | contract (paths, exact command patterns, exit condition, text), status, level, summary | delegating work (built; see "Delegation") |

Built in the first slice: presence, `event`, `msg` and the `lease.*` kinds. Delegation (`delegation.*`) is built in the delegation slice. Blobs, patches and supervision are later.

Leases expire unless renewed, so a crashed session cannot hold one indefinitely; a session whose presence times out (120 s without a heartbeat) loses its leases at once. The fencing token increases on every grant, and the hub rejects a renew or release that carries a stale token. The check runs in the edit hook, not on the file: after a rejection the hook acquires again, warning if another session now holds the path (deny for a protected path) and, if the path was free, saying that the earlier lease lapsed. A plain scope is a file; a directory scope ends with `/` (the lease tool adds it when the path is an existing directory) and covers everything under it; `area:` names conflict only with the same name.

## Delivery and latency

| Path | Mechanism | Latency to the receiving session | Status |
|---|---|---|---|
| Pull at next action | `UserPromptSubmit` and `PostToolUse` hooks return unread messages and change notices | at the receiver's next tool call or prompt | generally available |
| Lease check before an edit | `PreToolUse` HTTP hook asks the daemon | roughly 50–200 ms on a private network (estimate; cross-machine not yet measured); 0.20 ms p50 on localhost over ws://, 0.21 ms over wss:// (measured). The warning text reaches the model after the edit (see the open problem below); a deny reaches it before | generally available |
| Push | channel notification | about 1 s while the session is open (estimate; not yet measured into a live session); send to a client on the receiving daemon's socket 0.09 ms p50 on localhost (measured) | research preview |
| Wake an idle session | channel event, or an `asyncRewake` hook | seconds (estimate) | channel: preview; `asyncRewake` support per event to be verified |

## Defaults chosen from the evidence

- **Warn, do not block.** A conflicting edit gets the holder, the scope and the time, and the agent decides. Hard blocks are opt-in per path. CoAgent (related-work.md) found hard locks perform worse than telling an agent what changed and letting it repair.
- **Tell an agent when something it read has changed.** The daemon tracks files a session has read; a later edit by another session produces a change notice at the reader's next action.
- **Server-tracked claims, not negotiation in chat.** AgentRoom (related-work.md) found claims tracked by a server beat agents negotiating ownership in messages.

## Fault model

Decided 2026-11-14. Every other trust or safety statement in this repo follows from this section.

- **Participants are honest.** Every machine is an enrolled device on the team's tailnet, identified by its node key through `tailscale whois`, and every user on it is a teammate. Nobody lies to the hub on purpose. Byzantine fault tolerance (replicas that outvote liars, signed events, lying-peer detection) is a non-goal, and work aimed only at a dishonest participant is not done.
- **Participants are fallible.** Honest machines still crash, lose power, get partitioned, run buggy builds, loop, and relay text their agent read from an untrusted source. The design tolerates these faults. Guards against them stay: ownership and fencing checks, session binding, text cleaning and wrapping, bounded queues, and receiver-side caps. They exist to catch bugs and accidents, not adversaries.
- **Crash faults are tolerated for work, not for coordination.** Any component can crash or be cut off without corrupting shared state or blocking an edit: hooks let the action through and say the state is stale. There is one hub and no replica, so while it is down there is no coordination. Recovery restores it: daemons resume from their cursors and leases expire on their own.
- **Participants trust each other; the network path is not trusted:** traffic is encrypted by WireGuard on the tailnet and by TLS when enabled.
- **Device enrolment is the trust boundary.** Admitting a node to the tailnet admits it to wormhole. Narrow that with tailnet ACLs and `wormhole hub --allow`. Tailscale's Tailnet Lock makes enrolment require a signature from a trusted node, which matches the "signed devices" assumption; wormhole does not check whether it is on.
- **Consequences.** A peer that claims every lease, sends inaccurate activity, or floods messages is treated as a bug: rate limits and pruning are for loops, not abuse. The hub is trusted to keep the log honestly. Work toward tolerating more crash faults is in scope: keeping daemon state across restarts, watching the working tree, and possibly a replicated hub.

## Trust and safety

- Participants are trusted (see "Fault model"), but messages from other agents are still data to the receiving model. Every inbound message is wrapped as coming from a named session and cleaned, so it is not mistaken for the local user's instruction. Wrapping does not stop a model from following it, and a trusted agent can relay text it read from an untrusted source; the user's own permission prompts stay in force because wormhole answers `allow` only under a bypass level the receiving owner granted in a local policy, inside an open contract, for a path or exact argv command pattern that contract names, and never for a denylisted path or command, while the hub is stale, or for a path another session leases. Without such a contract the hook output is exactly what it was before delegation existed.
- Risk beside each delegation level. A trusted node may be compromised, or a trusted agent may relay text it read from an untrusted source (relayed injection); either acts with the receiving session's rights.

  | Level | What a relayed injection can do | Cost of a compromised trusted sender |
  |---|---|---|
  | `off` | Nothing; declined unread. | None. |
  | `inform` | What any message can do today: the model may follow it; prompts stay. | As today. |
  | `scoped-instruction` | The model treats the task as its user's instruction inside the paths and kind; every tool call still prompts. | Steers work inside the scope; the user sees each action. |
  | `scoped-bypass` | Edits inside the contract paths and the listed exact command patterns run without a prompt until the contract ends. | Arbitrary content in the granted paths, and the granted commands run (`cargo test` on a writable scope is code execution). |
  | `full-bypass` | Bash, edits and Read inside the repository (not denylisted, not protected) without a prompt, until the contract ends; every other tool still prompts. | A shell on the receiving machine for the contract's life. Grant only to senders whose machine you would hand your keyboard to. |
- At `scoped-bypass` the contract's command allowlist is the boundary. A command runs without a prompt only if the raw text has no quote, backslash, glob or brace character or `~`, it tokenises (shell separators, substitution, redirection and a leading `#` or `~` refused), and it matches a contract pattern word for word, program included (a pattern may end in a lone `*` for plain arguments), and the pattern's program is on the safe list. Anything else gets the normal local prompt, never a silent allow or deny. Default safe programs: `ls` and `stat` (list and describe files), `cat`, `head`, `tail` and `wc` (read files), `grep` and `diff` (search and compare), `cut`, `tr`, `basename`, `dirname` and `realpath` (pure text and path tools), and `pwd`, `echo`, `true` and `false` (print or exit). Each is on the list because none has an option that runs another program or writes a file. Left out on purpose: `rg` (`--pre`), `sort` (`--compress-program`, `-o`), `uniq` (writes its second operand), `rustfmt` (writes files outside any scope), shells, interpreters, `env`, `xargs`, `find`, `awk`, `sed`, `make`, `npx`, `npm` and `sudo`. `git` and `cargo` are not defaults: the owner may add them to `safe_programs`, and then they are usable only as `git|cargo <literal subcommand> [listed options]` (git: `status`, `log`, `diff`, `show` with `--oneline --stat --name-only --name-status --short --porcelain --cached --staged --no-color`; cargo: `test`, `check`, `build` with `--lib --bins --tests --doc --all-targets --workspace --release --locked --offline --quiet -q --no-fail-fast`); `cargo test` and `cargo build` still run project code (tests, build scripts), which is the owner's choice. Any other program added through `safe_programs` is the owner's responsibility: add only programs with no exec, config or alias escape. At `scoped-bypass`, every operand of an allowed command is read as a path and must be inside the repository (symlinks followed, none dangling), not protected and not denylisted; options containing `=` are refused; the allow also needs the session's repository to equal the contract's, no `dangerouslyDisableSandbox`, an audit line written first, and the policy file still granting the contract at its level (a narrowed policy closes the contract).
- The denylist (substring patterns, argv-aware checks, path globs) is defence in depth. Its text screen over contract text is a tripwire: free text can be reworded; argv checks are examples, not claims of completeness, because a list of dangerous programs cannot be complete. Path checks are applied to every concrete path per call.
- At `full-bypass`, Bash is not bounded by any parser. It is a trust decision about the sender: the tokenizer, wrapper and denylist checks are a speed bump, not a guarantee.
- Remote approval of another session's tool calls (channel permission relay) is never declared by wormhole's channel server, so it cannot be enabled through wormhole. It would let another person approve command execution on your machine.
- The hub listens only on the private network. No path is exposed to the public internet.
- The hub refuses to serve plaintext on any address other than loopback or a Tailscale address (100.64.0.0/10, fd7a:115c:a1e0::/48), and the daemon refuses a `ws://` hub URL whose host is not loopback, a Tailscale address or a `*.ts.net` name. With `--tls-cert` and `--tls-key` (from `tailscale cert`) the hub serves `wss://` and `https://`; the daemon verifies the certificate against the system roots, with no option to skip verification. TLS covers the daemon-to-hub link end to end, including where WireGuard stops short of the hub (a subnet router or exit node on the path). Identity still comes from `tailscale whois`, so the hub must run Tailscale; a non-Tailscale private network is not supported for identity yet. The hook and channel paths stay on the local machine (loopback HTTP and a Unix socket).
- By default events carry paths and one-line summaries, not file contents or prompts. Full supervision detail is opt-in per session.

## Delegation

Decisions: docs/adr/0001-delegation.md; contract: docs/slices/delegation-v1/spec.md. Built and tested in the delegation slice (2026-11-15).

- A session sends `Delegate` (to one session in the same repository) with a contract. The hub stores it in a `delegations` table, emits `delegation.request`, and shows it only to the sender's and target's machines; the activity page shows ids, kind, status, level and paths, never text, summaries, commands or result fields. A request to a session whose daemon did not advertise the `delegation` capability is refused, and a daemon sends delegation frames only on a connection whose `Welcome` listed it, so old hubs and daemons behave as before.
- The target daemon decides from its local policy file (re-read per request) using the hub-stamped sender, never payload fields. Acceptance goes through the hub (`DelegateAck`), which in one transaction releases the sender's own leases the contract paths cover and leases the paths to the target; a conflict, or a hub that does not answer, means the request is not accepted. A replayed request never reopens a contract. Contracts live in daemon memory and end on result, TTL, step budget or the kill switch.
- Notices to the receiving session put the daemon's status line, limits and denylisted kinds before the relayed text, which is capped so the block cap cannot remove them. Every notice keeps the preamble.
- Decisions, bypass answers, closes, revokes and results are appended to a JSONL audit log (0600) beside the policy.

## Failure behaviour

- Hub unreachable: hooks return within 800 ms and allow the action, with a notice that state is stale. Work is never blocked by an outage, which also means a protected path is not protected while the hub is unreachable or the daemon is down.
- Daemon reconnects and restarts resume from the hub's cursor, which stays before the oldest message not yet shown to its session; a hub whose log went back (database reset, or commits lost on power failure) is followed rather than ignored. See "Messages" for the limits.
- Edits made through shell commands bypass the edit hook, so leases and protected paths do not cover them. A working-tree watcher and a git pre-commit check would report them; neither is built yet.

## Resource use per developer machine

- daemon: one process; 10.2 MB resident and no measurable CPU when idle on localhost (measured, see below). Earlier estimate: 10–20 MB, near 0%.
- channel server: one per session; 7.9 MB resident (measured). Earlier estimate: 10–20 MB.
- hooks: HTTP hooks run inside Claude Code; no extra process. `SessionStart` runs `wormhole hook` once per session start (about 3 ms).

## First slice

1. hub and daemon: presence, messaging, leases with expiry and fencing.
2. Claude Code integration: `SessionStart` context, `PreToolUse` lease check (warn), `PostToolUse` activity and inbox, channel push.
3. A read-only activity page.
4. Acceptance: two machines; measure message latency (push and pull), hook latency, and resource use; show a lease conflict warning and a lease transfer between sessions; show a change notice after another session edits a file the first one read. Results recorded in this file with the date and versions.

Later: file passing, patch proposals, supervision detail levels, work delegation, other agents (Codex, Cursor) through the same daemon.

## First slice as built

What exists: `wormhole hub`, `wormhole daemon`, `wormhole mcp-channel`, `wormhole hook` and `wormhole install`, in one Rust binary. Acceptance tests (tests/acceptance.rs) run a hub and two daemons in one process over localhost with static identity: lease conflict warning, protected-path deny, lease transfer handshake (grant and deny), fencing rejects a stale holder, message delivery at the next `PostToolUse`, change notice after another session edits a file the first one read, reconnect resumes without loss or duplicates, hooks fail open when the hub is down, the activity page and its live updates, and the channel server as a real process.

Where the implementation differs from the text above, because of what Claude Code supports today (hooks reference read 2026-11-13):

- `SessionStart` does not accept HTTP hooks, only command and MCP-tool hooks, and MCP-tool hooks are skipped at launch. It runs `wormhole hook`, which asks the daemon over its Unix socket and prints the stale-state note itself if the daemon does not answer within 800 ms.
- Hook `timeout` is in whole seconds, so the 800 ms limit is enforced inside the daemon: every hub request carries a deadline, and on expiry the hook answers with a stale-state note and lets the action go ahead. The settings use a 5 s timeout only as a backstop, and never `onFailure: "block"`.
- When the daemon itself is down, Claude Code treats the refused HTTP hook as a non-blocking error: the action goes ahead, but no stale-state note can be shown. Only the hub-down case and `SessionStart` produce the note.
- `PreToolUse` returns `permissionDecision: "allow"` only under an open delegation bypass contract (see "Delegation"); otherwise never, since that would skip the user's own permission prompt. Warnings go in `additionalContext`; `deny` is used only for a protected path held by another session and for the hook bodies and paths that cannot be checked (below).
- `PostToolUse` matches every tool, so messages arrive at the next tool call of any kind and `Read` is seen for change notices.
- The hook endpoint requires a bearer token (`hook-token` next to the socket), because any local user can reach loopback. It checks the token before reading the body. Bodies carry file contents (a `Write` input holds the whole file), so the daemon reduces each body while it streams in, replacing strings over 4 KiB with empty ones; memory stays bounded and edits of any size get the normal lease check. It never answers 413, since Claude Code would treat that as a non-blocking error and the edit would skip the check. A body it cannot parse, or one that is still over 1 MiB once reduced, or over 1 GiB in total, gets a deny with the reason, and so does an edit whose path is over 4 KiB or whose repo-relative path is over 512 bytes, since neither can be checked. That path deny is given only when the hub answers within the hook's deadline; when it does not, the edit goes ahead with the stale note, as any edit does. These are the only cases where a hook fails closed.
- A channel push does not mark a message read: Claude Code drops channel events silently when the channel is not enabled for the session. Only the pull path marks messages read, so with channels enabled a message can appear twice.
- The channel server never negotiates MCP revision 2026-07-28. Claude Code's v2 MCP runtime asks stdio servers for that revision by default and does not register a channel server that negotiates it (MCP docs, "Push messages with channels", read 2026-11-14); the server answers with 2025-06-18 instead.
- The channel server learns its session from `CLAUDE_CODE_SESSION_ID`. After `/clear` an MCP server keeps the id it was started with, so pushes keep going to the old id until restart.
- `MultiEdit` is not in the current tools reference; the matcher keeps it in case it is used, and `NotebookEdit` paths are read from `file_path` or `notebook_path`.
- Leases are acquired on repo-relative paths after resolving symlinks and `..`. The repository id is the normalised, lowercased `origin` URL, so checkouts on different machines share leases; where an ssh host alias or a fork gives a different URL, set the same id on each checkout with `git config wormhole.repoId github.com/owner/repo`. Leases do not distinguish branches.

Checked in a real Claude Code session (2.1.325, `claude -p`, 2026-11-14, one machine, static identity): the settings printed by `wormhole install` were accepted as written; the `SessionStart` context reached the model; `PreToolUse` took a lease, `PostToolUse` recorded the edit and `SessionEnd` released the lease. Claude Code's HTTP hook client sent no `Origin` header, so the daemon's browser check does not get in its way.

Open problem found in that run: the conflict warning arrives after the edit. Claude Code inserts `PreToolUse` `additionalContext` next to the tool result, so the model read "WARNING from wormhole: notes.txt ... is leased by another session" only once the write had happened. Warn-not-block therefore informs the next action, not the conflicting one. Options to decide: deny the first conflicting attempt with the warning as the reason and allow a deliberate retry of the same path within a short window (the agent still decides, before the edit); use `permissionDecision: "ask"` so the user decides; or keep the current behaviour and rely on `SessionStart` and push to warn earlier. Until then, only protected paths are stopped before the edit.

The independent review (2026-11-14) recommends: deny the first conflicting attempt with the warning as the reason, keyed on (session, path, holder's token) rather than a time window, so an agent that messages the holder and waits is not denied again, and a new holder warns afresh; never answer `allow` outside a delegation bypass contract; keep failing open when the hub is down. A deny reason is shown to Claude before the edit, while an `ask` reason goes to the user, stalls unattended sessions and becomes a plain deny in `-p` runs. As a cheaper first line, warn when a session `Read`s a leased file, from a lease mirror the daemon keeps from the event stream, so the warning arrives before the edit is composed. Cost: a denied `Write` must be regenerated. To verify before choosing: that a hook deny holds in `acceptEdits` and auto permission modes. The owner decides.

Not built yet: the working-tree watcher and git pre-commit check for edits made through shell commands; file passing, patches, supervision; remote tool approval (permission relay) for delegation; a per-sender rate limit on `Delegate`; a result posted when a contract closes on TTL or steps (its leases expire with the contract TTL); `lease.*` events from a hand-off are visible to every machine, like all lease events; a login containing `@` makes `user@machine` grants ambiguous; event log retention; rate limits. A daemon restart keeps undelivered messages (they are replayed from the hub) but forgets which files each session read and its lease tokens, so pending change notices are lost and the next edit simply acquires again.

## Measured

Localhost only: one Apple M5 Pro (macOS, arm64), hub and two daemons on 127.0.0.1 with static identity, release build of commit 8a852b0, rustc 1.100.0, 2026-11-14. Produced by `scripts/bench.sh 300`, which runs the same requests over `ws://` and over `wss://` (TLS on the daemon-to-hub link, with a throwaway CA). p95 and p99 come from 300 sequential requests by one client, not from load. Cross-machine numbers (the point of the project) are not yet measured.

| Measurement | ws:// p50 | p95 | p99 | wss:// p50 | p95 | p99 |
|---|---|---|---|---|---|---|
| `PreToolUse` hook round trip, lease renew through the hub | 0.20 ms | 0.47 ms | 0.56 ms | 0.21 ms | 0.48 ms | 0.52 ms |
| `PreToolUse` hook round trip, conflict warning | 0.18 ms | 0.21 ms | 0.25 ms | 0.18 ms | 0.20 ms | 0.22 ms |
| `PostToolUse` hook round trip, nothing to deliver (no hub call) | 0.10 ms | 0.11 ms | 0.12 ms | 0.10 ms | 0.11 ms | 0.11 ms |
| `SessionStart` through `wormhole hook` (process start included) | 2.91 ms | 3.26 ms | 3.53 ms | 2.95 ms | 3.31 ms | 3.76 ms |
| Message from session A to a client attached to B's daemon socket, as the channel server attaches (send, hub, fan-out, push; the `mcp-channel` process and Claude Code are not in this path) | 0.09 ms | 0.14 ms | 0.16 ms | 0.11 ms | 0.14 ms | 0.16 ms |

TLS adds about 0.01–0.02 ms at p50 on paths that cross the hub link, within the run-to-run noise; the hook endpoints themselves are unchanged, since TLS sits only between daemon and hub. These numbers exclude Claude Code's own hook overhead and network latency. A `PostToolUse` delivering a backlog returns as many messages as fit in 8,000 characters (32 short ones in the run) and keeps the rest for the next call.

Compared with the first run (commit 073bfc9, before the review fixes and TLS): hook round trips are the same within noise; `SessionStart` through the command went from 2.0 ms to 2.9 ms p50 and resident memory grew, both from the larger binary (rustls, ring and the added code).

| Idle resource use (60 s, after the ws:// run) | |
|---|---|
| daemon resident memory | 10.2 MB (6.0 MB at 073bfc9) |
| daemon CPU | below 0.02% (no CPU time recorded at the 10 ms resolution of `ps`) |
| hub resident memory | 11.6 MB (7.6 MB at 073bfc9) |
| hub CPU | 0.05% (lease and presence sweep every 500 ms) |
| channel server resident memory | 7.9 MB (4.0 MB at 073bfc9) |

## Security notes

See SECURITY.md for what is covered. Known gaps in this slice:

- No rate limits: an agent loop between trusted sessions is bounded only at the receiver (100 notices per session, 8,000 characters per hook).
- The event log, with message bodies, and session-id bindings are never pruned; the hub database grows until it is deleted (daemons follow a reset log).
- The hook port is fixed. While the daemon is down, another local user could listen on 127.0.0.1:7421 and receive hook requests, including the token and edit contents. A command-hook transport over the uid-checked socket would avoid this; it is not the default.
- Any process running as the same user, including the agent's own shell, can read the hook token and use the daemon socket, and so act as any session on that machine.
- Identity is per node. A process under any other account on the machine can skip the daemon, connect to the hub itself and be that machine: read its sessions' messages and act as them.
- By default the hub accepts every node `tailscale whois` identifies, including nodes shared in from another tailnet; use `--allow` and tailnet ACLs to narrow it. Tagged nodes are identified by their first tag.
- After an outage with a backlog, the hub replays before it serves requests, so hooks fail open with a stale note until the replay ends.
- Activity summaries are generated by the daemon from paths, never from command text or contents, but the hub trusts the daemon to do so.
