# Design

Status: first slice built and tested on one machine (2026-11-14). Numbers marked "estimate" are not measured. Localhost measurements are under "Measured"; cross-machine numbers are not yet measured.

## Problem

Agents in separate sessions act on a stale view of the repo. A 2026 study of independent coding agents with no coordinator (ParallACT, see related-work.md) found that on conflicting tasks Claude Code's pass rate fell from 62% to 16%, and that only 21–23% of messages between agents were read before the recipient's first edit. When agents knew each other's tasks and agreed who owned the contested code, conflicts fell from 67% to 18%. The failure is timing, so delivery has to happen at edit time, not in an inbox the agent might check later.

## How a session receives outside input

A Claude Code session takes in outside input at two points:

1. Between tool calls, through hooks. `SessionStart`, `UserPromptSubmit`, `PreToolUse` and `PostToolUse` hooks can inject text as a system reminder (`additionalContext`, up to 10,000 characters). `PreToolUse` can deny a tool call with a reason. Hooks can be commands or HTTP calls. Generally available.
2. At any time, through a channel: an MCP server that declares the `claude/channel` capability and sends `notifications/claude/channel`. The event appears in the session as a tagged block. Research preview: enabled per session with a launch flag, and on Team or Enterprise plans by an admin setting.

Claude Code's own cross-session messaging (`ListAgents`, `SendMessage`) uses the same two entry points but only reaches sessions on the same account. wormhole provides the relay across accounts and machines.

## Components

```
 developer machine A                      hub machine                          developer machine B
 Claude Code sessions                     hub                                  Claude Code sessions
   channel MCP server  <-unix socket->     ordered event log (SQLite)            channel MCP server
   hooks (HTTP)           daemon <-WS->    presence, leases, inboxes, blobs  <-WS-> daemon <-unix socket->
                                           supervision fan-out                     hooks (HTTP)
```

- **hub**: one process. Holds the ordered event log, presence, leases, inboxes and content-addressed blobs. Listens on the private network only.
- **daemon**: one process per developer machine. Keeps one WebSocket to the hub, resumes from the last sequence number after a disconnect, and serves local sessions over a Unix socket.
- **channel server**: a stdio MCP server Claude Code starts per session; it forwards between the session and the local daemon and pushes inbound events into the session.
- **hooks**: HTTP hooks to the local daemon for the synchronous paths (lease check before an edit, activity after a tool call, context at session start).

Identity: the hub identifies each connection by the private network's own identity (for Tailscale, `tailscale whois` on the peer address). No shared tokens.

## Messages

All messages are JSON, carry a hub-assigned sequence number, and are delivered in order and at least once.

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
| `request`, `result` | task text, status, output summary | delegating work |

Leases expire unless renewed, so a crashed session cannot hold one indefinitely. The fencing token increases on every grant; the pre-edit check rejects writes that carry a stale token.

## Delivery and latency

| Path | Mechanism | Latency to the receiving session | Status |
|---|---|---|---|
| Pull at next action | `UserPromptSubmit` and `PostToolUse` hooks return unread messages and change notices | at the receiver's next tool call or prompt | generally available |
| Lease check before an edit | `PreToolUse` HTTP hook asks the daemon | before the edit, roughly 50–200 ms on a private network (estimate; cross-machine not yet measured); 0.19 ms p50 on localhost (measured) | generally available |
| Push | channel notification | about 1 s while the session is open (estimate; not yet measured into a live session); daemon-to-channel-server 0.09 ms p50 on localhost (measured) | research preview |
| Wake an idle session | channel event, or an `asyncRewake` hook | seconds (estimate) | channel: preview; `asyncRewake` support per event to be verified |

## Defaults chosen from the evidence

- **Warn, do not block.** A conflicting edit gets the holder, the scope and the time, and the agent decides. Hard blocks are opt-in per path. CoAgent (related-work.md) found hard locks perform worse than telling an agent what changed and letting it repair.
- **Tell an agent when something it read has changed.** The daemon tracks files a session has read; a later edit by another session produces a change notice at the reader's next action.
- **Server-tracked claims, not negotiation in chat.** AgentRoom (related-work.md) found claims tracked by a server beat agents negotiating ownership in messages.

## Trust and safety

- Participants are trusted, but messages from other agents are still data to the receiving model. Every inbound message is wrapped as coming from a named session, so it cannot pass as the local user's instruction.
- Remote approval of another session's tool calls (channel permission relay) is off by default. Enabling it lets another person approve command execution on your machine.
- The hub listens only on the private network. No path is exposed to the public internet.
- By default events carry paths and one-line summaries, not file contents or prompts. Full supervision detail is opt-in per session.

## Failure behaviour

- Hub unreachable: hooks return within a short timeout and allow the action, with a notice that state is stale. Work is never blocked by an outage.
- Daemon reconnects resume from the last sequence number, so no event is lost.
- Edits made through shell commands bypass the edit hook; the daemon also watches the working tree and a git pre-commit check reports conflicts.

## Resource use per developer machine

- daemon: one process; 6.0 MB resident and no measurable CPU when idle on localhost (measured, see below). Earlier estimate: 10–20 MB, near 0%.
- channel server: one per session; 4.0 MB resident (measured). Earlier estimate: 10–20 MB.
- hooks: HTTP hooks run inside Claude Code; no extra process. `SessionStart` runs `wormhole hook` once per session start (about 2 ms).

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
- `PreToolUse` never returns `permissionDecision: "allow"`, since that would skip the user's own permission prompt. Warnings go in `additionalContext`; `deny` is used only for a protected path held by another session.
- `PostToolUse` matches every tool, so messages arrive at the next tool call of any kind and `Read` is seen for change notices.
- The hook endpoint requires a bearer token (`hook-token` next to the socket), because any local user can reach loopback.
- A channel push does not mark a message read: Claude Code drops channel events silently when the channel is not enabled for the session. Only the pull path marks messages read, so with channels enabled a message can appear twice.
- The channel server learns its session from `CLAUDE_CODE_SESSION_ID`. After `/clear` an MCP server keeps the id it was started with, so pushes keep going to the old id until restart.
- `MultiEdit` is not in the current tools reference; the matcher keeps it in case it is used, and `NotebookEdit` paths are read from `file_path` or `notebook_path`.
- Leases are acquired on repo-relative paths after resolving symlinks and `..`; the repository id is the normalised `origin` URL, so checkouts on different machines share leases.

Not built yet: the working-tree watcher and git pre-commit check for edits made through shell commands; file passing, patches, supervision, delegation; event log retention; rate limits; persistence of the daemon's in-memory state (unread notices, files read, lease tokens are lost if the daemon restarts; the hub keeps the log and resumes from the stored cursor).

## Measured

Localhost only: one Apple M5 Pro (macOS, arm64), hub and two daemons on 127.0.0.1 with static identity, release build of commit 073bfc9, rustc 1.100.0, 2026-11-14. Produced by `scripts/bench.sh 300`. Cross-machine numbers (the point of the project) are not yet measured.

| Measurement | p50 | p95 | p99 |
|---|---|---|---|
| `PreToolUse` hook round trip, lease renew through the hub | 0.19 ms | 0.40 ms | 0.42 ms |
| `PreToolUse` hook round trip, conflict warning | 0.18 ms | 0.20 ms | 0.22 ms |
| `PostToolUse` hook round trip, nothing to deliver | 0.10 ms | 0.11 ms | 0.12 ms |
| `SessionStart` through `wormhole hook` (process start included) | 2.03 ms | 2.38 ms | 2.57 ms |
| Message from session A to session B's channel server (send, hub, fan-out, push) | 0.09 ms | 0.13 ms | 0.22 ms |

These exclude Claude Code's own hook overhead and network latency. A `PostToolUse` delivering a backlog returns as many messages as fit in 8,000 characters (32 short ones in the run) and keeps the rest for the next call.

| Idle resource use (60 s, after the run above) | |
|---|---|
| daemon resident memory | 6.0 MB |
| daemon CPU | below 0.02% (no CPU time recorded at the 10 ms resolution of `ps`) |
| hub resident memory | 7.6 MB |
| hub CPU | 0.05% (lease and presence sweep every 500 ms) |
| channel server resident memory | 4.0 MB |

## Security notes

See SECURITY.md for what is covered. Known gaps in this slice: no rate limits on a trusted peer; the event log and session-id bindings are never pruned; messages are size-capped but a trusted peer can still send many; activity summaries are generated by the daemon from paths, never from command text or contents, but the hub trusts the daemon to do so.
