# Design

Status: proposed. Numbers marked "estimate" are not measured; the first slice measures them.

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
| Lease check before an edit | `PreToolUse` HTTP hook asks the daemon | before the edit, roughly 50–200 ms on a private network (estimate) | generally available |
| Push | channel notification | about 1 s while the session is open (estimate) | research preview |
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

## Resource use per developer machine (estimate)

- daemon: one process, about 10–20 MB resident, near 0% CPU when idle.
- channel server: one per session, about 10–20 MB if compiled.
- hooks: HTTP hooks run inside Claude Code; no extra process.

## First slice

1. hub and daemon: presence, messaging, leases with expiry and fencing.
2. Claude Code integration: `SessionStart` context, `PreToolUse` lease check (warn), `PostToolUse` activity and inbox, channel push.
3. A read-only activity page.
4. Acceptance: two machines; measure message latency (push and pull), hook latency, and resource use; show a lease conflict warning and a lease transfer between sessions; show a change notice after another session edits a file the first one read. Results recorded in this file with the date and versions.

Later: file passing, patch proposals, supervision detail levels, work delegation, other agents (Codex, Cursor) through the same daemon.
