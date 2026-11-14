# Related work

Surveyed 2026-11-13. Grades: A = primary source read (spec, release metadata); B = maintained repository or official docs read; B-pre = preprint abstract or summary read, full text not read; C = repository description or search summary only. Star counts and dates are as of the survey date.

## What Claude Code provides

| Feature | What it does | Why it does not cover this | Grade |
|---|---|---|---|
| [Cross-session messaging](https://code.claude.com/docs/en/cross-session-messaging.md) (`ListAgents`, `SendMessage`) | Messages between sessions, delivered between tool calls; can wake an idle session | Reaches only the same account's sessions; no third-party API. Cross-account messaging is an open request ([anthropics/claude-code#28300](https://github.com/anthropics/claude-code/issues/28300)) | B |
| [Channels](https://code.claude.com/docs/en/channels.md) ([reference](https://code.claude.com/docs/en/channels-reference.md)) | An MCP server pushes events into a running session | A delivery mechanism, not a relay; research preview, launch flag required | B |
| [Hooks](https://code.claude.com/docs/en/hooks.md) | Inject context, deny a tool call with a reason, HTTP hooks | A delivery mechanism; needs a service to ask | B |
| [Agent teams](https://code.claude.com/docs/en/agent-teams.md) | Lead plus teammates, shared task list, mailboxes | One session on one machine; local files | B |

## Open-source tools

| Tool | Summary | Cross-machine | Delivery | Gap for this use | Grade |
|---|---|---|---|---|---|
| [mcp_agent_mail_rust](https://github.com/Dicklesworthstone/mcp_agent_mail_rust) | Identities, threads, file leases with expiry, pre-commit guard, overseer web UI | Not documented | MCP, agents poll their inbox | No delivery at edit time; licence adds a rider restricting certain companies, so it is not standard MIT | B |
| [agent-board](https://github.com/CollinPhipps/agent-board) | Task board, message log, file locks; one host, many clients | Yes | Poll | Single-commit project; no push | B |
| [parallel-agents](https://github.com/Viltrumlik/parallel-agents) | Claims enforced by a `PreToolUse` hook | No (shared filesystem) | Hook | Single machine | B |
| [beads](https://github.com/gastownhall/beads) / [gastown](https://github.com/gastownhall/gastown) | Dependency-aware issue tracker; multi-agent workspace manager | Through sync | CLI | No live presence, file claims or push | B |
| [claude-presence](https://github.com/garniergeorges/claude-presence) | Presence registry, advisory resource locks, broadcast inbox | No | MCP | Single machine | C |
| [claude-relay](https://github.com/gvorwaller/claude-relay) | WebSocket plus MCP between Claude Code instances | Probably | MCP | Not evaluated in depth; no licence file | C |
| [claude-squad](https://github.com/smtg-ai/claude-squad), [ccmanager](https://github.com/kbwo/ccmanager), [vibe-kanban](https://github.com/BloopAI/vibe-kanban) | Run several agents in worktrees | No | Local | One developer, one machine | C |

## Protocols

| Protocol | Status | Relevance | Grade |
|---|---|---|---|
| [A2A](https://github.com/a2aproject/A2A) | v1.0.1, 2026-05-28; Linux Foundation | Agent cards, discovery, task delegation; no shared-workspace, claim or lock concepts found | A (releases), C (scope) |
| [IBM ACP](https://github.com/i-am-bee/acp) | Archived; merged into A2A | None now | B |
| [AGNTCY ACP](https://github.com/agntcy/acp-spec) | Last pushed 2025-05 | Appears dormant | C |
| [ANP](https://github.com/agent-network-protocol/AgentNetworkProtocol) | Active | Decentralised identity and discovery | C |

None of these address coordination in a shared repository.

## Papers

| Paper | Finding used in the design | Grade |
|---|---|---|
| ParallACT, [arXiv 2611.00314](https://www.alphaxiv.org/abs/2611.00314) | Independent agents, no orchestrator, one codebase. On conflicting tasks Claude Code's pass rate fell from 62% to 16%; only 21–23% of messages were read before the recipient's first edit; when agents knew each other's tasks and agreed ownership, conflicts fell from 67% to 18% | B-pre |
| AgentRoom, [arXiv 2608.23740](https://www.alphaxiv.org/abs/2608.23740) | Server-checked claims over a CRDT workspace outperform negotiation in chat; claims are advisory for writes | B-pre |
| CoAgent, [arXiv 2606.15376](https://www.alphaxiv.org/abs/2606.15376) | Two-phase locking and optimistic concurrency control perform poorly for LLM agents; notifying agents whose reads went stale and letting them repair performs better | B-pre |
| Claim Plane, [arXiv 2607.21909](https://www.alphaxiv.org/abs/2607.21909), [2608.00947](https://www.alphaxiv.org/abs/2608.00947) | Pre-write admission of versioned change intents | C |
| Protocol surveys, [arXiv 2505.02279](https://www.alphaxiv.org/abs/2505.02279), [2504.16736](https://www.alphaxiv.org/abs/2504.16736) | MCP, ACP, A2A, ANP compared | C |

## Gaps this project targets

- Messages pushed between different developers' agents, delivered at edit time.
- Lease checks at edit time across machines.
- Change notices to agents whose reads went stale.
- An activity stream other sessions can watch.
- Leases on named areas as well as paths.
