# Delegation: source requirements

The owner's words, verbatim, are the source of truth. Each numbered line is one requirement; the ledger
(`delegation-ledger.tsv`) has one row per line. Context lines were approved by the owner for the design. Where
the revision (R lines) conflicts with an earlier line, the revision wins; the superseded lines are kept and
marked so the history stays legible.

## Goal (verbatim, the owner, 2026-11-15)

- G1. "The goal of this new mode is wherever contract task boundaries are created for back and forth collaboration without collision the sessions can hands off prompt each other since they're trust machines and trusted task scope."

## Approved design context (2026-11-15)

- C1. Who sets the policy: the receiving session's owner sets it, locally, never the sender: which senders, which repos and task scopes, and which kinds of task. It is default off.
- C2. Message kinds: build the `request`/`result` kinds that `docs/design.md` lists as planned ("task text, status, output summary | delegating work").
- C3. Task boundary: a request is accepted as an instruction only inside a contract task boundary: an explicit scope, for example a set of paths or leases, an issue or task ID and an allowed kind of work. Inside that boundary the receiving agent may treat the request as its user's instruction. Outside it, the message stays information, as today.
- C4. Leases tie delegation to non-collision. A handed-off task should carry or obtain the leases for its scope, so the two sessions don't edit the same paths.
- C5. Status: the receiver acknowledges, works, and posts a `result` (status and summary). Requests and results are visible, for example in `wormhole_who` or an MCP tool.

## Hard limits as first briefed (2026-11-15; H1 and H2 superseded by R1 to R8)

- H1. (superseded by R1, R3, R4) Permission prompts stay with each machine. Never add remote approval of another machine's tool calls; wormhole never answers `allow`. The receiver's own permission prompts remain in force.
- H2. (superseded by R5) Destructive and outward-facing work can't be delegated: force-push, deleting branches or data, deploys, merging PRs, publishing, sending messages outside wormhole, reading or sending secrets. A denylist in the policy that the owner can't switch off by accident.
- H3. Relayed injection is a stated threat. A trusted agent can relay text it read from an untrusted source. Keep scopes narrow, keep the sender allowlist explicit, and keep the inbound wrapping on every message.
- H4. Backward compatibility: hubs and daemons on the current version keep working. A machine without the new policy behaves exactly as today. Version or capability-flag the new message kinds.

## Revision (verbatim, the owner, 2026-11-15)

- R0. "Permission scoping should be configurable and modular and independent for us to determine as needed. We don't want to gut the possibility of a full bypass permissions between trust machines, teammates and sf scoped tasks that define clear contracts, exit conditions, spec, etc."

## Revision detail (approved with R0)

- R1. Permissions are independent policy modules the receiving owner composes in local config, per sender, per repo and per task scope, as levels from lowest to highest: `off` (default); `inform` (today's behaviour, information only); `scoped-instruction` (inside a contract boundary, treated as the user's instruction; local prompts still apply); `scoped-bypass` (inside the boundary the receiver may run the delegated work without local prompts, mapped onto Claude Code's own permission hooks, not by forging approvals); `full-bypass` for named trusted senders (no scope limit). Each level is independent, opt-in and configurable without a code change.
- R2. The destructive-action denylist is a module: on by default, and the owner can switch it off or edit it in local config. Defaults are the H2 list. Every module and its risk is documented.
- R3. sf-scoped contract tasks are the main use for bypass. A request can carry a task contract: spec or slice reference, allowed paths and leases, allowed commands, exit conditions (what done means, plus a time or step limit) and a result schema.
- R4. Bypass levels apply only while the contract is open. The contract ends on its exit condition, its TTL or a local kill switch, and the level drops back.
- R5. Policy is set only from local config on the receiving machine, never from a message; a request can never raise its own level.
- R6. Every accepted request and every action taken under bypass is written to a local audit log.
- R7. One local command revokes everything at once (the kill switch).
- R8. Inbound wrapping stays, so the agent always knows the text came from another session.
- R9. Remote tool approval (the channel permission relay): an optional module, off by default, if it fits cleanly; otherwise recorded in the ADR as future work. Not blocking.
- R10. `docs/design.md` "Trust and safety" and the ADR match; the threat of a relayed injection and the cost of compromising a trusted node are stated beside each bypass level.
- R11. Process: tests first, blind implementer, separate runner, adversarial review, a public-repo hygiene pass, branch-only work, no touching the running hub.
