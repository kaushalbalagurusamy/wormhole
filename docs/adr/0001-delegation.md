# ADR 0001: Delegation between trusted sessions, with modular permission levels

Status: accepted for slice delegation-v1 (2026-11-15). Source: `docs/requirements/delegation.md`.

## Context

wormhole relays messages between Claude Code sessions on enrolled machines. Today every relayed message is
information only, and wormhole never answers `allow`. The owner wants sessions to hand work to each other inside
contract task boundaries (G1), with the receiving owner choosing locally how much a delegated task may do, up to
a full permission bypass for named trusted senders (R0, R1). Leases must keep the two sessions from colliding
(C4).

Facts checked on 2026-11-15 (code.claude.com/docs/en/hooks, /permissions, /channels-reference; parts of the
hooks page came back summarised, so the wording is not verbatim):

- A `PreToolUse` hook answering `permissionDecision: "allow"` skips the permission prompt, except for actions
  no mode auto-approves and some MCP tools that need user interaction.
- Deny and ask rules in the user's settings are still evaluated when a hook answers `allow`; they win.
- In plan mode a hook's `allow` has no effect on edits or other calls that are not read-only.
- With several hooks, precedence is deny > defer > ask > allow.
- A channel may declare `claude/channel/permission`, and Claude Code then forwards approval prompts to it; the
  first answer from terminal or channel wins.

## Decisions

1. **Capability flag, not a protocol version.** The daemon lists `caps: ["delegation"]` in `Resume` only when it
   has a delegation policy; the hub lists `caps: ["delegation"]` in `Welcome`. Both fields default to empty,
   and serde ignores unknown fields, so old peers read new frames. An old hub drops a connection on a request
   variant it cannot parse, so a daemon never sends a delegation request unless the hub advertised the
   capability. The hub refuses a request to a session whose daemon did not advertise it ("does not accept
   delegated tasks"), so old daemons and daemons without a policy never see one: they behave exactly as today
   (H4).
2. **A request names one session.** No user or broadcast targets. Its events are visible only to the sender's
   and the recipient's machines, and the activity page shows no task text or summary.
3. **The hub keeps the status.** A `delegations` table holds each request's status
   (`pending`, `accepted`, `informed`, `declined`, `expired`, `done`, `failed`, `partial`, `revoked`). An ack is
   idempotent: a second ack returns the stored outcome with `fresh: false`. A pending request expires after
   10 minutes.
4. **Policy is local and composable.** The receiving daemon reads a JSON policy file named by
   `--delegation-policy`. It holds grants (sender, repos, task ids, level, paths, kinds, commands, limits) and a
   denylist module. Nothing in a request can raise a level; the level comes from the grant, and a contract that
   leaves the grant's boundary drops to `inform` (R5). The file is re-read on each request, so an edit needs no
   restart. A policy that cannot be parsed refuses to start the daemon; a later bad edit makes every request
   `inform`.
5. **Levels** (R1): `off`, `inform`, `scoped-instruction`, `scoped-bypass`, `full-bypass`. The matching grant
   with the highest level whose boundary the contract fits applies; an `off` grant that matches wins over all.
   Senders are named exactly (`user` or `user@machine`, never a wildcard).
6. **Bypass is a hook answer, scoped by the contract.** Under `scoped-bypass` the `PreToolUse` hook answers
   `allow` only for an edit tool whose resolved path is inside the contract's paths, not denylisted, not
   protected and not leased by another session, or for a `Bash` command matching one of the contract's command
   patterns with no shell control characters and no denylist match. Under `full-bypass` it answers `allow` for
   any tool call except denylist matches and lease or protected-path conflicts. Everything else gets the
   existing behaviour, so the user's prompt appears. The user's settings deny and ask rules still win. wormhole
   forges no approval and declares no permission relay.
7. **Contracts end.** A contract is open from the receiver's first fresh ack until its result is posted, its TTL
   passes (capped by the grant and at 4 hours), its step budget (bypass answers) is spent, or the kill switch is
   set. A contract is held in daemon memory only, so a daemon restart closes it; a replayed request is never
   reopened (fail closed).
8. **Leases are obtained at acceptance, atomically, by the hub.** The sender's own leases inside the scope are
   released (the hand-off); a lease of the sender's that is broader than the scope, or any lease of a third
   session, overlapping the scope makes the acceptance fail, and the request stays information. Posting the result
   releases the leases the acceptance granted.
9. **Denylist module** (R2): on by default, with default kinds, command patterns and path globs (in the slice
   spec). The owner can set `enabled: false` or replace any list. It refuses a contract whose kind is
   denylisted or whose text or exit condition mentions a denylisted command, and it blocks bypass answers for
   denylisted commands and paths. A policy granting a denylisted kind while the module is on is refused at load.
   **The text screen is a tripwire, not enforcement**: free text can always be reworded. What enforces the
   limits is the scope of the bypass answer (paths, command patterns, metacharacter refusal), the user's own
   deny rules, and the prompt that appears for anything outside the contract.
10. **Audit and kill switch** (R6, R7): every request decision, acceptance, bypass answer, contract close and
    revoke is appended to a JSONL audit log (mode 0600) next to the policy. `wormhole delegation revoke --policy
    FILE` creates `FILE.revoked`; while it exists every request is `inform` and every open contract is closed
    at its next check. `wormhole delegation resume --policy FILE` removes it.
11. **Wrapping stays** (R8, H3): every delegation notice keeps the preamble and a tag naming the sending session.
    The daemon, not the sender, writes the status line and the boundary; the relayed task text comes after
    them and is capped so that cutting the block never removes the limits.
12. **Remote tool approval (R9) is future work.** Claude Code's permission relay would let a remote session
    answer this session's prompts. It does not fit cleanly: the channel server has no authenticated human on
    the other end, only another agent, and the decision would leave the receiving machine. The scoped hook
    answer covers the use case (sf contract tasks) without it. Recorded here; not built.

## Risk beside each level

A trusted node that is compromised, or a trusted agent that relays text it read from an untrusted source
(relayed injection), acts with the receiving session's rights at the levels below.

| Level | What a relayed injection can do | Cost of a compromised trusted sender |
|---|---|---|
| `off` | Nothing; the request is declined unread. | None. |
| `inform` | What any message can do today: the model may follow it, the user's prompts stay. | As today. |
| `scoped-instruction` | The model treats the task as its user's instruction inside the paths and kind. Every tool call still prompts. | The attacker steers work inside the scope; the user sees and approves each action. |
| `scoped-bypass` | Edits inside the contract paths and the listed commands run without a prompt, until the contract ends. | Arbitrary content in the granted paths, and the granted commands run (a test command runs code the attacker can write into the scope: treat `cargo test` on a writable scope as code execution). |
| `full-bypass` | Anything the receiving user can do without a settings deny rule, until the contract ends. | Equivalent to a shell on the receiving machine for the contract's life. Grant only to senders whose machine you would hand your keyboard to. |

## Consequences

- Machines without a policy, old daemons and old hubs behave as before.
- The design statement "wormhole never answers `allow`" becomes "wormhole answers `allow` only under a bypass
  level the receiving owner granted, inside an open contract".
- Shell edits still bypass leases, as before; under bypass a granted command can write anywhere.
