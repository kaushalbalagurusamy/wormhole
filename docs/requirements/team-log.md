# Team log, team policy and auto-update: source requirements

The owner's words, verbatim, are the source of truth. Each numbered line is one requirement; the ledger
(`delegation-ledger.tsv`) has one row per line. The detail lines were briefed with the owner's approval on
2026-11-15. Where a line here conflicts with `delegation.md`, this file wins for the lines it names.

## Source (verbatim, the owner, 2026-11-15)

- S1. "wormhole looks like we need to escalate it to the full permissioning version that i was talking about earlier where agents can request reviews, send each other tasks etc. we are already doing that through issues so there is zero reason that we need to pollute git issues and wait too long to check them which slows the team down, goes down useless paths etc. check if we can enable this full permissioning mode for the agents to work in a true swarm, also all messages should be available to all agents through the log, just the directed agent takes the instruction"
- S2. "the wormhole update i specified should also make sure it updates on everyone's devices right"

## Detail for S1 (approved 2026-11-15)

- TL1. Shared team log: every `msg`, delegation `request`, `ack` and `result` in a repo, with its full text, is readable by every session in that repo. Supersedes ADR 0001 decision 2, recorded as an ADR amendment stating the trade-off.
- TL2. An MCP tool `wormhole_log` with filters for since, session or user, kind and task id, and a cap; a daemon socket call behind it; the hub serves the log to any session in the same repo.
- TL3. The activity page may show the text to tailnet viewers; decide and record the decision.
- TL4. A message is addressed to a session, a user or all. Only the target treats it as an instruction, and only within its own local policy; everyone else receives it wrapped as information ("for session X, not for you").
- TL5. The existing inbound wrapping stays; the "addressed to you / not to you" line is part of the trusted header the daemon writes, not the relayed text.
- TL6. Retention: the log is bounded by a configurable count or age, documented.
- TL7. Team policy preset `docs/examples/team-policy.json`: each named teammate login gets `full-bypass` on one named repo, denylist module on, empty safe-program list. What `full-bypass` means is documented plainly.
- TL8. `scripts/join.sh --delegation-policy PATH` installs the daemon with that policy in one step. A policy can never be pushed to another machine; this stays so and is said.
- TL9. Contract kinds `review` (findings with severity, file:line and verdict) and `task` (status, summary, artifacts) with result schemas.
- TL10. `wormhole_delegate` takes an optional short `ref` (an issue or PR URL).
- TL11. README and `docs/design.md` carry a short "Which channel" note: wormhole for live agent-to-agent tasks, reviews and status, its log the shared record; GitHub for human-facing specs, PRs and decisions.
- TL12. Policy comes only from local config; no remote approval of another machine's tool calls.
- TL13. Backward compatible: old daemons and hubs keep working; log access is gated behind a new capability (`team-log`).

## Detail for S2 (approved 2026-11-15)

- AU1. The hub announces a target build (an exact commit SHA on the wormhole repository's `main`), set by its operator locally, in `Welcome` and on change, behind a capability flag.
- AU2. The daemon updates itself only when local config allows it (`--auto-update`; `join.sh` turns it on by default, `--no-auto-update` turns it off): fetch its own source clone, refuse a target that is not an ancestor of or equal to `origin/main`, check out the SHA detached, `cargo build --release --locked`, swap the binary atomically keeping the previous one, restart through its LaunchAgent or systemd unit.
- AU3. A failed build keeps the old binary running and is reported in presence or activity; attempts are rate-limited; never update mid-tool-call; a dirty clone is refused and reported.
- AU4. Rollback: the operator sets an older SHA on `main`'s history and every daemon moves to it; `wormhole update --revert` swaps back to the previous binary locally.
- AU5. An update never touches the local delegation policy file or its level; stated in ADR and docs, and tested.
- AU6. `wormhole_who` and the activity page show each daemon's running commit, its target and its update status.
- AU7. The trust concentration is documented plainly: whoever controls the repository's `main` and the hub's target can run code on every auto-updating machine.
