# ADR 0002: Shared team log (amends ADR 0001 decision 2)

Status: accepted for slice team-log-v1 (2026-11-15). Source: `docs/requirements/team-log.md` (S1, TL1 to TL13).

## Context

ADR 0001 decision 2 kept a delegation between two machines: its events reached only the sender's and the
receiver's machines, a request named one session, and the activity page showed no task text or summary. Messages
were routed the same way: a `msg` reached only the machines it was addressed to. The owner now wants every agent
in a repository to be able to read all coordination in that repository ("all messages should be available to all
agents through the log, just the directed agent takes the instruction"), so teams stop using GitHub issues as a
slow message bus.

## Decisions

1. **A team log beside the event log.** The hub keeps a `team_log` table (seq, ts, repo, kind, sender, target,
   task id, text and the event's data). Every `msg`, `delegation.request`, fresh `delegation.ack` and
   `delegation.result` is written to it with its full text, under the repository of the authoring session as the
   hub knows it. A message sent from a session with no repository is not logged. Rows are written only when the
   authoring connection's daemon advertised the `team-log` capability, so an old daemon's messages keep the
   privacy they were sent under, and nothing sent before the upgrade is ever exposed (it was never written).
2. **Pull, not push.** Any session reads its own repository's log with the `wormhole_log` tool (daemon socket
   tool `log`, hub request `Log`). The hub takes the repository from its own record of the asking session, never
   from the request. Live delivery is unchanged: a message is still pushed only to the machines it is addressed
   to, and a delegation request only to the target machine. Push to non-targets was considered and not built: it
   would put foreign instructions into every session's context and needs per-connection gating, phantom-session
   and read-receipt changes for little gain.
3. **Only the target acts, enforced in three places.** (a) The hub still delivers `delegation.request` events
   only to the target machine, so only the target daemon evaluates its local policy and can open a contract. (b)
   Log entries come back as the answer to a socket call and never pass through the daemon's event path, so a
   log entry can never open a contract, answer `allow` or enter an inbox. (c) The daemon writes each log entry's
   addressing as tag attributes (`to`, `for_you`) and as the first line of the block, derived from hub-stamped
   fields and the asking session's own id and user: "Addressed to this session", or "For session X, not for you:
   information only". Relayed text follows, every line quoted with `> `, so no relayed line can pass for a daemon
   line. A log copy of a delegation request addressed to the session says it grants nothing; the delegation
   notice remains the only grant. Pushed message notices gain the same `to` and `for_you` attributes.
4. **Delegation targets stay single-session.** Acknowledgement and the lease hand-off are atomic per session;
   user and broadcast delegation are not built.
5. **The repository filter is scoping, not access control.** A session's repository is what its daemon reports in
   `Hello`, so any enrolled machine can read any repository's log by claiming it. The access boundary is the
   hub's identity allowlist (`--allow` and the tailnet), as for everything else on the hub.
6. **The activity page stays redacted.** It shows who wrote to whom and sizes, never message bodies or delegation
   text. Page viewers are not scoped to a repository, a browser page is easier to leak (screen sharing,
   shoulder-surfing, history) than a tool answer, and agents, who need the text, get it from `wormhole_log`.
7. **Retention.** The team log keeps at most `--log-max-entries` rows (default 10,000; at least 1) and drops
   rows older than `--log-max-age-days` (default 30; 0 means no age limit). The event log used for replay is not
   pruned by this; its growth is unchanged from before this ADR.
8. **Capability.** The hub lists `team-log` in `Welcome`; a daemon lists `team-log` in `Resume`. A daemon sends
   `Log` only on a connection whose `Welcome` listed it (an old hub drops a connection on a request it cannot
   parse), and its `wormhole_log` tool otherwise fails with "does not support the team log".

## Trade-off

Decision 2 of ADR 0001 bought privacy between two machines; this gives it up inside a repository. Every
enrolled teammate's agent can now read every message and every delegated task's text, contract, answer and
result in a repository it claims. Text an agent relays from an untrusted source now reaches every agent that
reads the log, not one: a relayed injection travels further. What limits it: the log is pulled, not pushed;
each entry is wrapped as information with daemon-written addressing; only the addressee is told it may act, and
then only within its own user's instructions and local delegation policy; and no log entry can grant a
permission. Anything an agent must keep from teammates does not belong in wormhole.

## Consequences

- ADR 0001 decision 2 now reads: a request names one session; its live events reach only the two machines; its
  text is in the repository's team log; the page still shows no text.
- Old hubs and old daemons behave as before; mixed teams log only what new daemons author.
