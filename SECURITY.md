# Security

## Reporting

Report a vulnerability privately through GitHub's "Report a vulnerability" form on this repository (Security tab). Do not open a public issue. Include the version or commit, what an attacker needs, and a reproduction if you have one. Expect an acknowledgement within a week.

## Scope

wormhole assumes machines that trust each other on a private network (Tailscale or similar). In scope:

- The hub accepting a connection it cannot identify, or letting one connection act for a session, user or machine it does not own.
- Lease bypass: a stale fencing token accepted, a lease released or granted by a non-holder.
- Text from another session reaching a model without being wrapped, cleaned and length-limited, or able to pass as the local user's instruction.
- File contents, prompts or message bodies leaking into the event log, activity page or hook output beyond what the design states.
- The daemon's loopback HTTP endpoint or Unix socket being usable from a browser or another local user.
- Hooks blocking work when the hub or daemon is down (they must fail open, except a protected path held by another session).

Out of scope: participants who are already trusted acting maliciously within their own permissions, denial of service from a trusted peer, and anything requiring the hub to be exposed to the public internet (unsupported).

## Threat model notes

Covered:

- Identity comes from the network (`tailscale whois` on the peer address), never from the payload. whois runs once for every new connection or HTTP request and is never cached, so a tailnet address reassigned to another node is identified afresh; if whois fails or returns no user and node, the connection is refused (identity fails closed, unlike hooks). Static identity is for tests; the hub refuses it unless bound to loopback and rejects non-loopback peers.
- Relayed text is cleaned before it reaches a model: control characters and all Unicode format (Cf) characters are removed, including the tag block U+E0000 to U+E007F used to smuggle hidden instructions, variation selectors, U+00AD, U+034F and U+180E. U+2028, U+2029 and U+0085 are treated as line breaks. `<`, `>` and `&` are escaped so a body cannot close its wrapper.
- A session id is bound in the hub database to the first peer that registers it, and stays bound after the session ends or times out; another peer cannot re-register it. A timed-out session's leases are released. A message to a session records the recipient's user and machine when it is sent, and only that peer can receive it, before or after the session expires.
- Each hub connection has a bounded outbound queue. A consumer that cannot keep up is disconnected (and resumes from its cursor on reconnect); replay waits at most 2 s for queue space and reaches back at most 100,000 events.
- Every hub route checks that the Host header names the hub (its listen address, or a name given with `--hostname`), against DNS rebinding. The activity page also refuses a foreign `Origin` or a cross-site `Sec-Fetch-Site`, and never shows fencing tokens.
- The daemon's loopback hook endpoint requires `Authorization: Bearer <token>`, compared in constant time. The token is 32 random bytes from `/dev/urandom`, kept in `hook-token` (mode 0600) in the daemon's private directory; `wormhole install` prints it for `.claude/settings.local.json`, which is not committed. The endpoint also rejects any `Origin` header and any `Host` that is not loopback, so other local users and browsers cannot drive it. Headers and token are checked before any of the body is read, and bodies are capped at 32 MiB.
- The daemon's runtime directory is checked with `lstat` before use: it must be a real directory (not a symlink), owned by the effective uid (`geteuid`), with no group or other access. The socket path is never followed if it is a symlink or replaced if it is not a socket. Each Unix socket peer's uid must equal the daemon's effective uid. (The other-uid case is tested as a rule, since tests have no second account.)
- Edit paths are resolved on disk before leases and protected globs are applied: symlinks and `..` are followed, the result must lie under the canonical repository root, and on a case-insensitive filesystem protected globs match regardless of case. A symlink that leads out of the repository is treated as outside it.
- The hub database holds message bodies. It is created with mode 0600 before SQLite opens it (not following a symlink), its `-wal` and `-shm` files are set to 0600, and a failure to set modes is an error. A missing parent directory is created 0700, and a parent directory other users can write to is refused.
- A lease transfer applies the same overlap check as an acquire, in one transaction: it is refused if the recipient would overlap a lease held by a third session.
- Lease TTLs from clients are clamped to 100 ms through 4 hours, and expiry arithmetic saturates within SQLite's i64 range, so a huge or wrapped TTL cannot overflow or create a lease that never expires.
- Length caps are applied to the escaped output, so escaping cannot expand text past the cap. A block larger than the whole context budget is truncated rather than withheld.

Known gaps are listed in docs/design.md under "Security notes".
