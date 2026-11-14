# Security

## Reporting

Report a vulnerability privately through GitHub's "Report a vulnerability" form on this repository (Security tab). Do not open a public issue. Include the version or commit, what an attacker needs, and a reproduction if you have one. Expect an acknowledgement within a week.

## Scope

wormhole assumes honest, enrolled devices on a private network (Tailscale); see the fault model in docs/design.md. Participants do not lie, but they crash, run buggy builds and relay untrusted text, so the checks below still matter. In scope:

- The hub accepting a connection it cannot identify, or letting one connection act for a session, user or machine it does not own.
- Lease bypass: a stale fencing token accepted, a lease released or granted by a non-holder.
- Text from another session reaching a model without being wrapped, cleaned and length-limited, or able to pass as the local user's instruction.
- File contents, prompts or message bodies leaking into the event log, activity page or hook output beyond what the design states.
- The daemon's loopback HTTP endpoint or Unix socket being usable from a browser or another local user.
- Hooks blocking work when the hub or daemon is down. They must fail open; a protected path is denied only while the hub answers and reports another holder.

Out of scope: an enrolled participant lying on purpose (no Byzantine fault tolerance: false activity, hoarding leases, a dishonest hub), denial of service from an enrolled peer, a compromised device that was admitted to the tailnet, and anything requiring the hub to be exposed to the public internet (unsupported). The same behaviour caused by a bug, such as an agent loop, is in scope.

## Threat model notes

Covered:

- Transport: participants trust each other, the network path is not trusted. The hub serves plaintext only on loopback or a Tailscale address, where WireGuard encrypts the path, and the daemon sends plaintext only to such an address or a `*.ts.net` name. Elsewhere TLS is required: the hub serves `wss://` and `https://` with rustls (no OpenSSL), and the daemon verifies the certificate against the system roots; there is no option to skip verification. A renewed certificate is loaded on SIGHUP. Tests cover a verified round trip and rejection of an untrusted, expired or misnamed certificate.
- Identity comes from the network (`tailscale whois` on the peer address), never from the payload. whois runs once for every new connection or HTTP request and is never cached, so a tailnet address reassigned to another node is identified afresh; if whois fails or returns no user and node, the connection is refused (identity fails closed, unlike hooks). Static identity is for tests; the hub refuses it unless bound to loopback and rejects non-loopback peers.
- Relayed text is cleaned before it reaches a model: control characters and all Unicode format (Cf) characters are removed, including the tag block U+E0000 to U+E007F used to smuggle hidden instructions, variation selectors, U+00AD, U+034F and U+180E. U+2028, U+2029 and U+0085 are treated as line breaks. `<`, `>` and `&` are escaped so a body cannot close its wrapper. The hub refuses a session id, repo, path, user or scope containing any of these characters, so a single-line name cannot break into forged lines. The daemon also folds every name it shows a model to one line, so a name stored before this check, or sent by an older hub without it, cannot either; only a message body keeps its line breaks.
- A session id is bound in the hub database to the first peer that registers it, and stays bound after the session ends or times out; another peer cannot re-register it. A timed-out session's leases are released. A message to a session records the recipient's user and machine when it is sent, and only that peer can receive it, before or after the session expires.
- Each hub connection has a bounded outbound queue. A consumer that cannot keep up is disconnected (and resumes from its cursor on reconnect); replay waits at most 2 s for queue space and reaches back at most 100,000 events.
- Every hub route checks that the Host header names the hub (its listen address, or a name given with `--hostname`), against DNS rebinding. The activity page also refuses a foreign `Origin` or a cross-site `Sec-Fetch-Site`, and never shows fencing tokens.
- The daemon's loopback hook endpoint requires `Authorization: Bearer <token>`, compared in constant time. The token is 32 random bytes from `/dev/urandom`, kept in `hook-token` (mode 0600) in the daemon's private directory; `wormhole install` prints it for `.claude/settings.local.json`, which is not committed. The endpoint also rejects any `Origin` header and any `Host` that is not loopback, so other local users and browsers cannot drive it. Headers and token are checked before any of the body is read. No body size is refused with 413 (which Claude Code would treat as a non-blocking error, letting the edit skip the check): the body is reduced while it streams in, keeping only strings up to 4 KiB, so the path is recovered and the normal deny or warning applies to edits of any size. A body that cannot be parsed, is still over 1 MiB once reduced, or exceeds 1 GiB is answered with a PreToolUse deny that says why.
- The daemon's runtime directory is checked with `lstat` before use: it must be a real directory (not a symlink), owned by the effective uid (`geteuid`), with no group or other access. The socket path is never followed if it is a symlink or replaced if it is not a socket. Each Unix socket peer's uid must equal the daemon's effective uid. (The other-uid case is tested as a rule, since tests have no second account.)
- Edit paths are resolved on disk before leases and protected globs are applied: symlinks and `..` are followed, the result must lie under the canonical repository root, and on a case-insensitive filesystem protected globs match regardless of case. A symlink that leads out of the repository is treated as outside it.
- The hub database holds message bodies. It is created with mode 0600 before SQLite opens it (not following a symlink), its `-wal` and `-shm` files are set to 0600, and a failure to set modes is an error. A missing parent directory is created 0700, and a parent directory other users can write to is refused.
- A lease transfer applies the same overlap check as an acquire, in one transaction: it is refused if the recipient would overlap a lease held by a third session. The grantor's own leases inside the transferred scope are released with it, each with a `lease.released` event; if the grantor also holds a broader lease that overlaps the scope, the transfer is refused and the grantor is told to narrow or release that lease first, so no lease is dropped silently. Containment is conservative: a plain scope names a file and a directory scope ends with `/`; a glob covers a directory scope only if it is recursive (`**` or `<dirs>/**`, never `a**`) over it, so a directory lease is never released by a narrower glob.
- Lease TTLs from clients are clamped to 100 ms through 4 hours, and expiry arithmetic saturates within SQLite's i64 range, so a huge or wrapped TTL cannot overflow or create a lease that never expires.
- Length caps are applied to the escaped output, so escaping cannot expand text past the cap. A block larger than the whole context budget is truncated rather than withheld.

Not covered (accepted for this slice; details in docs/design.md under "Security notes"):

- Processes running as the same user, including the agent's own shell, can read the hook token and use the daemon socket.
- While the daemon is down, another local user could listen on the fixed hook port and receive hook requests.
- Text relayed by a trusted agent may carry instructions it read elsewhere. It is wrapped, cleaned and labelled as data, and the user's permission prompts stay in force, but the receiving model can still follow it.
- Edits through shell commands are not checked against leases or protected paths.
- No rate limits, and no pruning of the hub's log.
