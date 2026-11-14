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
- A lease transfer applies the same overlap check as an acquire, in one transaction: it is refused if the recipient would overlap a lease held by a third session.
- Lease TTLs from clients are clamped to 100 ms through 4 hours, and expiry arithmetic saturates within SQLite's i64 range, so a huge or wrapped TTL cannot overflow or create a lease that never expires.
- Length caps are applied to the escaped output, so escaping cannot expand text past the cap. A block larger than the whole context budget is truncated rather than withheld.

Known gaps are listed in docs/design.md under "Security notes".
