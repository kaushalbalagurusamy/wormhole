# ADR 0004: Name shared-in devices after their tailnet address

Status: accepted (2026-11-17), at the owner's request ("Wormhole update should go live tonight").

## Context

The hub names each connection's machine from `tailscale whois` on the connection's own address
(`src/hub/identity.rs`). For a device shared in from another tailnet, Tailscale hides the real name: whois returns an
empty `Name` and the `ComputedName` `device-of-shared-to-user`. On the team hub (2026-11-17), every teammate except
the hub's owner connects that way, so `wormhole_who`, the team log and leases showed all their machines as one name.
A daemon could report its own name, but that would be a claim the hub can't check; identity must come only from
Tailscale.

## Decisions

1. **A shared-in device is named `shared-<address>`.** When whois returns `device-of-shared-to-user`, the hub
   names the machine after the tailnet address it read from the connection, with `.` and `:` replaced by `-`. An
   example is `shared-100-113-6-5`. The address comes from the socket, not the peer, so the name is as trustworthy
   as whois. It is stable for as long as Tailscale keeps the device's address. Named devices are unchanged.
2. **Sessions bound to the placeholder move once.** A session id is bound to its first owner for good
   (`session_owners`). A session first bound to `user@device-of-shared-to-user` is rebound once to the same user's
   new `shared-...` name, on its first hello after the upgrade. It is never rebound to another user, and never again
   after that. Without this, every long-running session of a sharer would be refused as "belongs to another machine".

## Consequences

- `wormhole_who`, the team log, leases and delegation records tell each teammate's machines apart.
- If Tailscale reassigns a device's address, that device gets a new name; its existing sessions are refused and must
  restart. That is the same behaviour as renaming a named device.
- The one-time move trusts the user, not the machine. Before this change all of a user's shared devices already
  looked alike, so this grants no access that wasn't already there.
- Delegation policies match on users, not machines, so no policy changes.
