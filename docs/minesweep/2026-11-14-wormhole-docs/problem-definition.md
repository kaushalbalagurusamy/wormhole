# Problem definition: wormhole first slice (minesweep 2026-11-14)

Brief: README.md, docs/design.md and SECURITY.md at commit b94bfbb (`brief.md`). Register: `register.json`, `register.md`. All lenses are uncalibrated, so findings are leads, acted on with evidence.

## Scope set by the owner

Trusted devices on a private Tailscale tailnet and their Claude Code sessions. Untrusted participants, the public internet, multi-tenant use and other agents (Codex, Cursor) are out of scope and produced no findings. The business and theory lens groups were not swept for the same reason.

## Objective kept

Let agent sessions on different machines see who is working on what, warn before conflicting edits, pass messages and change notices, and fail open when coordination is unavailable.

## Invariants the findings imply

- A message to a session is delivered at least once while it is within the hub's replay window, across daemon restarts and a hub log that went back (F-003, F-004).
- A lease scope covers exactly what it names: a file, a directory (ending in `/`), a recursive glob, or a named area; a transfer never drops a lease silently (F-006).
- Text from another session is data: wrapped, cleaned, length-limited, and never able to approve a tool call (F-010).
- Hooks fail open; a protected path is enforced only while the hub answers, and never for shell edits (F-007).
- The channel server negotiates an MCP revision on which Claude Code registers channels (F-002).

## Triage

Fix now (done, test-first; commits on main):

| Finding | Fix | Commits |
|---|---|---|
| F-002 channel server negotiated MCP 2026-07-28, so channels never registered | answer with 2025-06-18 or an older supported revision | 3e7b274, e7b1acb |
| F-003 daemon restart lost undelivered messages | ack only up to the oldest undelivered message; replayed read receipts drop delivered ones | b5387bc, 0ee3bf4, dc11ba5 |
| F-004 hub log reset made daemons ignore new events | follow a hub head behind the cursor | b5387bc, dc11ba5 |
| F-006 directory and glob leases, transfer and fencing gaps | directory scopes, expiry notices, lapsed-token notice, covered sub-leases released with events, broader grantor lease refuses the transfer, exact containment | f7cafe3, c8f59c6, 66ab03c, 08b10ff, b175792, cf9ab0e, 88a15be |
| F-005 repo ids split on case | lowercase ids; `git config wormhole.repoId` override | e9f2dc6, 92bb48f |
| F-008 any identified node accepted | `wormhole hub --allow` user or tag allowlist | e9f2dc6, 92bb48f |
| F-009 hook token readable by other local users | install and README say to `chmod 600` the settings file | e9f2dc6, 92bb48f |
| F-011 duplicate delivery could double an action | channel instructions: same seq, act once | 6ed3ff7, 92bb48f |
| F-015 SessionStart cut off the lease list | this repo's leases first, then its sessions, then a count | e9f2dc6, 92bb48f |
| Docs claims the code did not support (quarantine) | design, README and SECURITY corrected | b97c574 |

Document (recorded in docs/design.md "Security notes" or SECURITY.md "Not covered"; no code change in this pass):

| Finding | Why not fixed now |
|---|---|
| F-001 warning lands after the edit | the policy is the owner's decision; the reviewer's recommendation is recorded |
| F-007 protected paths bypassed by shell edits and outages | the working-tree watcher is a later slice; wording now matches behaviour |
| F-009 (rest) port takeover while the daemon is down | needs a command-hook transport choice from the owner |
| F-010 relayed injection from a trusted agent | wrapping is advisory by nature; permission prompts stay in force |
| F-012 no rate limits or pruning | bounded at the receiver; pruning is safe now that daemons follow a reset log |
| F-013 cross-machine latency unmeasured | needs a second machine (`scripts/bench.sh` across the tailnet, direct and DERP) |
| F-014 replay blocks requests after an outage | fails open with a stale note; restructuring the connection loop is a later change |
| F-017 channel availability by plan and provider | stated in README and design |
| F-020 retention | stated as not built |

Out of scope or dismissed:

| Finding | Reason |
|---|---|
| F-025 peer patches installing dependencies | patch passing is not built; its design must add a confirmation rule |
| F-016, F-018, F-019, F-021 to F-024 | dismissed with evidence in the register (hook semantics stated correctly, licences permissive, lockfile pinned, WebSocket refuses Origin, block caps, single-writer store, plain-text page) |

## Open questions for the owner

1. F-001: which pre-edit policy (deny once per session, path and holder token; warn on Read; both; ask; or keep warn-only)?
2. F-009: switch hooks to the command transport over the uid-checked socket (about 2 ms per hook instead of 0.1 ms), to remove the hook port and token?
3. F-013: a second tailnet machine for the cross-machine benchmark.

## Brief lines not followed as written

See `quarantine` in register.json: "warning before editing" (L36), "at least once" (L97), "rejects writes that carry a stale token" (L111), "no event is lost" (L138), "watches the working tree" (L139), "permission relay is off by default" (L131). Each has a replacement statement, and the docs now say the replacement.
