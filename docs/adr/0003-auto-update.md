# ADR 0003: Hub-announced target build, daemon self-update

Status: accepted for slice team-log-v1 (2026-11-15). Source: `docs/requirements/team-log.md` (S2, AU1 to AU7).

## Context

The owner wants a wormhole change to reach every teammate's machine without each teammate rebuilding by hand.
Each machine runs one daemon, built from a local clone of this repository by `scripts/join.sh` and run by a
LaunchAgent (macOS, `KeepAlive`) or a systemd user unit (`Restart=always`).

## Decisions

1. **The hub announces, the daemon decides.** The hub operator writes a commit SHA (40 lowercase hex) into a file
   named by `wormhole hub --target-file PATH`; the hub re-reads it about twice a second. It sends the target in
   `Welcome` (`target`) and, when it changes, a `Target` frame, only to connections that advertised the `update`
   capability. An empty, missing or malformed file means no target.
2. **Opt-in per machine.** A daemon updates only when started with `--auto-update SRC` (its own clone). `join.sh`
   passes it by default; `--no-auto-update` leaves it out. Without it the daemon reports `disabled` and does
   nothing else.
3. **Only commits on `main`.** The daemon validates the SHA format, refuses a dirty clone (`git status
   --porcelain` not empty), runs `git fetch origin`, and refuses a commit that is not an ancestor of or equal to
   its clone's `origin/main` (so no branch, fork or arbitrary commit). It then checks the commit out detached,
   runs `cargo build --release --locked`, and checks that the new binary's `wormhole version` names the target.
4. **Swap, keep, restart.** The current binary is copied to `<bin>.prev`, the new one is renamed over `<bin>` (an
   atomic rename on the same filesystem), and the daemon exits with status 75 so its LaunchAgent or systemd unit
   starts the new binary with the same arguments. It swaps only when idle: no tool call between a `PreToolUse` and
   its `PostToolUse` (younger than 10 minutes), no hook in the last few seconds and no open delegation contract.
5. **Failures keep the old binary.** Any refusal or failure leaves the running binary in place and is reported as
   the daemon's update status. Attempts are at most one per 5 minutes.
6. **Rollback.** The operator writes an older SHA that is still on `main`'s history; daemons move to it the same
   way. Locally, `wormhole update --revert` swaps `<bin>.prev` back and sets a hold file (`<bin>.hold`) so the
   daemon stops following the hub until `wormhole update --resume`. A target older than the commit that added
   this updater leaves daemons without an updater: they need `join.sh` again.
7. **Visibility.** Each daemon reports its running commit (built in by `build.rs`), the target and its status to
   the hub (`DaemonStatus`, only when the hub advertised `update`). `wormhole_who` and the activity page list them.
8. **Permission stays local.** The updater never reads or writes the delegation policy file, its kill switch or
   its audit log, and the restarted daemon keeps the arguments its service was installed with. An update cannot
   raise a level or add a grant. A new build can change what the code does with a policy, which is the trust
   concentration below.

## Amendment 1 (2026-11-15): bounded rollback

A security review found that accepting any ancestor of `origin/main` let a misused or compromised hub roll every
machine back to a commit from before a security fix (for example before delegation's amendments). Rollback stays,
bounded:

- The binary carries `MIN_SAFE_COMMIT`, the last security-relevant commit at release time, raised in a later
  release when a security fix lands. A target that is not a descendant of (or equal to) it is refused.
- `--update-floor SHA` raises the minimum on one machine. Both checks always apply, so the local floor can never
  lower the built-in one.
- A target that is not a descendant of the running commit is a downgrade: allowed above the floor, reported as
  `downgrade` in the daemon's status, as a `daemon.downgrade` event on the activity page, and marked `DOWNGRADE`
  in `wormhole_who`.

Trade-off: an operator can still roll machines back, but no further than the newest security floor; a fix that
must stick needs a release that raises `MIN_SAFE_COMMIT` and an update to it. Moving the floor forward is a code
change on `main`, so it carries the same trust as any update. Future hardening, not built: accept only signed
tags or signed commits (checked against keys in local config), so that control of `main` or of the hub alone is
not enough to run code on every machine.

## Trust concentration

Whoever can push to this repository's `main` and whoever controls the hub's target file can run code on every
auto-updating machine, as the user who runs the daemon, within about five minutes. That is the same reach as a
full-bypass grant to everyone at once. Protect `main` (reviews, branch protection), keep the hub's target file
writable only by its operator, and turn auto-update off (`join.sh --no-auto-update`) on any machine whose owner
does not accept that.

## Consequences

- The first update needs a manual `join.sh` re-run on each machine, because daemons built before this ADR have
  no updater.
- A stale clone with local commits or edits refuses to update until its owner cleans it.
