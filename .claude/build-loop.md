# Build-loop profile: wormhole

Read by the `/sf` build loop before any implementation work in this repository.

| Item | Where |
|---|---|
| Source requirements (verbatim) | `docs/requirements/delegation.md` |
| Requirements ledger | `docs/requirements/delegation-ledger.tsv` (one row per source line: `satisfied`, `partial`, `blocked`, `unserved`, with the artifact or the dependency) |
| ADRs | `docs/adr/` (numbered from 0001) |
| Slices | `docs/slices/<id>/` (spec, research brief, review notes) |
| Tests | `tests/` (black-box, through `tests/common`) and in-crate `#[cfg(test)]` |
| Test command | `cargo test --locked` with the toolchain below |
| Lint | `cargo fmt --check` and `cargo clippy --locked --all-targets -- -D warnings` (as in `.github/workflows/ci.yml`) |
| Reviewer | a fresh adversarial agent, told to hunt passes earned the wrong way and security holes |
| Backlog and inbound | GitHub issues on this repository; the requirements file above |

## Stage separation

- A test author writes the tests first, from the slice spec.
- A blind implementer never reads the test files named as protected in the slice spec.
- A separate agent runs the tests and reports counts.
- A fresh reviewer reads the code, not the comments.

## Toolchain

A current stable Rust toolchain. Where cargo is not on PATH (a shared machine), set `RUSTUP_HOME`,
`CARGO_HOME`, `TMPDIR` and `PATH` as that machine's local notes say; keep those paths out of this file.

## Hygiene

- The machine is shared: one cargo build or test at a time (wait until `pgrep -x cargo` is empty), at most two
  implementation agents at once. Use the repository's own `target/`.
- Never run the binary against the live setup: no `~/.wormhole/`, no default socket, no port 7421, no
  `launchctl`. Tests bind port 0 and use temporary directories.
- Public repository: no teammates' names, emails or logins, hub addresses, tailnet names or tokens. Use
  placeholders such as `alice@example.com` and `hub.your-tailnet.ts.net`.
