# wormhole

A live connection between coding-agent sessions running on different machines that share one repository.

Several developers, each with their own agent sessions (Claude Code first), work in the same repo. Today those agents cannot see each other: two of them can build the same feature in parallel, edit the same file, or act on state that changed minutes ago. wormhole gives every session on a trusted network a shared, live view: who is working on what, leases on files and areas, messages between agents, file and patch passing, and a stream of each session's activity that others can watch.

## Status

Design only. Nothing is built yet. See [docs/design.md](docs/design.md) for the protocol and the first slice, and [docs/related-work.md](docs/related-work.md) for what exists and why it was not adopted.

## Scope

- Machines that fully trust each other, connected over a private network (Tailscale or similar).
- One hub process on one machine; one small daemon per developer machine.
- Delivery into Claude Code through hooks (generally available) and, optionally, channels (research preview).

## Not in scope

- Untrusted participants or public networks.
- Replacing git, pull requests or code review.
- Routing between different users' Claude accounts through Anthropic's services; wormhole runs its own relay.

## License

Apache-2.0. See [LICENSE](LICENSE).
