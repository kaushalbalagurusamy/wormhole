# wormhole

A live connection between coding-agent sessions running on different machines that share one repository.

Several developers, each with their own agent sessions (Claude Code first), work in the same repo. Today those agents cannot see each other: two of them can build the same feature in parallel, edit the same file, or act on state that changed minutes ago. wormhole gives every session on a trusted network a shared, live view: who is working on what, leases on files and areas, messages between agents, file and patch passing, and a stream of each session's activity that others can watch.

## Status

First slice built: hub, daemon, Claude Code hooks, channel MCP server, activity page. Tested on one machine over localhost; not yet run across machines. See [docs/design.md](docs/design.md) for the protocol, the measured numbers and what is left, [docs/related-work.md](docs/related-work.md) for what exists, and [SECURITY.md](SECURITY.md) for reporting and the threat model.

## Use

Build with a current stable Rust toolchain:

    cargo build --release --locked
    export PATH="$PWD/target/release:$PATH"

On the hub machine, listen on its Tailscale address only. Every connection is identified with `tailscale whois`; unidentified peers are refused, and with `--allow` only the named users (or `tag:` names) are accepted.

    mkdir -m 700 -p ~/.wormhole
    wormhole hub --listen 100.64.0.1:7420 --hostname hub.your-tailnet.ts.net --db ~/.wormhole/hub.sqlite \
        --allow alice@example.com --allow bob@example.com

On each developer machine, run one daemon. It serves hooks on 127.0.0.1:7421 and a socket in `~/.wormhole/` (mode 0700).

    wormhole daemon --hub ws://hub.your-tailnet.ts.net:7420/ws --protected 'secrets/**'

In each project, print the Claude Code configuration and merge it by hand; nothing is written for you:

    wormhole install --project .

The printed settings contain this machine's hook token: put them in `.claude/settings.local.json` and `chmod 600` it.

Then start Claude Code as usual. Every session gets "who is working on what" at start, a warning when it edits a file another session holds (today that warning reaches the model just after the edit; see docs/design.md), and messages and "changed since you read it" notices after each tool call. To also receive messages pushed between tool calls (channels, a research preview):

    claude --dangerously-load-development-channels server:wormhole

Channels need a claude.ai account or a Console API key, are not available on Bedrock, Google Cloud or Foundry, and on Team and Enterprise plans an admin must enable them.

The activity page is at `http://hub.your-tailnet.ts.net:7420/` from any machine on the tailnet.

For a single machine without Tailscale, run the hub with `--identity static` on 127.0.0.1 and pass `--static-identity you@this-machine` to the daemon. Static identity is refused on any other address, and a browser cannot open the activity page in this mode because it cannot send the identity header.

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
