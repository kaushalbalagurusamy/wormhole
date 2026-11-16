# wormhole

A live connection between coding-agent sessions running on different machines that share one repository.

Several developers, each with their own agent sessions (Claude Code first), work in the same repo. Today those agents cannot see each other: two of them can build the same feature in parallel, edit the same file, or act on state that changed minutes ago. wormhole gives every session on a trusted network a shared, live view: who is working on what, leases on files and areas, messages between agents, file and patch passing, and a stream of each session's activity that others can watch.

## Status

First slice built: hub, daemon, Claude Code hooks, channel MCP server, activity page. Tested on one machine over localhost; not yet run across machines. See [docs/design.md](docs/design.md) for the protocol, the measured numbers and what is left, [docs/related-work.md](docs/related-work.md) for what exists, and [SECURITY.md](SECURITY.md) for reporting and the threat model.

## Use

Build with a current stable Rust toolchain:

    cargo build --release --locked
    export PATH="$PWD/target/release:$PATH"

On the hub machine, listen on its Tailscale address only. Every connection is identified with `tailscale whois`; unidentified peers are refused, and with `--allow` only the named tailnet logins (or `tag:` names) are accepted.

    mkdir -m 700 -p ~/.wormhole
    wormhole hub --listen 100.64.0.1:7420 --hostname hub.your-tailnet.ts.net --db ~/.wormhole/hub.sqlite \
        --allow alice@example.com --allow bob@example.com

WireGuard already encrypts tailnet traffic. To also encrypt the daemon-to-hub link end to end (for example when a subnet router or exit node is on the path), serve TLS with a certificate from Tailscale (HTTPS certificates must be enabled for the tailnet):

    tailscale cert --cert-file ~/.wormhole/hub.crt --key-file ~/.wormhole/hub.key hub.your-tailnet.ts.net
    wormhole hub --listen 100.64.0.1:7420 --hostname hub.your-tailnet.ts.net --db ~/.wormhole/hub.sqlite \
        --tls-cert ~/.wormhole/hub.crt --tls-key ~/.wormhole/hub.key --allow alice@example.com

Tailscale certificates last 90 days: run the same `tailscale cert` command before they expire (from cron or a timer) and send the hub `SIGHUP` to load the new files without a restart. The hub refuses plaintext on any address other than loopback or a Tailscale address.

To join an existing hub from a developer machine in one step (macOS or Linux), run from a clone of this repo:

    scripts/join.sh hub.your-tailnet.ts.net:7420 ~/code/your-repo --protected 'secrets/**'

It checks the hub answers, builds and installs the binary, runs the daemon as a LaunchAgent or a systemd user unit, merges the hooks into the repo's `.claude/settings.local.json` (mode 0600) and registers the MCP server for that checkout. It is safe to re-run. The manual steps follow.

On each developer machine, run one daemon. It serves hooks on 127.0.0.1:7421 and a socket in `~/.wormhole/` (mode 0700).

    wormhole daemon --hub ws://hub.your-tailnet.ts.net:7420/ws --protected 'secrets/**'

With TLS on the hub, use `wss://hub.your-tailnet.ts.net:7420/ws`; the certificate is checked against the system roots. The daemon refuses `ws://` to anything other than loopback, a Tailscale address or a `*.ts.net` name.

In each project, print the Claude Code configuration and merge it by hand; nothing is written for you:

    wormhole install --project .

The printed settings contain this machine's hook token: put them in `.claude/settings.local.json` and `chmod 600` it.

Then start Claude Code as usual. Every session gets "who is working on what" at start, a warning when it edits a file another session holds (today that warning reaches the model just after the edit; see docs/design.md), and messages and "changed since you read it" notices after each tool call. To also receive messages pushed between tool calls (channels, a research preview):

    claude --dangerously-load-development-channels server:wormhole

Channels need a claude.ai account or a Console API key, are not available on Bedrock, Google Cloud or Foundry, and on Team and Enterprise plans an admin must enable them.

The activity page is at `http://hub.your-tailnet.ts.net:7420/` (or `https://` with TLS) from any machine on the tailnet.

For a single machine without Tailscale, run the hub with `--identity static` on 127.0.0.1 and pass `--static-identity you@this-machine` to the daemon. Static identity is refused on any other address, and a browser cannot open the activity page in this mode because it cannot send the identity header.

## Delegation

A session can hand another session a task inside a contract (paths, exact command patterns, an exit condition) with `wormhole_delegate`; the receiver posts the outcome with `wormhole_result`. The receiving owner decides, locally, how much a sender may do. Without a policy file the daemon never receives delegated tasks, and nothing changes from before.

    wormhole daemon --hub ws://hub.your-tailnet.ts.net:7420/ws --delegation-policy ~/.wormhole/delegation.json

A policy names senders exactly and gives each a level: `off`, `inform` (information only, as any message), `scoped-instruction` (the task is treated as your instruction inside its paths; every prompt stays), `scoped-bypass` (edits inside the paths and the listed exact command patterns run without a prompt until the contract ends) or `full-bypass` (anything except the denylist). The file is re-read on every request.

    {
      "grants": [
        {
          "from": ["alice@example.com"],
          "repos": ["github.com/owner/repo"],
          "level": "scoped-bypass",
          "paths": ["src/**"],
          "kinds": ["tests", "fix"],
          "commands": ["cargo test"],
          "max_ttl_secs": 3600,
          "max_steps": 200
        }
      ]
    }

A command in a contract runs without a prompt only if it matches a contract pattern word for word, its program is one you listed in `"safe_programs"`, and every operand is a path inside the repository. Bash at `scoped-bypass` is off until you list programs. `DEFAULT_SAFE_PROGRAMS` is empty, because every program people reach for has some mode that reads or runs more than its operands name (a recursive search, a file of names, an exec option). `docs/examples/delegation-policy.json` is a valid policy listing seventeen read-only candidates (`ls cat head tail wc grep diff stat pwd echo true false cut tr basename dirname realpath`) with placeholder senders; copy only what you have checked. `git` and `cargo` are listed the same way and are usable only with a literal subcommand and a short option list (`git status` while the denylist is on, because `git log`, `git diff` and `git show` can print denied files such as `secrets/x`; those only with the denylist off; `cargo test|check|build`; a `+toolchain` token is refused). `cargo test` and `cargo build` still run project code. Programs you add are your responsibility. A directory operand is allowed only for `ls`, `stat`, `realpath`, `basename`, `dirname` and `git status` (a recursive read could print denied files), and tightening the policy shrinks open contracts at their next bypass answer. Anything else prompts as usual. `full-bypass` Bash is not bounded by any parser: it is a trust decision about the sender. A denylist is on by default (force pushes, deploys, publishing, secrets paths and similar) as defence in depth; every bypass answer is checked against it again per tool call. Each decision, bypass answer and contract close is appended to `delegation.json.audit.jsonl` next to the policy. To stop everything at once:

    wormhole delegation revoke --policy ~/.wormhole/delegation.json
    wormhole delegation resume --policy ~/.wormhole/delegation.json

Bypass levels remove your prompts for the contract's life: read the risks in [docs/adr/0001-delegation.md](docs/adr/0001-delegation.md) and [SECURITY.md](SECURITY.md) before granting one.

## Scope

- Honest, enrolled devices on one private network (Tailscale), and their Claude Code sessions. Crashes, restarts and partitions are tolerated; dishonest participants are not. See [the fault model](docs/design.md#fault-model).
- Each machine is used by one person, or by accounts that all trust each other. Identity is per tailnet node: every account on an allowed machine has that machine's full access to the hub, including its sessions' messages.
- One hub process on one machine; one small daemon per developer machine.
- Delivery into Claude Code through hooks (generally available) and, optionally, channels (research preview).

## Not in scope

- Untrusted or dishonest participants (Byzantine fault tolerance), and public networks.
- Machines shared with accounts you do not trust.
- Replacing git, pull requests or code review.
- Routing between different users' Claude accounts through Anthropic's services; wormhole runs its own relay.

## License

Apache-2.0. See [LICENSE](LICENSE).
