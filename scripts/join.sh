#!/usr/bin/env bash
# Join a wormhole hub from this machine and connect one repository checkout.
#
#   scripts/join.sh <hub-host:port> <repo-checkout> [--protected GLOB]...
#   e.g. scripts/join.sh versus-mini.tail1d5eb3.ts.net:7420 ~/code/RCT-capstone --protected '**/.env*'
#
# Steps: check the hub answers; build wormhole (installs Rust with rustup if cargo is missing);
# install the binary in ~/.wormhole/bin; run the daemon as a LaunchAgent (macOS) or a systemd
# user unit (Linux); merge the hooks into <repo>/.claude/settings.local.json (mode 0600); register
# the MCP server for that checkout. Safe to re-run. Never prints the hook token.
set -euo pipefail

die() { echo "join: $*" >&2; exit 1; }
[ $# -ge 2 ] || die "usage: join.sh <hub-host:port> <repo-checkout> [--protected GLOB]..."
HUB="$1"; REPO="$(cd "$2" && pwd)"; shift 2
PROTECTED=()
while [ $# -gt 0 ]; do
  [ "$1" = "--protected" ] && [ $# -ge 2 ] || die "unexpected argument: $1"
  PROTECTED+=(--protected "$2"); shift 2
done
SRC="$(cd "$(dirname "$0")/.." && pwd)"
WH="$HOME/.wormhole"; BIN="$WH/bin/wormhole"

echo "1/6 Checking the hub at https://$HUB/"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "https://$HUB/" || true)
case "$code" in
  200) ;;
  403) die "the hub refused your identity (403). Tell the hub owner which Tailscale login you use." ;;
  000) die "cannot reach $HUB. Accept the Tailscale share for the hub machine, check Tailscale is running, then re-run." ;;
  *)   die "unexpected HTTP $code from the hub." ;;
esac

echo "2/6 Building wormhole"
if ! command -v cargo >/dev/null; then
  [ -x "$HOME/.cargo/bin/cargo" ] || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  export PATH="$HOME/.cargo/bin:$PATH"
fi
(cd "$SRC" && cargo build --release --locked -q)

echo "3/6 Installing $BIN"
mkdir -p "$WH/bin"; chmod 700 "$WH" "$WH/bin"
cp "$SRC/target/release/wormhole" "$BIN.new" && mv "$BIN.new" "$BIN"

echo "4/6 Running the daemon"
ARGS=(daemon --hub "wss://$HUB/ws" "${PROTECTED[@]}")
case "$(uname)" in
  Darwin)
    P="$HOME/Library/LaunchAgents/dev.wormhole.daemon.plist"; mkdir -p "$(dirname "$P")"
    {
      echo '<?xml version="1.0" encoding="UTF-8"?>'
      echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
      echo '<plist version="1.0"><dict><key>Label</key><string>dev.wormhole.daemon</string>'
      echo '<key>ProgramArguments</key><array>'
      for a in "$BIN" "${ARGS[@]}"; do a=${a//&/&amp;}; a=${a//</&lt;}; echo "<string>${a//>/&gt;}</string>"; done
      echo '</array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/>'
      echo "<key>StandardErrorPath</key><string>$WH/daemon.log</string><key>StandardOutPath</key><string>$WH/daemon.log</string>"
      echo '</dict></plist>'
    } > "$P"
    launchctl bootout "gui/$(id -u)/dev.wormhole.daemon" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$P"
    ;;
  Linux)
    U="$HOME/.config/systemd/user/wormhole-daemon.service"; mkdir -p "$(dirname "$U")"
    q=(); for a in "$BIN" "${ARGS[@]}"; do q+=("\"${a//\"/\\\"}\""); done
    printf '[Unit]\nDescription=wormhole daemon\n[Service]\nExecStart=%s\nRestart=always\n[Install]\nWantedBy=default.target\n' "${q[*]}" > "$U"
    systemctl --user daemon-reload && systemctl --user enable --now wormhole-daemon
    systemctl --user restart wormhole-daemon
    ;;
  *) die "unsupported OS $(uname); run '$BIN ${ARGS[*]}' yourself" ;;
esac
for _ in $(seq 1 20); do [ -S "$WH/daemon.sock" ] && [ -s "$WH/hook-token" ] && break; sleep 0.5; done
[ -S "$WH/daemon.sock" ] || die "the daemon did not start; see $WH/daemon.log (or journalctl --user -u wormhole-daemon)"

echo "5/6 Connecting $REPO"
command -v python3 >/dev/null || die "python3 is needed to merge the hook settings"
CFG=$("$BIN" install --project "$REPO" | python3 -c 'import re,sys; print(re.search(r"```json\n(.*?)\n```", sys.stdin.read(), re.S).group(1))')
mkdir -p "$REPO/.claude"; S="$REPO/.claude/settings.local.json"; [ -f "$S" ] || echo '{}' > "$S"
CFG="$CFG" python3 - "$S" <<'PY'
import json, os, sys
path = sys.argv[1]
cur, new = json.load(open(path)), json.loads(os.environ["CFG"])
hooks = cur.setdefault("hooks", {})
def ours(entry):
    return any("127.0.0.1:7421/hook" in json.dumps(h) or "daemon.sock" in json.dumps(h) for h in entry.get("hooks", []))
for event, entries in new.get("hooks", {}).items():
    hooks[event] = [e for e in hooks.get(event, []) if not ours(e)] + entries  # replace our old entries, keep the rest
fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(cur, f, indent=2)
os.replace(path + ".tmp", path)
PY
chmod 600 "$S"
git -C "$REPO" check-ignore -q "$S" || echo "warning: $S is not gitignored; never commit it (it holds the hook token)" >&2
if command -v claude >/dev/null; then
  (cd "$REPO" && claude mcp remove wormhole --scope local >/dev/null 2>&1 || true
   cd "$REPO" && claude mcp add wormhole --scope local -- "$BIN" mcp-channel --socket "$WH/daemon.sock" >/dev/null)
else
  echo "Claude Code not found; later run in $REPO: claude mcp add wormhole --scope local -- $BIN mcp-channel --socket $WH/daemon.sock"
fi

echo "6/6 Done. Open Claude Code in $REPO; your session appears on https://$HUB/"
