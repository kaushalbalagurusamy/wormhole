#!/bin/sh
# Measure hook latency, message delivery latency and idle resource use on this machine,
# with a hub and two daemons on localhost (static identity), first over ws:// and then over
# wss:// with a throwaway CA (needs the openssl CLI). Usage: scripts/bench.sh [n]
set -eu
N="${1:-300}"
cd "$(dirname "$0")/.."
cargo build --release --quiet --bin wormhole --example bench
T="$(cd "${CARGO_TARGET_DIR:-target}/release" && pwd)"
W="$T/wormhole"
REV="$(git rev-parse --short HEAD)"
D="$(mktemp -d "${TMPDIR:-/tmp}/wormhole-bench.XXXXXX")"
HUB=; DA=; DB=; MCP=
trap 'kill $HUB $DA $DB $MCP 2>/dev/null || true; rm -rf "$D"' EXIT
# Unix socket paths are limited to about 100 bytes, so work inside the temp dir and use
# relative socket paths.
cd "$D"

for r in a b; do
  mkdir -p "$r/proj/.git" "$r/proj/src"
  printf '[remote "origin"]\n\turl = git@example.com:bench/proj.git\n' > "$r/proj/.git/config"
  echo 'ref: refs/heads/main' > "$r/proj/.git/HEAD"
done

echo "date: $(date -u +%Y-%m-%dT%H:%MZ)"
echo "wormhole: $REV, $(rustc --version)"
echo "machine: $(uname -sm), $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -p)"

# start_net <ws|wss>: a fresh hub and two daemons.
start_net() {
  kill $HUB $DA $DB 2>/dev/null || true
  sleep 0.3
  rm -rf hub.sqlite* run-a run-b
  if [ "$1" = wss ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=bench CA" -keyout ca.key -out ca.pem 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout hub.key -out hub.csr 2>/dev/null
    printf 'subjectAltName=DNS:localhost\n' > san.ext
    openssl x509 -req -in hub.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile san.ext -out hub.crt 2>/dev/null
    "$W" hub --listen 127.0.0.1:17420 --db hub.sqlite --identity static --tls-cert hub.crt --tls-key hub.key 2>hub.log & HUB=$!
    URL=wss://localhost:17420/ws; CA="--tls-ca ca.pem"
  else
    "$W" hub --listen 127.0.0.1:17420 --db hub.sqlite --identity static 2>hub.log & HUB=$!
    URL=ws://127.0.0.1:17420/ws; CA=
  fi
  sleep 0.3
  "$W" daemon --hub $URL $CA --http 127.0.0.1:17421 --socket run-a/d.sock --static-identity alice@bench-a 2>a.log & DA=$!
  "$W" daemon --hub $URL $CA --http 127.0.0.1:17422 --socket run-b/d.sock --static-identity bob@bench-b 2>b.log & DB=$!
  sleep 1
  kill -0 $DA $DB || { cat hub.log a.log b.log; exit 1; }
}

run() {
  "$T/examples/bench" 127.0.0.1:17421 "$(cat run-a/hook-token)" run-a/d.sock \
    127.0.0.1:17422 "$(cat run-b/hook-token)" run-b/d.sock \
    "$D/a/proj" "$D/b/proj" "$W" "$N"
}

if command -v openssl >/dev/null; then
  start_net wss
  echo "transport: wss:// (TLS on the daemon-to-hub link)"
  run
fi
start_net ws
echo "transport: ws:// (loopback plaintext)"
run

# One channel server attached to a session, as Claude Code would run it.
( sleep 120 ) | CLAUDE_CODE_SESSION_ID=bench-a-0000-4000-8000-000000000001 "$W" mcp-channel --socket run-a/d.sock >/dev/null & MCP=$!

cpu_s() { ps -o time= -p "$1" | awk -F'[:.]' '{ if (NF==3) print $1*60+$2+$3/100; else print $1*3600+$2*60+$3+$4/100 }'; }
sleep 5
IDLE=60
A0=$(cpu_s $DA); H0=$(cpu_s $HUB)
sleep $IDLE
A1=$(cpu_s $DA); H1=$(cpu_s $HUB)
for p in "daemon:$DA" "hub:$HUB" "mcp-channel:$(pgrep -P $MCP 2>/dev/null || echo $MCP)"; do
  name=${p%%:*}; pid=${p#*:}
  echo "$name idle RSS: $(ps -o rss= -p "$pid" | awk '{printf "%.1f MB", $1/1024}')"
done
awk -v a0="$A0" -v a1="$A1" -v h0="$H0" -v h1="$H1" -v t="$IDLE" \
  'BEGIN { printf "daemon idle CPU over %ds: %.3f%%\nhub idle CPU over %ds: %.3f%%\n", t, (a1-a0)/t*100, t, (h1-h0)/t*100 }'
