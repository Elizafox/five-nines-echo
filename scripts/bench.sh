#!/usr/bin/env bash
# Turnkey connection-rate + throughput benchmark for echod.
#
# Builds a release echod and the echobench load generator, launches a supervisor
# with a tuned config (rate limiter + in-flight cap disabled, isolated ports and
# sockets dir so it won't collide with a running instance), waits for the plain
# port to accept, runs the plain/tls x conn/throughput matrix, then tears the
# supervisor down.
#
# Loopback is NOT exempt from the per-IP accept rate limiter (src/limits.rs), so
# the disabled `[limits]` below are what let this measure the server instead of
# the throttle.
#
# Usage: scripts/bench.sh [--connections N] [--duration S] [--message-size B]
set -euo pipefail
cd "$(dirname "$0")/.."

CONNECTIONS=50
DURATION=10
MSG_SIZE=256
while [ $# -gt 0 ]; do
  case "$1" in
    --connections)  CONNECTIONS=$2; shift 2 ;;
    --duration)     DURATION=$2;    shift 2 ;;
    --message-size) MSG_SIZE=$2;    shift 2 ;;
    -h|--help)
      echo "usage: scripts/bench.sh [--connections N] [--duration S] [--message-size B]"
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

PLAIN_PORT=17070
TLS_PORT=17071
WORKDIR="/tmp/echobench-$$"        # short path: keeps UDS sun_path under the 104-char limit
CONF="$WORKDIR/bench.toml"
LOG="$WORKDIR/echod.log"
SUP_PID=""

cleanup() {
  if [ -n "$SUP_PID" ] && kill -0 "$SUP_PID" 2>/dev/null; then
    kill -TERM "$SUP_PID" 2>/dev/null || true
    for _ in 1 2 3 4 5 6; do kill -0 "$SUP_PID" 2>/dev/null || break; sleep 0.5; done
    kill -KILL "$SUP_PID" 2>/dev/null || true
  fi
  pkill -f "echod --config $CONF" 2>/dev/null || true
  rm -rf "$WORKDIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "building release echod + echobench..."
cargo build --release
cargo build --release --example echobench
[ -f certs/server.crt ] || ./certs/gen.sh

mkdir -p "$WORKDIR/sock"
cat >"$CONF" <<EOF
plain_port  = $PLAIN_PORT
tls_port    = $TLS_PORT
sockets_dir = "$WORKDIR/sock"

[limits]
accept_rate_per_ip     = 0   # disable per-IP token bucket (src/limits.rs:132)
max_in_flight_per_role = 0   # disable concurrent-session cap (src/limits.rs:45)
tls_idle_timeout_secs  = 0   # no idle watchdog during a run

[health]
bind_addr = ""               # disable health HTTP so we don't touch :7079
EOF

echo "launching echod supervisor (ports $PLAIN_PORT/$TLS_PORT, log $LOG)..."
./target/release/echod --config "$CONF" supervisor >"$LOG" 2>&1 &
SUP_PID=$!

# Readiness: poll the plain port until it accepts (mirrors e2e/portability.py).
tries=0
until (exec 3<>"/dev/tcp/127.0.0.1/$PLAIN_PORT") 2>/dev/null; do
  tries=$((tries + 1))
  if ! kill -0 "$SUP_PID" 2>/dev/null; then
    echo "supervisor exited before listening; see $LOG" >&2
    exit 1
  fi
  if [ "$tries" -ge 100 ]; then
    echo "supervisor never opened plain port $PLAIN_PORT; see $LOG" >&2
    exit 1
  fi
  sleep 0.1
done

BENCH=./target/release/examples/echobench
run() {
  local title=$1; shift
  echo
  echo "### $title"
  "$BENCH" "$@" --connections "$CONNECTIONS" --duration "$DURATION" --message-size "$MSG_SIZE"
}

echo "server up. running matrix: ${CONNECTIONS} conns x ${DURATION}s, ${MSG_SIZE}B messages"
run "plain / connection rate" --plain --port "$PLAIN_PORT" --mode conn
run "plain / throughput"      --plain --port "$PLAIN_PORT" --mode throughput
run "tls / connection rate"   --tls   --port "$TLS_PORT"   --mode conn
run "tls / throughput"        --tls   --port "$TLS_PORT"   --mode throughput

echo
echo "done."
