#!/usr/bin/env bash
# Whole-gateway HTTP load run: one release gateway, a bun origin, ApacheBench.
#
#   benches/http/run.sh [requests] [concurrency]
#
# Requires: cargo, bun, ab (httpd-tools / apache2-utils), python3, openssl.
# Prints CSV to stdout. Gateway, origin and load generator share one host, so
# results show relative cost between workloads on that host, not capacity.
# THREADS sets the gateway's worker threads (default 2, the gateway default).
# PERF=1 records a flat `perf record` of the gateway for each workload into the
# work directory; build with symbols for it to be readable:
#   CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=line-tables-only \
#     PERF=1 benches/http/run.sh
#
# There is deliberately no direct-to-origin row: ApacheBench keeps connections
# alive with HTTP/1.0 semantics, which the origin does not honour, so it would
# measure reconnects rather than the origin.
set -euo pipefail

REQUESTS=${1:-100000}
CONCURRENCY=${2:-64}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE="$ROOT/benches/http"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/lagos-load.XXXXXX")
PIDS=()
# A load run has nothing worth draining: the gateway's graceful shutdown would
# keep it alive for `server.graceful_shutdown` after the script ends.
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  sleep 0.5
  for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

for port in 19100 19101 9405; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "port $port is already in use" >&2
    exit 1
  fi
done

cargo build --release --locked --bin lagos --manifest-path "$ROOT/Cargo.toml" >&2
BIN="$ROOT/target/release/lagos"

cp "$ROOT/tests/e2e/jwks_server.py" "$ROOT/tests/e2e/oidc_mint.py" "$WORK/"
openssl genrsa -out "$WORK/oidc_key.pem" 2048 2>/dev/null
openssl rsa -in "$WORK/oidc_key.pem" -pubout -out "$WORK/oidc_pub.pem" 2>/dev/null
( cd "$WORK" && exec python3 jwks_server.py ) >"$WORK/jwks.log" 2>&1 & PIDS+=($!)
bun "$HERE/origin.js" 19101 >"$WORK/origin.log" 2>&1 & PIDS+=($!)
GATEWAY_CONFIG="$HERE/gateway.yml" "$BIN" >/dev/null 2>"$WORK/gateway.err" & GW=$!; PIDS+=($GW)

for _ in $(seq 50); do
  curl -fs -o /dev/null http://127.0.0.1:19100/public/ready 2>/dev/null && break
  sleep 0.1
done
TOKEN=$(cd "$WORK" && python3 oidc_mint.py valid)
curl -fs -o /dev/null -H "Authorization: Bearer $TOKEN" http://127.0.0.1:19100/private/warm

# field <ab output> <label>: the value after an ApacheBench label.
field() { awk -v k="$2" 'index($0, k) == 1 { sub(k, ""); print $1; exit }' "$1"; }
pct() { awk -v p="$2%" '$1 == p { print $2; exit }' "$1"; }

run() {
  local name=$1 url=$2; shift 2
  ab -q -k -c "$CONCURRENCY" -n $((REQUESTS / 10)) "$@" "$url" >/dev/null 2>&1 || true
  local before after
  before=$(awk '{print $14 + $15}' "/proc/$GW/stat")
  if [ "${PERF:-0}" = 1 ]; then
    perf record -F 999 -p "$GW" -o "$WORK/$name.perf.data" -- sleep 3600 >/dev/null 2>&1 & local PERF_PID=$!
    sleep 0.5
  fi
  local start end
  start=$(date +%s.%N)
  ab -k -c "$CONCURRENCY" -n "$REQUESTS" "$@" "$url" >"$WORK/$name.ab" 2>&1 || true
  end=$(date +%s.%N)
  if [ -n "${PERF_PID:-}" ]; then kill -INT "$PERF_PID"; wait "$PERF_PID" 2>/dev/null || true; unset PERF_PID; fi
  after=$(awk '{print $14 + $15}' "/proc/$GW/stat")
  local hz cpu
  hz=$(getconf CLK_TCK)
  cpu=$(awk -v a="$after" -v b="$before" -v s="$start" -v e="$end" -v hz="$hz" \
    'BEGIN { printf "%.0f", 100 * (a - b) / hz / (e - s) }')
  local rss
  rss=$(awk '/VmHWM/ {print $2}' "/proc/$GW/status")
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$name" "$CONCURRENCY" "$REQUESTS" \
    "$(field "$WORK/$name.ab" 'Requests per second:')" \
    "$(pct "$WORK/$name.ab" 50)" "$(pct "$WORK/$name.ab" 95)" "$(pct "$WORK/$name.ab" 99)" \
    "$(field "$WORK/$name.ab" 'Failed requests:')" \
    "$(field "$WORK/$name.ab" 'Non-2xx responses:')" "$cpu" "$rss"
}

echo "workload,concurrency,requests,rps,p50_ms,p95_ms,p99_ms,failed,non_2xx,gateway_cpu_pct,gateway_peak_rss_kib"
run proxy http://127.0.0.1:19100/public/items
run cache_hit http://127.0.0.1:19100/cached/items
run jwt_proxy http://127.0.0.1:19100/private/items -H "Authorization: Bearer $TOKEN"
run refused_404 http://127.0.0.1:19100/not-routed
echo "work directory: $WORK" >&2
