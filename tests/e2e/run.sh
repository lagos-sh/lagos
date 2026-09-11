#!/usr/bin/env bash
#
# End-to-end suite. Stands up a fake upstream, a fake Google certificate
# endpoint and a fake legacy service, runs both gateway binaries against them,
# and asserts the security-relevant behaviour of the whole stack.
#
#   ./tests/e2e/run.sh          (from the repository root)
#
# Requires: cargo, python3, openssl, curl.

set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
ROOT=$PWD
E2E=tests/e2e
WORK=$(mktemp -d)
PASS=0; FAIL=0

cleanup() {
  exec 2>/dev/null   # suppress the shell's job-termination notices
  # SIGINT is inherited as ignored by background jobs, so TERM is what actually
  # lands. Never `wait` unbounded: Pingora drains on TERM and a wedged fixture
  # would hang CI forever.
  for p in "${PIDS[@]:-}"; do kill -TERM "$p"; done
  for _ in 1 2 3 4 5 6 7 8; do
    alive=0
    for p in "${PIDS[@]:-}"; do kill -0 "$p" && alive=1; done
    [ "$alive" -eq 0 ] && break
    sleep 0.5
  done
  for p in "${PIDS[@]:-}"; do kill -KILL "$p"; done
  rm -rf "$WORK"
}
trap cleanup EXIT
PIDS=()

say()  { printf '\n\033[1m%s\033[0m\n' "$1"; }
ok()   { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %-52s %s\n' "$1" "${2:-}"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %-52s %s\n' "$1" "${2:-}"; }

# Assert an HTTP status. Usage: expect <desc> <want> <curl args...>
expect() {
  local desc=$1 want=$2; shift 2
  local got; got=$(curl -s -o "$WORK/body" -w '%{http_code}' -m 5 "$@")
  if [ "$got" = "$want" ]; then ok "$desc" "$got"
  else bad "$desc" "got $got want $want — $(head -c 90 "$WORK/body")"; fi
}

say "building"
if ! cargo build --bin lagos >"$WORK/build.log" 2>&1; then
  cat "$WORK/build.log"; exit 1
fi
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
  -days 1 -nodes -subj "/CN=securetoken-test" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/evil.pem" -out "$WORK/evilcert.pem" \
  -days 1 -nodes -subj "/CN=evil" 2>/dev/null
# A plain RSA key for the generic OIDC issuer, published as a JWKS rather than
# as Google's certificate map.
openssl genrsa -out "$WORK/oidc_key.pem" 2048 2>/dev/null
openssl rsa -in "$WORK/oidc_key.pem" -pubout -out "$WORK/oidc_pub.pem" 2>/dev/null

# A stale process on a fixture port would be silently tested instead of the one
# we just built — and would quietly pass or fail for the wrong reason.
# Cargo's output directory is configurable (a shared target dir across sibling
# checkouts, say), so ask cargo rather than assuming ./target.
TARGET_DIR=$(cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
BIN="$TARGET_DIR/debug"

say "checking ports"
BUSY=()
for port in 9401 9402 9403 9405 9411 9412 3311 3313; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then BUSY+=("$port"); fi
done
if [ "${#BUSY[@]}" -gt 0 ]; then
  echo "  ports already in use: ${BUSY[*]}"
  echo "  something else is listening; stop it and re-run."
  exit 1
fi
ok "fixture ports are free"

say "starting fixtures"
cp "$ROOT/$E2E"/*.py "$WORK/"
# Fixtures must not hold the script's stdout open, or a piped caller never sees EOF.
( cd "$WORK" && exec python3 echo_upstream.py ) >"$WORK/up.log"     2>&1 & PIDS+=($!)
( cd "$WORK" && exec python3 certs_server.py ) >"$WORK/certs.log"  2>&1 & PIDS+=($!)
( cd "$WORK" && exec python3 sse_upstream.py ) >"$WORK/sse.log"    2>&1 & PIDS+=($!)
( cd "$WORK" && exec python3 pool_member.py 9411 pool-1 ) >"$WORK/p1.log" 2>&1 & PIDS+=($!)
( cd "$WORK" && exec python3 pool_member.py 9412 pool-2 ) >"$WORK/p2.log" 2>&1 & PIDS+=($!)
( cd "$WORK" && exec python3 jwks_server.py ) >"$WORK/jwks.log" 2>&1 & PIDS+=($!)
( cd "$WORK" && exec python3 cache_upstream.py ) >"$WORK/cache.log" 2>&1 & PIDS+=($!)
sleep 1.5

export API_KEY=super-secret-key
# Deliberately different: the whole point of the machine tier is that the
# public credential must not open internal routes.
export INTERNAL_API_KEY=internal-only-key
export GATEWAY_IDENTITY_SECRET=identity-signing-key
export UPSTREAM_ECHO_URL=http://127.0.0.1:9401
export UPSTREAM_SSE_URL=http://127.0.0.1:9404
export LEGACY_SERVICE_URL=http://127.0.0.1:9403
export FIREBASE_PROJECT_ID=demo-project
export PROXY_ENABLE_PHASE2_ROUTES=true
export NODE_ENV=development

GATEWAY_CONFIG=$E2E/gateway.yml     "$BIN/lagos"         > "$WORK/g.log" 2>&1 & PIDS+=($!)
G=http://127.0.0.1:3311
I=http://127.0.0.1:3313

# Poll rather than sleep a fixed amount: startup time moves with the number of
# listeners and with how loaded the machine is.
wait_ready() {
  local name=$1 url=$2 log=$3
  for _ in $(seq 1 60); do
    if curl -fsS -m 2 "$url" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  echo "  $name did not become ready"; sed 's/\x1b\[[0-9;]*m//g' "$log" | tail -20; return 1
}
wait_ready "gateway"     "$G/bff/health" "$WORK/g.log" || exit 1
# The internal listener answers no health path; a refused connection is the signal.
for _ in $(seq 1 60); do
  curl -s -o /dev/null -m 2 "$I/" && break
  sleep 0.5
done

say "health and routing"
expect "health endpoint"                    200 "$G/bff/health"
expect "public route proxies"               200 "$G/bff/v1/products/42"
expect "disallowed method"                  404 -X POST "$G/bff/v1/products/42"
expect "unallowlisted prefix"               404 "$G/bff/v1/nonexistent/thing"
expect "unknown bare path"                  404 "$G/nosuchservice/42"

say "deny-list"
expect "internal subtree"                   404 "$G/bff/v1/products/internal/sync"
expect "denied under an allowed prefix"     404 "$G/bff/v1/loyalty/wallets/7"

say "path traversal"
expect "plain dot-segment"                  404 --path-as-is "$G/bff/v1/products/../products/internal/x"
expect "single-encoded"                     404 "$G/bff/v1/products/%2e%2e/products/internal/x"
expect "double-encoded"                     404 "$G/bff/v1/products/%252e%252e/products/internal/x"
expect "encoded separator"                  404 "$G/bff/v1/products%2f..%2fproducts%2finternal"
expect "backslash"                          404 "$G/bff/v1/products/..%5cinternal"

say "credentials"
expect "client supplies x-api-key"          403 -H 'x-api-key: stolen' "$G/bff/v1/products/42"
expect "no token on an authenticated route" 401 "$G/bff/v1/loyalty/settings"
expect "junk token"                         401 -H 'Authorization: Bearer not.a.jwt' "$G/bff/v1/loyalty/settings"
expect "wrong auth scheme"                  401 -H 'Authorization: Basic abc' "$G/bff/v1/loyalty/settings"

say "token verification"
TOK=$(cd "$WORK" && python3 mint.py)
expect "valid token"                        200 -H "Authorization: Bearer $TOK" "$G/bff/v1/loyalty/settings"
expect "lowercase bearer scheme"            200 -H "Authorization: bearer $TOK" "$G/bff/v1/loyalty/settings"
expect "expired"                            401 -H "Authorization: Bearer $(cd "$WORK" && python3 mint.py expired)"  "$G/bff/v1/loyalty/settings"
expect "wrong audience"                     401 -H "Authorization: Bearer $(cd "$WORK" && python3 mint.py wrongaud)" "$G/bff/v1/loyalty/settings"
expect "tampered signature"                 401 -H "Authorization: Bearer ${TOK%?}X" "$G/bff/v1/loyalty/settings"
FORGED=$(python3 -c "
import base64,json
t='$TOK'.split('.'); p=json.loads(base64.urlsafe_b64decode(t[1]+'==')); p['sub']='1'
print(f\"{t[0]}.{base64.urlsafe_b64encode(json.dumps(p).encode()).rstrip(b'=').decode()}.{t[2]}\")")
expect "payload swapped, signature kept"    401 -H "Authorization: Bearer $FORGED" "$G/bff/v1/loyalty/settings"
EVIL=$(cd "$WORK" && python3 mint.py evilkey)
expect "signed with another key"            401 -H "Authorization: Bearer $EVIL" "$G/bff/v1/loyalty/settings"
NONE=$(cd "$WORK" && python3 mint.py algnone)
expect "alg:none downgrade"                 401 -H "Authorization: Bearer $NONE" "$G/bff/v1/loyalty/settings"
expect "issuer not configured"              503 -H "Authorization: Bearer $(cd "$WORK" && python3 mint.py otherproject)" "$G/bff/v1/loyalty/settings"

say "header hygiene"
curl -s -m 5 -H "Authorization: Bearer $TOK" -H 'Cookie: session=leak' \
     -H 'X-Random: x' \
     "$G/bff/v1/loyalty/settings" > "$WORK/h.json"
python3 - "$WORK/h.json" <<'PY' && ok "no client header leaked upstream" || bad "client header leaked upstream"
import json,sys
h = json.load(open(sys.argv[1]))["headers"]
leaked = [k for k in ("cookie","x-random","authorization") if k in h]
sys.exit(1 if leaked else 0)
PY
python3 - "$WORK/h.json" <<'PY' && ok "identity injected from the token, not the client" || bad "identity not injected correctly"
import json,sys
h = json.load(open(sys.argv[1]))["headers"]
sys.exit(0 if h.get("x-auth-subject") == "4821" else 1)
PY
python3 - "$WORK/h.json" <<'PY' && ok "x-api-key injected server-side" || bad "x-api-key missing"
import json,sys
h = json.load(open(sys.argv[1]))["headers"]
sys.exit(0 if h.get("x-api-key") == "super-secret-key" else 1)
PY
python3 - "$WORK/h.json" <<'PY' && ok "gateway identity token verifies" || bad "identity token did not verify"
import base64,hashlib,hmac,json,sys
h = json.load(open(sys.argv[1]))["headers"]
tok = h.get("x-auth-token","")
try:
    si, sig = tok.rsplit(".", 1)
    want = base64.urlsafe_b64encode(
        hmac.new(b"identity-signing-key", si.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    claims = json.loads(base64.urlsafe_b64decode(si.split(".")[1] + "=="))
    sys.exit(0 if hmac.compare_digest(sig, want) and claims["sub"] == "4821" else 1)
except Exception:
    sys.exit(1)
PY

say "single entry point"
expect "bare service path is served too"       200 "$G/products/42"
expect "deny-list applies at the bare path"    404 "$G/loyalty/wallets/7"
expect "deny-list applies at the mounted path" 404 "$G/bff/v1/loyalty/wallets/7"

say "machine tier isolation"
# Two separate refusals: the route is simply not in the public table (404),
# and presenting the machine credential to the public listener is itself an
# error (403) on any path, which is why it cannot be used to enumerate.
expect "machine route absent from public port" 404 -X POST "$G/products/internal/sync"
expect "machine key refused on public" 403 \
  -H "x-internal-api-key: $INTERNAL_API_KEY" "$G/bff/v1/ops/internal/x"
expect "machine credential refused on public"  403 -X POST -H "x-api-key: $API_KEY" "$G/products/42"
expect "machine route served on internal port" 200 -X POST -H "x-internal-api-key: $INTERNAL_API_KEY" "$I/products/internal/sync"
expect "the public key does NOT open internal" 404 -X POST -H "x-internal-api-key: $API_KEY" "$I/products/internal/sync"
expect "wrong credential is refused"           404 -X POST -H "x-internal-api-key: wrong" "$I/products/internal/sync"
curl -s -m 5 -X POST -H "x-internal-api-key: $INTERNAL_API_KEY" "$I/products/internal/sync" > "$WORK/mach.json"
python3 "$E2E/assert_header.py" "$WORK/mach.json" x-internal-api-key "$INTERNAL_API_KEY" \
  && ok "internal upstream gets the internal credential" || bad "internal credential not forwarded"
python3 "$E2E/assert_absent.py" "$WORK/mach.json" x-api-key \
  && ok "public credential never reaches internal upstream" || bad "public credential leaked to internal upstream"
expect "absent credential is refused"          404 -X POST "$I/products/internal/sync"
expect "public route absent from internal port" 404 "$I/bff/v1/products/42"

say "optional auth tier"
expect "signed-out browse works"              200 "$G/bff/v1/browse/1"
curl -s -m 5 "$G/bff/v1/browse/1" > "$WORK/anon.json"
python3 "$E2E/assert_absent.py" "$WORK/anon.json" x-auth-subject \
  && ok "anonymous request carries no identity" || bad "identity leaked on anonymous request"
expect "spoofed identity refused when signed out" 403 \
  -H "X-Auth-Subject: 99999" "$G/bff/v1/browse/1"
expect "spoofed identity refused when signed in" 403 \
  -H "Authorization: Bearer $TOK" -H "X-Auth-Subject: 99999" "$G/bff/v1/loyalty/settings"
expect "forged identity token refused" 403 \
  -H "X-Auth-Token: forged" "$G/bff/v1/browse/1"
curl -s -m 5 -H "Authorization: Bearer $TOK" "$G/bff/v1/browse/1" > "$WORK/signed.json"
python3 "$E2E/assert_header.py" "$WORK/signed.json" x-auth-subject 4821 \
  && ok "signed-in browse is personalised" || bad "identity missing when signed in"
expect "stale token is a 401, not silent anon" 401 \
  -H "Authorization: Bearer $(cd "$WORK" && python3 mint.py expired)" "$G/bff/v1/browse/1"

say "body size"
dd if=/dev/zero of="$WORK/oversize.bin" bs=2048 count=1 2>/dev/null
expect "oversize body refused" 413 -X POST --data-binary @"$WORK/oversize.bin" \
  "$G/bff/v1/browse/1"
python3 "$E2E/assert_json.py" "$WORK/body" statusCode 413 \
  && ok "413 carries the JSON error envelope" || bad "413 body was not the JSON envelope"

say "streaming and upstream failures"
# An event stream must arrive incrementally; a proxy that buffers it is useless
# for the realtime order feed.
curl -sN -m 12 "$G/bff/v1/events/orders" > "$WORK/sse.out" 2>/dev/null
python3 "$E2E/assert_sse.py" "$WORK/sse.out" \
  && ok "SSE events stream incrementally" || bad "SSE was buffered or truncated"
expect "unresponsive upstream returns 504"  504 "$G/bff/v1/blackhole/x"
python3 "$E2E/assert_json.py" "$WORK/body" statusCode 504 \
  && ok "504 carries the JSON error envelope" || bad "504 body was not the JSON envelope"
expect "unreachable upstream returns 502"   502 "$G/bff/v1/deadend/x"

say "upstream pool, load balancing and health checks"
# Both members healthy: round robin must actually use both.
SEEN=$(for i in 1 2 3 4 5 6 7 8; do curl -s -m 5 "$G/bff/v1/pooled/x"; echo; done | sort -u | tr '\n' ' ')
[ "$SEEN" = "pool-1 pool-2 " ] \
  && ok "round robin spreads across both members" || bad "pool used only: $SEEN"

# Fail one member's health check; it must leave the rotation.
touch "$WORK/unhealthy-9412"
sleep 3
SEEN=$(for i in 1 2 3 4 5 6; do curl -s -m 5 "$G/bff/v1/pooled/x"; echo; done | sort -u | tr '\n' ' ')
[ "$SEEN" = "pool-1 " ] \
  && ok "an unhealthy member is taken out of rotation" || bad "unhealthy member still served: $SEEN"

# And return once it recovers.
rm -f "$WORK/unhealthy-9412"
sleep 3
SEEN=$(for i in 1 2 3 4 5 6 7 8; do curl -s -m 5 "$G/bff/v1/pooled/x"; echo; done | sort -u | tr '\n' ' ')
[ "$SEEN" = "pool-1 pool-2 " ] \
  && ok "a recovered member returns to rotation" || bad "recovered member absent: $SEEN"

say "declarative claim mapping and ownership binding"
CO=$(cd "$WORK" && python3 mint.py withcompany)
expect "own merchant id is permitted"        200 -H "Authorization: Bearer $CO" "$G/bff/v1/scoped/x?merchantId=11"
expect "another merchant id is refused"      403 -H "Authorization: Bearer $CO" "$G/bff/v1/scoped/x?merchantId=12"
expect "percent-encoded value still matches" 200 -H "Authorization: Bearer $CO" "$G/bff/v1/scoped/x?merchantId=%31%31"
expect "omitted parameter is refused"        403 -H "Authorization: Bearer $CO" "$G/bff/v1/scoped/x"
expect "caller without the claim is refused" 403 -H "Authorization: Bearer $TOK" "$G/bff/v1/scoped/x?merchantId=11"

curl -s -m 5 -H "Authorization: Bearer $CO" "$G/bff/v1/loyalty/settings" > "$WORK/claims.json"
python3 "$E2E/assert_header.py" "$WORK/claims.json" x-company-id 11 \
  && ok "mapped claim reaches the upstream" || bad "mapped claim missing"
python3 "$E2E/assert_header.py" "$WORK/claims.json" x-user-type V \
  && ok "second mapped claim reaches the upstream" || bad "second mapped claim missing"

# The claim is absent from this token; the header must be absent too, not empty.
curl -s -m 5 -H "Authorization: Bearer $TOK" "$G/bff/v1/loyalty/settings" > "$WORK/noclaim.json"
python3 "$E2E/assert_absent.py" "$WORK/noclaim.json" x-company-id \
  && ok "absent claim leaves the header absent" || bad "absent claim produced a header"

# A client must never be able to assert a mapped claim header itself.
curl -s -m 5 -H "Authorization: Bearer $CO" -H "x-company-id: 999" \
  "$G/bff/v1/loyalty/settings" > "$WORK/spoof.json"
python3 "$E2E/assert_header.py" "$WORK/spoof.json" x-company-id 11 \
  && ok "client-supplied claim header is overwritten" || bad "client spoofed a mapped claim header"

say "response cache"
# The origin numbers every response, so one distinct value across three
# requests means they were served from cache.
distinct() { for i in 1 2 3; do curl -s -m 5 "$@"; echo; done | sort -u | wc -l | tr -d ' '; }

[ "$(distinct "$G/bff/v1/cacheable/a")" = "1" ] \
  && ok "a cacheable response is served from cache" || bad "response was not cached"
[ "$(distinct "$G/bff/v1/uncached/a")" = "3" ] \
  && ok "a route without cache always reaches the origin" || bad "uncached route was cached"

# RFC 9111: a shared cache must not store these.
[ "$(distinct "$G/bff/v1/private/a")" = "3" ] \
  && ok 'private is not stored by a shared cache' || bad "private response was cached"
[ "$(distinct "$G/bff/v1/nostore/a")" = "3" ] \
  && ok 'no-store is not stored' || bad "no-store response was cached"

# The one that leaks data if it is wrong: a response to an authorized request
# must not be shared with the next caller.
[ "$(distinct -H "Authorization: Bearer $TOK" "$G/bff/v1/cacheable/auth")" = "3" ] \
  && ok "an authorized request's response is not shared" || bad "AUTHENTICATED RESPONSE WAS CACHED"

# The host is part of the key, so two tenants on one path stay separate.
A=$(curl -s -m 5 -H "Host: a.example.com" "$G/bff/v1/cacheable/t")
B=$(curl -s -m 5 -H "Host: b.example.com" "$G/bff/v1/cacheable/t")
A2=$(curl -s -m 5 -H "Host: a.example.com" "$G/bff/v1/cacheable/t")
{ [ "$A" != "$B" ] && [ "$A" = "$A2" ]; } \
  && ok "the host is part of the cache key" || bad "two hosts shared a cache entry"

curl -s -m 5 "http://127.0.0.1:9390/" | grep -q 'gateway_cache_total' \
  && ok "cache outcomes are exported" || bad "gateway_cache_total missing"

say "circuit breaker"
# The upstream is a closed port, so every attempt fails. After `failures: 3`
# the circuit opens and the gateway answers without dialling.
CODES=$(for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -m 5 -w '%{http_code} ' "$G/bff/v1/breaking/x"
done)
case "$CODES" in
  "502 502 502 503 503 503 ") ok "the circuit opens after the configured failures" ;;
  *) bad "unexpected sequence: $CODES" ;;
esac

curl -s -D- -o /dev/null -m 5 "$G/bff/v1/breaking/x" | grep -qi '^retry-after:' \
  && ok "a shed request says when to come back" || bad "503 carried no Retry-After"

python3 "$E2E/assert_json.py" "$WORK/body" statusCode 503 > /dev/null 2>&1 || true
curl -s -m 5 "$G/bff/v1/breaking/x" > "$WORK/cb.json"
python3 "$E2E/assert_json.py" "$WORK/cb.json" error "Service Unavailable" \
  && ok "it carries the JSON error envelope" || bad "503 body was not the envelope"

# An upstream with no breaker keeps failing the slow way — proving the breaker
# is what changed the behaviour, not something else.
expect "an upstream without a breaker still dials" 502 "$G/bff/v1/deadend/x"

curl -s -m 5 "http://127.0.0.1:9390/" | grep -q 'gateway_circuit_state{upstream="breaking"} 2' \
  && ok "the open circuit is visible in metrics" || bad "circuit state not exported"

say "trace context"
# Relaying `traceparent` untouched would make the upstream a child of the
# *client* and hide the gateway from the trace entirely.
IN="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
curl -s -m 5 -H "traceparent: $IN" "$G/bff/v1/products/42" > "$WORK/trace.json"
SEEN=$(python3 -c "import json;print(json.load(open('$WORK/trace.json'))['headers'].get('traceparent',''))")
case "$SEEN" in
  00-4bf92f3577b34da6a3ce929d0e0e4736-*) ok "the trace id is continued" ;;
  *) bad "trace id was not continued: $SEEN" ;;
esac
[ "$SEEN" != "$IN" ] \
  && ok "the gateway becomes the upstream's parent" || bad "traceparent was relayed untouched"
case "$SEEN" in
  *-00f067aa0ba902b7-*) bad "the client span id was reused" ;;
  *) ok "this hop has its own span id" ;;
esac
case "$SEEN" in
  *-01) ok "the sampling decision is honoured" ;;
  *) bad "sampling flag was changed: $SEEN" ;;
esac

# A request with no context must get one rather than travelling untraced.
curl -s -m 5 "$G/bff/v1/products/42" > "$WORK/trace2.json"
FRESH=$(python3 -c "import json;print(json.load(open('$WORK/trace2.json'))['headers'].get('traceparent',''))")
[ ${#FRESH} -eq 55 ] \
  && ok "a request with no context starts one" || bad "no traceparent generated: $FRESH"

# A broken header must never fail a request.
expect "a malformed traceparent does not fail the request" 200 \
  -H "traceparent: garbage" "$G/bff/v1/products/42"

say "host matching"
# A host-specific route must win over the catch-all, whatever the order.
# The catch-all points at a closed port, so the status says which one matched.
expect "a host-specific route wins over a catch-all" 200 \
  -H "Host: a.example.com" "$G/bff/v1/tenant/x"
# The port is a deployment detail and must not affect matching.
expect "the port is ignored when matching"           200 \
  -H "Host: a.example.com:8443" "$G/bff/v1/tenant/x"
expect "matching ignores case"                       200 \
  -H "Host: A.Example.COM" "$G/bff/v1/tenant/x"
expect "another host falls through to the catch-all" 502 \
  -H "Host: b.example.com" "$G/bff/v1/tenant/x"

say "generic OIDC issuer"
# Not Firebase: a standard issuer publishing an RFC 7517 JWKS. This is what
# proves the gateway is not tied to one identity provider.
mint_oidc() { (cd "$WORK" && python3 oidc_mint.py "$1"); }

curl -s -m 5 -H "Authorization: Bearer $(mint_oidc valid)" "$G/bff/v1/oidc/x" > "$WORK/oidc.json"
python3 "$E2E/assert_header.py" "$WORK/oidc.json" x-auth-subject user-9 \
  && ok "a token from a standard OIDC issuer is accepted" || bad "OIDC token rejected"
python3 "$E2E/assert_header.py" "$WORK/oidc.json" x-user-role admin \
  && ok "its claims map to headers" || bad "claim mapping failed for OIDC"

expect "wrong audience is refused"   401 -H "Authorization: Bearer $(mint_oidc wrongaud)" "$G/bff/v1/oidc/x"
expect "expired token is refused"    401 -H "Authorization: Bearer $(mint_oidc expired)"  "$G/bff/v1/oidc/x"
expect "alg:none is refused"         401 -H "Authorization: Bearer $(mint_oidc algnone)"  "$G/bff/v1/oidc/x"
expect "a missing required claim is refused" 401 -H "Authorization: Bearer $(mint_oidc noclaim)" "$G/bff/v1/oidc/x"
# An unconfigured issuer is not a client error: the gateway cannot verify it.
expect "an unknown issuer is refused" 503 -H "Authorization: Bearer $(mint_oidc wrongiss)" "$G/bff/v1/oidc/x"

# Both providers are live at once, routed by the token's `iss`.
expect "a Firebase token still works alongside it" 200 \
  -H "Authorization: Bearer $TOK" "$G/bff/v1/loyalty/settings"

say "retries"
CODES=$(for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -m 5 -w '%{http_code} ' "$G/bff/v1/retried/x"
done)
[ "$CODES" = "200 200 200 200 200 200 " ] \
  && ok "a connect failure is retried onto a live backend" || bad "retry failed: $CODES"

# Nothing was delivered on a connect failure, so a POST is safe to repeat.
CODES=$(for i in 1 2 3 4; do
  curl -s -o /dev/null -m 5 -X POST -d 'x=1' -w '%{http_code} ' "$G/bff/v1/retried/x"
done)
[ "$CODES" = "200 200 200 200 " ] \
  && ok "a POST is retried when nothing was delivered" || bad "POST retry failed: $CODES"

# Without a retry policy the same pool surfaces the failure.
FAILED=$(for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -m 5 -w '%{http_code}\n' "$G/bff/v1/unretried/x"
done | grep -c 502 || true)
[ "$FAILED" -gt 0 ] \
  && ok "without a policy the failure is surfaced" || bad "unretried route never failed"

say "CORS"
acao() { curl -s -D- -o /dev/null -m 5 -H "Origin: $1" "$G/bff/v1$2" | grep -i '^access-control-allow-origin:' | tr -d '\r'; }

[ -n "$(acao https://app.example.com /products/42)" ] \
  && ok "an allowed origin is echoed" || bad "allowed origin got no ACAO"
[ -z "$(acao https://evil.example.net /products/42)" ] \
  && ok "an unlisted origin gets nothing" || bad "unlisted origin was allowed"
[ -z "$(acao https://app.example.com.evil.net /products/42)" ] \
  && ok "a lookalike suffix does not match" || bad "lookalike origin was allowed"
[ -n "$(acao https://pr-1.preview.example.com /products/42)" ] \
  && ok "a wildcard sub-domain matches" || bad "wildcard sub-domain rejected"
[ -z "$(acao https://evilpreview.example.com /products/42)" ] \
  && ok "the wildcard dot boundary holds" || bad "wildcard matched across the boundary"
[ -z "$(acao http://app.example.com /products/42)" ] \
  && ok "the scheme is part of the origin" || bad "http matched an https origin"

curl -s -D- -o /dev/null -m 5 -H "Origin: https://app.example.com" "$G/bff/v1/products/42" \
  | grep -qi '^vary:.*origin' \
  && ok "an echoed origin sets Vary" || bad "Vary: Origin missing — a cache could cross origins"

PRE=$(curl -s -D- -o /dev/null -m 5 -X OPTIONS -H "Origin: https://app.example.com" \
  -H "Access-Control-Request-Method: GET" "$G/bff/v1/products/42")
echo "$PRE" | grep -q '204' \
  && ok "preflight is answered by the gateway" || bad "preflight was not answered"
echo "$PRE" | grep -qi '^access-control-allow-methods:' \
  && ok "preflight lists the allowed methods" || bad "preflight had no methods"

# A preflight must be answered without credentials: a browser sends none, so
# requiring a token would break every cross-origin call to a protected route.
curl -s -o /dev/null -m 5 -w '%{http_code}' -X OPTIONS -H "Origin: https://app.example.com" \
  -H "Access-Control-Request-Method: GET" "$G/bff/v1/loyalty/settings" | grep -q 204 \
  && ok "preflight on an authenticated route needs no token" || bad "preflight required auth"

# Both 404s must look identical, or a page can enumerate the deny-list by
# checking which one carries the cross-origin header.
DENIED=$(acao https://app.example.com /loyalty/wallets)
UNKNOWN=$(acao https://app.example.com /no/such/path)
[ "$DENIED" = "$UNKNOWN" ] \
  && ok "denied and unknown paths are indistinguishable" || bad "the deny-list is enumerable via CORS"

say "rate limiting"
CODES=$(for i in 1 2 3 4 5; do
  curl -s -o /dev/null -m 5 -H "X-Forwarded-For: 203.0.113.7" -w '%{http_code} ' "$G/bff/v1/limited/x"
done)
[ "$CODES" = "200 200 200 429 429 " ] \
  && ok "requests over the limit are refused" || bad "unexpected sequence: $CODES"

curl -s -D- -o /dev/null -m 5 -H "X-Forwarded-For: 203.0.113.7" "$G/bff/v1/limited/x" \
  | grep -qi '^retry-after:' \
  && ok "429 says when to retry" || bad "429 carried no Retry-After"

python3 "$E2E/assert_json.py" "$WORK/body" statusCode 429 > /dev/null 2>&1 || true
expect "a different client has its own quota" 200 \
  -H "X-Forwarded-For: 198.51.100.9" "$G/bff/v1/limited/x"

# The bypass that matters: only the trusted hop may decide the key, so varying
# the client-supplied prefix must not hand out a fresh quota.
CODES=$(for i in 1 2 3; do
  curl -s -o /dev/null -m 5 -H "X-Forwarded-For: 10.0.0.$i, 203.0.113.7" -w '%{http_code} ' "$G/bff/v1/limited/x"
done)
[ "$CODES" = "429 429 429 " ] \
  && ok "a forged XFF prefix cannot mint a new quota" || bad "rate limit bypassed: $CODES"

expect "an unlimited route is unaffected" 200 "$G/bff/v1/products/42"

say "metrics"
M=http://127.0.0.1:9390
curl -s -m 5 "$M/" > "$WORK/metrics.txt"
grep -q '^gateway_requests_total' "$WORK/metrics.txt" \
  && ok "requests are counted" || bad "gateway_requests_total missing"
grep -q '^gateway_routes ' "$WORK/metrics.txt" \
  && ok "route count is exported" || bad "gateway_routes missing"
grep -q 'gateway_pool_backends{state="healthy",upstream="pooled"}' "$WORK/metrics.txt" \
  && ok "pool health is exported" || bad "gateway_pool_backends missing"

# A label fed from the request would be a memory-exhaustion bug: each distinct
# value allocates a permanent time series. Invented methods must collapse.
for v in AAA BBB CCC DDD EEE FFF; do
  curl -s -o /dev/null -m 5 -X "$v" "$G/bff/v1/products/42"
done
curl -s -m 5 "$M/" > "$WORK/metrics2.txt"
INVENTED=$(grep -c 'method="AAA"\|method="BBB"\|method="CCC"' "$WORK/metrics2.txt" || true)
[ "$INVENTED" = "0" ] \
  && ok "invented methods cannot create time series" || bad "unbounded method label: $INVENTED"
grep -q 'method="OTHER"' "$WORK/metrics2.txt" \
  && ok "they collapse into OTHER" || bad "OTHER bucket missing"

# No label may carry a path, a request id or a subject.
if grep -E '^gateway_[a-z_]+\{[^}]*(path|request_id|subject|user_id)=' "$WORK/metrics2.txt" > /dev/null; then
  bad "a high-cardinality label leaked into metrics"
else
  ok "no request-derived label is exported"
fi

say "route hot reload"
cp "$E2E/routes.yml" "$WORK/routes.backup"
cat >> "$E2E/routes.yml" <<'EOF'
  - id: hotreload
    prefix: hotreload
    upstream: echo
    methods: [GET]
EOF
sleep 4
expect "new route served without a restart" 200 "$G/bff/v1/hotreload/1"
# ops/internal is a machine route and is NOT on the deny-list. A reload
# that publishes the unpartitioned table would expose it on the public port.
expect "machine path still absent on public after reload" 404 "$G/bff/v1/ops/internal/x"
expect "machine path still served internally after reload" 200 \
  -H "x-internal-api-key: $INTERNAL_API_KEY" "$I/ops/internal/x"

# A route naming an upstream that does not exist must be rejected wholesale:
# publishing it would turn every request it matched into a 502.
cp "$WORK/routes.backup" "$E2E/routes.yml"
cat >> "$E2E/routes.yml" <<'EOF'
  - id: ghost
    prefix: ghost
    upstream: does-not-exist
    methods: [GET]
EOF
sleep 4
expect "route naming an unknown upstream is rejected" 404 "$G/bff/v1/ghost/1"
expect "the previous table keeps serving" 200 "$G/bff/v1/products/42"

echo 'not: [valid yaml' > "$E2E/routes.yml"
sleep 4
expect "bad route file keeps the old table" 200 "$G/bff/v1/products/42"
cp "$WORK/routes.backup" "$E2E/routes.yml"

say "filter interaction regressions"
if python3 "$E2E/regressions.py" "$BIN/lagos"; then
  ok "filter interaction regression suite"
else
  bad "filter interaction regression suite"
fi

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
