#!/usr/bin/env bash
# Run on a Linux Docker host after building examples/extension. Proves that a
# request reaches the upstream with the header produced by the custom code.
set -euo pipefail

image=${1:?usage: tests/extension-smoke.sh IMAGE}
container_name="lagos-extension-smoke-$$"
upstream_pid=

cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
  if [ -n "$upstream_pid" ]; then
    kill "$upstream_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

python3 tests/e2e/echo_upstream.py &
upstream_pid=$!
docker run -d --rm --name "$container_name" --network host \
  -e USERS_URL=http://127.0.0.1:9401 "$image" >/dev/null

response=
for _ in {1..30}; do
  if response=$(curl -fsS --max-time 2 http://127.0.0.1:8080/users 2>/dev/null); then
    break
  fi
  sleep 0.5
done

if [ -z "$response" ]; then
  docker logs "$container_name"
  echo "extension smoke: gateway did not answer" >&2
  exit 1
fi

printf '%s' "$response" | python3 -c '
import json, sys
request = json.load(sys.stdin)
assert request["headers"].get("x-lagos-example") == "custom", request
print("extension smoke: upstream received x-lagos-example: custom")
'
