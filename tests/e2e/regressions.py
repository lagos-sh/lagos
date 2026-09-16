"""Regression checks across gateway filters, cache, auth and upstream health.

Usage: python3 tests/e2e/regressions.py /path/to/lagos
Uses only the Python standard library and openssl. All fixtures use temporary
files and loopback listeners; no configuration in the checkout is modified.
"""

import base64
import collections
import http.client
import http.server
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Fixture(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        if not isinstance(sys.exc_info()[1], (ConnectionResetError, BrokenPipeError)):
            super().handle_error(request, client_address)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST

    def respond(self):
        path = urllib.parse.urlsplit(self.path).path
        with self.server.count_lock:
            self.server.counts[path] += 1
            count = self.server.counts[path]
        body = self.rfile.read(int(self.headers.get("content-length", "0"))).decode()
        response = {
            "origin": count,
            "language": self.headers.get("accept-language"),
            "body": body,
            "subject": self.headers.get("x-auth-subject"),
            "port": self.server.server_port,
        }
        status = 500 if path == "/cb/fail" else 200
        if path == "/hc" and not self.headers.get("host"):
            status = 400
        if path == "/member-hc" and self.headers.get("host") != self.server.health_host:
            status = 400
        if path == "/jwks":
            response = self.server.jwks
        if path == "/bound":
            response["merchantId"] = dict(urllib.parse.parse_qsl(
                urllib.parse.urlsplit(self.path).query)).get("merchantId")
        self.send_response(status)
        if path == "/vary":
            self.send_header("vary", "accept-language")
        elif path == "/star":
            self.send_header("vary", "accept-language")
            self.send_header("vary", "*")
        elif path == "/varyidentity":
            self.send_header("vary", "x-auth-subject")
        if path == "/authcache" and self.headers.get("x-auth-subject"):
            self.send_header("cache-control", "private, no-store")
        elif path in ("/authshared", "/varyidentity"):
            self.send_header("cache-control", "public, max-age=60")
            if path == "/authshared":
                response["subject"] = None
        else:
            self.send_header("cache-control", "max-age=60")
        data = json.dumps(response).encode()
        if path == "/large":
            data += b" " * 8192
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Checks:
    def __init__(self):
        self.passed = 0

    def check(self, condition, description):
        if not condition:
            raise AssertionError(description)
        self.passed += 1
        print(f"  ✓ {description}", flush=True)


def run(binary, work):
    key = work / "key.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(key), "2048"], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    modulus = subprocess.check_output(
        ["openssl", "rsa", "-in", str(key), "-noout", "-modulus"],
        stderr=subprocess.DEVNULL).decode().strip().split("=")[1]
    jwks = {"keys": [{"kty": "RSA", "kid": "regression", "use": "sig",
                      "n": b64(bytes.fromhex(modulus)), "e": "AQAB"}]}

    def token(subject="11", issuer="https://regression.test", issued_at="valid"):
        now = int(time.time())
        payload = {"iss": issuer, "sub": subject, "aud": "regression-api", "exp": now + 3600}
        if issued_at != "missing":
            payload["iat"] = now - 10 if issued_at == "valid" else issued_at
        message = b64(json.dumps({"alg": "RS256", "kid": "regression"}).encode())
        message += "." + b64(json.dumps(payload).encode())
        signature = subprocess.check_output(
            ["openssl", "dgst", "-sha256", "-sign", str(key)], input=message.encode())
        return "Bearer " + message + "." + b64(signature)

    servers, threads, proc = [], [], None
    log = (work / "gateway.log").open("w")
    checks = Checks()
    try:
        for _ in range(2):
            server = Fixture(("127.0.0.1", 0), Handler)
            server.jwks = jwks
            server.counts = collections.Counter()
            server.count_lock = threading.Lock()
            servers.append(server)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        first, second = [server.server_port for server in servers]
        servers[0].health_host = f"127.0.0.1:{first}"
        servers[1].health_host = f"127.0.0.1:{second}"
        port, metrics = free_port(), free_port()
        origin = f"http://127.0.0.1:{first}"
        groups = {
            "public": [
                {"prefix": f"/{path}", "upstream": "origin", "cache": True}
                for path in ("vary", "star", "write", "large", "cb/cached")
            ] + [
                {"id": "swap", "prefix": "/swap", "upstream": "origin", "cache": True},
                {"prefix": "/healthprobe", "upstream": "health"},
                {"prefix": "/memberprobe", "upstream": "memberhealth"},
                {"prefix": "/mixedprobe", "upstream": "mixedhealth"},
                {"prefix": "/cb/fail", "upstream": "cb"},
                {"prefix": "/cb/limited", "upstream": "cb", "rate_limit": {
                    "requests": 1, "interval": "60s", "key": "route"}},
            ],
            "optional": [
                {"prefix": f"/{path}", "upstream": "origin", "cache": True,
                 "cache_authenticated": True}
                for path in ("authcache", "authshared", "varyidentity")
            ],
            "authenticated": [
                {"prefix": "/bound", "upstream": "origin",
                 "bind": {"query.merchantId": "identity.subject"}},
                {"prefix": "/boundheader", "upstream": "origin",
                 "bind": {"header.x-merchant-id": "identity.subject"}},
                {"prefix": "/identity", "upstream": "pool"},
            ],
        }
        for route in groups["public"]:
            if route["prefix"] == "/cb/cached":
                route["upstream"] = "cb"
        route_file = work / "routes.yml"

        def publish_routes():
            staged = work / "routes.next"
            staged.write_text(json.dumps(groups))
            staged.replace(route_file)

        publish_routes()
        config = {
            "server": {"listen": f"127.0.0.1:{port}", "graceful_shutdown": "1s"},
            "observability": {"metrics": {"listen": f"127.0.0.1:{metrics}",
                                           "pool_sample_interval": "100ms"}},
            "cache": {"max_size": "64KiB", "max_object_size": "4KiB"},
            "auth": {"jwt": [{"issuer": "https://regression.test", "audience": ["regression-api"],
                               "jwks_url": origin + "/jwks"}]},
            "forward": {"authorization": False, "headers": ["x-merchant-id"]},
            "cors": {"origins": ["https://app.test"]},
            "upstreams": {
                "origin": origin,
                "second": f"http://127.0.0.1:{second}",
                "pool": {"targets": [origin, f"http://127.0.0.1:{second}"],
                         "balance": "consistent", "hash_on": "identity"},
                "cb": {"url": origin, "circuit_breaker": {
                    "failures": 1, "cooldown": "200ms", "successes_to_close": 1}},
                "health": {"url": origin, "health_check": {
                    "path": "/hc", "interval": "100ms", "unhealthy_after": 1}},
                "memberhealth": {"targets": [origin, f"http://127.0.0.1:{second}"],
                                 "health_check": {"path": "/member-hc", "interval": "100ms",
                                                  "unhealthy_after": 1}},
                "mixedhealth": {"targets": [f"https://127.0.0.1:{first}",
                                             f"http://127.0.0.1:{second}"],
                                "health_check": {"path": "/member-hc", "interval": "100ms",
                                                 "timeout": "200ms", "unhealthy_after": 1}},
            },
            "routes": {"file": str(route_file), "reload": "100ms"},
        }
        config_path = work / "gateway.yml"
        config_path.write_text(json.dumps(config))
        proc = subprocess.Popen([str(binary), "run", str(config_path)], stdout=log, stderr=log)

        def request(path, headers=None, method="GET", body=None, target=port):
            conn = http.client.HTTPConnection("127.0.0.1", target, timeout=5)
            try:
                # A list permits deliberately duplicated headers.
                if isinstance(headers, list):
                    conn.putrequest(method, path)
                    for name, value in headers:
                        conn.putheader(name, value)
                    conn.endheaders()
                else:
                    conn.request(method, path, body=body, headers=headers or {})
                response = conn.getresponse()
                raw = response.read()
                try:
                    data = json.loads(raw)
                except ValueError:
                    data = raw.decode()
                return response.status, data, response.headers
            finally:
                conn.close()

        def wait_until(predicate, description, timeout=5):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise AssertionError("gateway exited during " + description)
                try:
                    if predicate():
                        return
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(0.05)
            raise AssertionError("timed out: " + description)

        wait_until(lambda: request("/health")[0] == 200, "gateway startup", timeout=30)
        auth = {"authorization": token()}
        checks.check(request("/bound?merchantId=11", auth)[0] == 200, "a unique ownership parameter passes")
        for query in ("merchantId=11&merchantId=12", "merchantId=11&%6derchantId=12",
                      "merchantId=11&merchantId", "merchantId=11&merchantId=11"):
            checks.check(request("/bound?" + query, auth)[0] == 403, "duplicate binding refused: " + query)
        checks.check(request("/boundheader", [*auth.items(), ("x-merchant-id", "11"),
                     ("x-merchant-id", "12")])[0] == 403, "duplicate ownership headers are refused")

        english = request("/vary", {"accept-language": "en", "origin": "https://app.test"})
        french = request("/vary", {"accept-language": "fr"})
        checks.check(english[1]["language"] == "en" and french[1]["language"] == "fr",
                     "Vary selects the requested language")
        checks.check(request("/vary", {"accept-language": "en"})[1] == english[1], "English variant is cached")
        checks.check(request("/vary", {"accept-language": "fr"})[1] == french[1], "French variant is cached")
        varies = ",".join(english[2].get_all("vary")).lower()
        checks.check("accept-language" in varies and "origin" in varies, "CORS preserves upstream Vary")
        checks.check(request("/star")[1] != request("/star")[1], "Vary star is never reused")

        for method in ("POST", "PUT", "PATCH", "DELETE"):
            a = request("/write", method=method, body="first")[1]
            b = request("/write", method=method, body="second")[1]
            checks.check(a["body"] == "first" and b["body"] == "second" and a["origin"] != b["origin"],
                         method + " always reaches the origin")
        large_a, large_b = request("/large"), request("/large")
        checks.check(large_a[0] == large_b[0] == 200 and large_a[1] != large_b[1],
                     "oversized cache objects pass through without storage")

        anonymous = request("/authcache")[1]
        signed_in = request("/authcache", auth)[1]
        checks.check(anonymous["subject"] is None and signed_in["subject"] == "11",
                     "authorized request bypasses an anonymous-only cache hit")
        checks.check(signed_in != request("/authcache", auth)[1], "private authenticated responses remain uncached")
        shared = request("/authshared")[1]
        checks.check(request("/authshared", auth)[1] == shared, "explicitly public responses can still be shared")
        alice = request("/varyidentity", auth)[1]
        bob_auth = {"authorization": token(subject="12"), "x-auth-subject": "11"}
        bob = request("/varyidentity", bob_auth)[1]
        checks.check(alice["subject"] == "11" and bob["subject"] == "12", "Vary uses verified injected identity")
        checks.check(request("/varyidentity", auth)[1] == alice, "identity variant can be reused for its owner")

        for issued_at in ("missing", None, "not-a-timestamp", -1, time.time() + 3600, int(time.time()) + 3600):
            checks.check(request("/identity", {"authorization": token(issued_at=issued_at)})[0] == 401,
                         f"invalid iat refused: {issued_at}")
        peers = set()
        for i in range(32):
            user = {"authorization": token(subject=str(i))}
            peer = request("/identity", user)[1]["port"]
            peers.add(peer)
            if request("/identity", user)[1]["port"] != peer:
                raise AssertionError("identity affinity changed between requests")
        checks.check(peers == {first, second}, "production identity hashing distributes users and stays sticky")

        for i in range(8):
            forged = token(issuer=f"attacker-{i}")
            request("/identity", {"authorization": forged})
        exposition = request("/metrics", target=metrics)[1]
        labels = [line for line in exposition.splitlines() if 'reason="unknown_issuer"' in line]
        checks.check(len(labels) == 1 and labels[0].endswith(" 8") and "attacker-" not in exposition,
                     "forged issuers share one bounded rejection label")
        wait_until(lambda: servers[0].counts["/hc"] >= 2, "health probes")
        checks.check(request("/healthprobe")[0] == 200, "HTTP health checks retain Host")
        wait_until(lambda: all(server.counts["/member-hc"] >= 2 for server in servers),
                   "per-member health probes")
        # Wait for the failing TLS endpoint to be ejected and successful HTTP
        # checks to finish. Initial pool members are provisionally healthy.
        wait_until(lambda: 'gateway_pool_backends{state="unhealthy",upstream="mixedhealth"} 1'
                   in request("/metrics", target=metrics)[1], "mixed-scheme health result")
        peers = {request("/memberprobe")[1]["port"] for _ in range(8)}
        checks.check(peers == {first, second},
                     "health checks use each member's Host authority and port")
        checks.check(all(request("/mixedprobe")[1].get("port") == second for _ in range(4)),
                     "HTTP member stays healthy when the first pool member uses TLS")

        cached = request("/cb/cached")[1]
        checks.check(request("/cb/limited")[0] == 200, "initial quota request reaches the upstream")
        checks.check(request("/cb/fail")[0] == 500, "upstream failure opens the circuit")
        time.sleep(0.25)
        checks.check(request("/cb/limited")[0] == 429, "local rate limiting still refuses a trial")
        checks.check(request("/cb/cached")[1] == cached, "cached responses remain available with an open circuit")
        exposition = request("/metrics", target=metrics)[1]
        checks.check('gateway_circuit_state{upstream="cb"} 2' in exposition,
                     "local refusals and cache hits do not close the circuit")
        checks.check(request("/cb/fail")[0] == 500 and request("/cb/fail")[0] == 503,
                     "a real failed trial reopens the circuit")

        before = request("/swap")[1]
        for route in groups["public"]:
            if route["prefix"] == "/swap":
                route["upstream"] = "second"  # Keep the same route ID.
        publish_routes()
        wait_until(lambda: request("/swap?ready=1")[1].get("port") == second, "route reload")
        after = request("/swap")[1]
        checks.check(before["port"] == first and after["port"] == second,
                     "route reload invalidates entries even when the route ID is unchanged")
        checks.check(request("/swap")[1] == after, "the new route snapshot can populate its own cache")
        print(f"{checks.passed} regression checks passed", flush=True)
    except Exception:
        log.flush()
        print((work / "gateway.log").read_text()[-12000:], file=sys.stderr)
        raise
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)
        log.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="lagos-regressions-") as directory:
        run(pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(directory))
