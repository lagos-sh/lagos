"""SIGTERM drains in-flight requests, refuses new ones and exits on time."""

import http.client
import http.server
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
import time

from regressions import Checks, Fixture, free_port


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path.endswith("/slow"):
            time.sleep(1.5)
        self.send_response(200)
        self.send_header("content-length", "2")
        self.end_headers()
        try:
            self.wfile.write(b"ok")
        except (BrokenPipeError, ConnectionResetError):
            pass


def run(binary, work):
    origin = Fixture(("127.0.0.1", 0), Origin)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    port = free_port()
    drain = 3
    config = {
        "server": {"listen": f"127.0.0.1:{port}", "graceful_shutdown": f"{drain}s"},
        "upstreams": {"origin": f"http://127.0.0.1:{origin.server_port}"},
        "routes": {"public": [{"prefix": "/drain", "upstream": "origin"}]},
    }
    path = work / "gateway.yml"
    path.write_text(json.dumps(config))
    checks = Checks()

    def request(path, timeout=5):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    with (work / "gateway.log").open("w") as log:
        proc = subprocess.Popen([str(binary), "run", str(path)], stdout=log, stderr=log)
        try:
            until = time.monotonic() + 30
            while True:
                if proc.poll() is not None:
                    raise AssertionError((work / "gateway.log").read_text())
                try:
                    if request("/drain/fast", timeout=1)[0] == 200:
                        break
                except (OSError, http.client.HTTPException):
                    pass
                if time.monotonic() > until:
                    raise AssertionError("shutdown fixture startup timed out")
                time.sleep(0.05)

            inflight = {}

            def slow():
                try:
                    inflight["result"] = request("/drain/slow")
                except (OSError, http.client.HTTPException) as error:
                    inflight["result"] = error

            worker = threading.Thread(target=slow)
            worker.start()
            time.sleep(0.4)
            signalled = time.monotonic()
            proc.terminate()
            time.sleep(0.3)
            try:
                request("/drain/fast", timeout=1)
                refused = False
            except (OSError, http.client.HTTPException):
                refused = True
            checks.check(refused, "new connections are refused once SIGTERM arrives")
            worker.join(timeout=10)
            checks.check(inflight.get("result") == (200, b"ok"),
                         "a request in flight at SIGTERM completes")
            try:
                code = proc.wait(timeout=drain + 5)
            except subprocess.TimeoutExpired:
                code = None
            elapsed = time.monotonic() - signalled
            checks.check(code is not None and elapsed < drain + 3,
                         f"the gateway exits within graceful_shutdown ({elapsed:.1f}s, limit {drain}s)")
            print(f"{checks.passed} shutdown checks passed", flush=True)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)
            origin.shutdown()
            origin.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="lagos-shutdown-") as directory:
        run(pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(directory))
