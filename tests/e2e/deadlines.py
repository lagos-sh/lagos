"""Absolute exchange-deadline regressions using temporary loopback fixtures."""

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

from regressions import Checks, Fixture, free_port


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path.endswith("/slow"):
            time.sleep(0.5)
        if self.path.endswith("/stream"):
            self.send_response(200)
            self.send_header("content-length", "100")
            self.end_headers()
            try:
                for _ in range(100):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.03)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
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
    port, metrics = free_port(), free_port()
    config = {
        "server": {"listen": f"127.0.0.1:{port}", "graceful_shutdown": "1s"},
        "timeouts": {"request_total": "150ms", "downstream_read": "5s"},
        "upstreams": {"origin": f"http://127.0.0.1:{origin.server_port}"},
        "observability": {"metrics": {"listen": f"127.0.0.1:{metrics}"}},
        "routes": {"public": [{"prefix": "/deadline", "upstream": "origin",
                                 "concurrency": {"max": 1}}]},
    }
    path = work / "gateway.yml"
    path.write_text(json.dumps(config))
    checks = Checks()
    with (work / "gateway.log").open("w") as log:
        proc = subprocess.Popen([str(binary), "run", str(path)], stdout=log, stderr=log)
        def request(path, target=port):
            connection = http.client.HTTPConnection("127.0.0.1", target, timeout=3)
            try:
                connection.request("GET", path)
                response = connection.getresponse()
                return response.status, response.read()
            finally:
                connection.close()
        try:
            until = time.monotonic() + 30
            while True:
                if proc.poll() is not None:
                    raise AssertionError((work / "gateway.log").read_text())
                try:
                    if request("/deadline/fast")[0] == 200:
                        break
                except (OSError, http.client.HTTPException):
                    pass
                if time.monotonic() > until:
                    raise AssertionError("deadline fixture startup timed out")
                time.sleep(0.05)
            began = time.monotonic()
            closed = False
            try:
                request("/deadline/slow")
            except (OSError, http.client.HTTPException):
                closed = True
            checks.check(closed and time.monotonic() - began < 2,
                         "absolute deadline closes a stalled exchange")
            checks.check(request("/deadline/fast")[0] == 200,
                         "deadline cancellation releases the route concurrency slot")
            partial = b""
            try:
                request("/deadline/stream")
            except http.client.IncompleteRead as error:
                partial = error.partial
            checks.check(0 < len(partial) < 100,
                         "steady streaming progress cannot reset the absolute deadline")
            with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
                connection.sendall(b"GET /deadline/fast HTTP/1.1\r\nHost: test\r\n")
                time.sleep(0.3)
                checks.check(connection.recv(1) == b"", "total budget includes incomplete request headers")
            exposition = request("/metrics", metrics)[1].decode()
            count = next(float(line.split()[1]) for line in exposition.splitlines()
                         if line.startswith("gateway_request_deadlines_total "))
            checks.check(count >= 3, "absolute deadline closures have a dedicated metric")
            print(f"{checks.passed} absolute-deadline checks passed", flush=True)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
            origin.shutdown()
            origin.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="lagos-deadlines-") as directory:
        run(pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(directory))
