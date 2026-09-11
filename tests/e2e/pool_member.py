"""A pool member that names itself, and can be made to fail its health check.

Started twice on different ports. Touching `unhealthy-<port>` in the working
directory makes /health answer 503, which is how the e2e proves the balancer
actually takes a backend out of rotation.
"""
import http.server
import os
import sys

PORT = int(sys.argv[1])
NAME = sys.argv[2]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health" and os.path.exists(f"unhealthy-{PORT}"):
            self.send_response(503)
            self.end_headers()
            self.wfile.write(b"unhealthy")
            return
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.end_headers()
        self.wfile.write(NAME.encode())

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
