"""Upstream that reflects the request the gateway actually sent."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def _reply(self):
        body = json.dumps({
            "path": self.path,
            "method": self.command,
            "headers": {k.lower(): v for k, v in self.headers.items()},
        }, indent=2).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = do_POST = do_PUT = _reply
    def log_message(self, *a): pass

HTTPServer(("127.0.0.1", 9401), H).serve_forever()
