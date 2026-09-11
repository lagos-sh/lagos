"""Stand-in for Google's x509 certificate endpoint."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

CERT = open("cert.pem").read()

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"testkid": CERT}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("cache-control", "public, max-age=3600")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass

HTTPServer(("127.0.0.1", 9402), H).serve_forever()
