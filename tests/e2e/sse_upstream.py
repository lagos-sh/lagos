"""Upstream that emits SSE events slowly, and a path that never responds."""
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        if self.path.startswith("/blackhole"):
            time.sleep(300)          # never answers: exercises the read timeout
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()
        for i in range(5):
            chunk = f"data: event-{i} at {time.time():.3f}\n\n".encode()
            self.wfile.write(b"%X\r\n%s\r\n" % (len(chunk), chunk))
            self.wfile.flush()
            time.sleep(1)
        self.wfile.write(b"0\r\n\r\n"); self.wfile.flush()
    def log_message(self, *a): pass

ThreadingHTTPServer(("127.0.0.1", 9404), H).serve_forever()
