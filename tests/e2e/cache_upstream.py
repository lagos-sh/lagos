"""An upstream that numbers every response, so a cache hit is visible.

The path selects the `Cache-Control` it sends back, which is what lets the
suite check that the RFC rules are actually applied rather than assumed.
"""
import http.server
import itertools

counter = itertools.count(1)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        n = next(counter)
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        if self.path.startswith("/cacheable"):
            self.send_header("cache-control", "max-age=60")
        elif self.path.startswith("/private"):
            self.send_header("cache-control", "private")
        elif self.path.startswith("/nostore"):
            self.send_header("cache-control", "no-store")
        body = f"origin-{n}".encode()
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", 9406), Handler).serve_forever()
