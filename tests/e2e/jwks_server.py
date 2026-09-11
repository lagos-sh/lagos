"""Serve an RFC 7517 JWKS, the way any OIDC provider does.

Deliberately not Google's certificate-map format: this fixture is what proves
the gateway verifies tokens from a standard issuer, not only from Firebase.
"""
import base64
import http.server
import json
import subprocess


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


modulus_hex = subprocess.run(
    ["openssl", "rsa", "-pubin", "-in", "oidc_pub.pem", "-noout", "-modulus"],
    capture_output=True,
    text=True,
).stdout.strip().split("=")[1]

JWKS = json.dumps(
    {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "test-key-1",
                "n": b64u(bytes.fromhex(modulus_hex)),
                "e": b64u((65537).to_bytes(3, "big")),
            }
        ]
    }
).encode()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("cache-control", "max-age=300")
        self.end_headers()
        self.wfile.write(JWKS)

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", 9405), Handler).serve_forever()
