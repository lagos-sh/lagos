"""Mint RS256 JWTs for the generic OIDC issuer used in the e2e suite.

Usage: oidc_mint.py [valid|wrongaud|wrongiss|expired|algnone|noclaim]
"""
import base64
import json
import subprocess
import sys
import time


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


mode = sys.argv[1] if len(sys.argv) > 1 else "valid"
now = int(time.time())
header = {"alg": "RS256", "typ": "JWT", "kid": "test-key-1"}
payload = {
    "iss": "https://issuer.test",
    "aud": "e2e-api",
    "sub": "user-9",
    "iat": now - 10,
    "exp": now + 3600,
    "role": "admin",
}

if mode == "wrongaud":
    payload["aud"] = "someone-else"
elif mode == "wrongiss":
    payload["iss"] = "https://other.test"
elif mode == "expired":
    payload["iat"], payload["exp"] = now - 7200, now - 3600
elif mode == "algnone":
    header["alg"] = "none"
elif mode == "noclaim":
    payload.pop("role")

signing_input = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(payload).encode())}"
if mode == "algnone":
    print(f"{signing_input}.")
    raise SystemExit

sig = subprocess.run(
    ["openssl", "dgst", "-sha256", "-sign", "oidc_key.pem"],
    input=signing_input.encode(),
    capture_output=True,
).stdout
print(f"{signing_input}.{b64(sig)}")
