"""Mint RS256 JWTs the way Google's securetoken service does, for e2e tests.

Usage: mint.py [valid|expired|wrongaud|evilkey|algnone|otherproject|nocompany|legacyoutage|withcompany]
"""
import base64, json, subprocess, sys, time


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


mode = sys.argv[1] if len(sys.argv) > 1 else "valid"
now = int(time.time())

header = {"alg": "RS256", "typ": "JWT", "kid": "testkid"}
payload = {
    "iss": "https://securetoken.google.com/demo-project",
    "aud": "demo-project",
    "sub": "4821",
    "auth_time": now - 10,
    "iat": now - 10,
    "exp": now + 3600,
    "user_type": "V",
    "email": "merchant@example.com",
}
key = "key.pem"

if mode == "expired":
    payload["iat"], payload["exp"] = now - 7200, now - 3600
elif mode == "wrongaud":
    payload["aud"] = "some-other-project"
elif mode == "otherproject":
    payload["iss"] = "https://securetoken.google.com/some-other-project"
elif mode == "nocompany":
    payload["sub"] = "5000"
elif mode == "legacyoutage":
    payload["sub"] = "5555"
elif mode == "withcompany":
    # Carries the claim a declarative `bind:` compares against.
    payload["company_id"] = 11
elif mode == "evilkey":
    key = "evil.pem"
elif mode == "algnone":
    header["alg"] = "none"
    print(f"{b64(json.dumps(header).encode())}.{b64(json.dumps(payload).encode())}.")
    raise SystemExit

signing_input = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(payload).encode())}"
sig = subprocess.run(
    ["openssl", "dgst", "-sha256", "-sign", key],
    input=signing_input.encode(), capture_output=True, check=True,
).stdout
print(f"{signing_input}.{b64(sig)}")
