# Browser-cookie origin protection

When a browser automatically sends a JWT cookie, authentication alone does not
prove that the user intended a mutation. CORS response headers are a separate
control and do not replace CSRF protection. Applications must still protect
state changes and set appropriate Secure, HttpOnly and SameSite cookie flags.
See [OWASP's CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

Unreleased source offers opt-in gateway protection:

```yaml
auth:
  token_cookies: [access_token]
  cookie_protection:
    origins: [https://app.example.com, https://admin.example.net]
    referer_fallback: false # default
```

For unsafe methods (everything except GET, HEAD, OPTIONS and TRACE), a request
whose gateway credential comes from a cookie must carry one valid, trusted
Origin. Missing, null, malformed, duplicate and untrusted origins receive 403.
Origins are normalized scheme/host/port tuples, with no wildcards, paths or
credentials; default ports compare equivalently. The trusted list is explicit
and is never inferred from client Host or Forwarded headers.

If `referer_fallback: true`, **only absence of Origin** permits checking one
Referer URL's origin. Missing both still rejects. A bad/null/duplicate Origin
cannot be rescued by a trusted Referer. Referrer policies and browser redirects
can suppress these headers; test deployment flows before enabling fallback.

Explicit bearer-token clients retain normal JWT verification and do not need
Origin. A bearer header takes precedence over a token cookie. Duplicate
Authorization fields on token-verifying routes are rejected as ambiguous.
Safe cookie-authenticated requests still verify JWT signatures and claims.
Public routes and application-owned sessions remain the application's concern.
GET/HEAD routes must not mutate state; method-override conventions need their
own application protection.

The policy defaults to absent to preserve existing deployments, which must
continue their application CSRF protection. Enable it for same-site or cross-site
browser apps by listing actual trusted app origins. Cross-site cookie flags and
browser third-party-cookie restrictions remain application/deployment concerns.
This policy does not protect against XSS or an already compromised trusted app.
