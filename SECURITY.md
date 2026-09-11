# Security policy

Lagos is a trust boundary. Every service behind it has stopped checking who the
caller is, because the gateway already did — so a bug here is not a bug in one
application, it is a bug in the thing all of them are relying on. Please report
anything you find.

## Reporting a vulnerability

**Use [GitHub's private vulnerability reporting](https://github.com/lagos-sh/lagos/security/advisories/new).**
It opens a channel visible only to the maintainers, and it works without
exposing an email address or asking you to encrypt anything.

Please do **not** open a public issue for a suspected vulnerability. A public
issue describing an authentication bypass is a working exploit handed to
everyone running the gateway before there is a fix to run.

A useful report has: what you sent, what came back, what you expected instead,
and the configuration it happened under. A failing `curl` is worth more than a
paragraph of description.

### What to expect

This is an early-stage project with a small maintainer team, so these are honest
expectations rather than a service level agreement:

| | |
|---|---|
| Acknowledgement | within a week |
| Assessment, and whether it is in scope | within two weeks |
| Fix for a confirmed critical issue | as fast as it can be done properly |

There is no bug bounty. Credit in the advisory and the release notes is offered
for every valid report, and declined gracefully if you would rather stay
anonymous.

## Supported versions

Pre-1.0, only `main` is supported. There are no maintenance branches and no
backports — fixes land on `main` and are released from there. If you are running
a tagged version, be ready to move forward to get a fix.

## What counts as a vulnerability

Lagos makes a small number of specific promises. A way to break any of them is a
vulnerability, and these are the ones worth attacking:

- **Identity cannot be forged.** A client must not be able to make an upstream
  see identity headers it did not earn — not by sending them directly, not
  through casing or duplication tricks, not through header smuggling.
- **A refused request stays refused.** No path encoding, traversal sequence,
  normalization difference or routing quirk should reach an upstream that the
  deny-list or allowlist was supposed to protect.
- **A token is verified properly.** Expired, wrong-audience, wrong-issuer,
  foreign-key, `alg:none`, and swapped-payload tokens must all fail.
- **Credentials do not leak.** Injected upstream credentials must never appear
  in a response, a log line, an error body or a trace.
- **One caller's response is not served to another.** Anything that makes the
  response cache return a personalised or authorized response to a different
  caller is critical.
- **Refusals are indistinguishable.** A caller must not be able to tell a
  deny-listed path from a path that does not exist — that difference is how a
  deny-list gets mapped.
- **Limits hold.** A way to bypass rate limiting, or to make the gateway consume
  unbounded memory with a well-formed request, is in scope.

## What does not count

- **Misconfiguration.** Setting `trusted_proxies` higher than the number of
  proxies actually in front of the gateway lets a client forge its own address.
  That is documented, validated where it can be, and still the operator's
  decision — it is not a vulnerability in Lagos. The same applies to allowlisting
  a header that should not have been allowlisted, or enabling
  `cache_authenticated` on a route whose upstream sends wrong `Cache-Control`.
- **Volumetric denial of service.** Enough traffic will exhaust any gateway.
  A single request that costs disproportionate memory or CPU *is* in scope; a
  million ordinary ones are not.
- **Vulnerabilities in dependencies**, unless Lagos's use of them is what makes
  the issue exploitable. Report those upstream — though telling us as well is
  appreciated, so the dependency can be bumped.
- **Anything that requires write access to the configuration.** Whoever can edit
  `gateway.yml` already decides what the gateway does.

## Disclosure

Coordinated. We will agree a date with you, publish a GitHub advisory with a
CVE, and credit you unless you would rather we did not. If a report goes
unanswered for 90 days, publish — an unresponsive maintainer is not a reason to
leave users unaware.
