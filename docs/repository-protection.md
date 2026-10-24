# Repository protection

State of `lagos-sh/lagos` as read through the GitHub API on 2026-10-24. Nothing
here has been applied: changing repository settings needs a maintainer with
admin rights to run the steps below.

| Setting | Observed | Recommended |
| --- | --- | --- |
| `main` branch protection / rulesets | none | ruleset below |
| Release tags `v*` | unprotected | tag ruleset below |
| Default `GITHUB_TOKEN` permissions | `read` | keep |
| Actions may approve PRs | no | keep |
| Require actions pinned to a full SHA | off | on (every workflow is pinned) |
| Release environment | none | `release` with required reviewers |
| Secret scanning + push protection | off | on (free for public repositories) |
| Dependabot alerts | on | keep |
| Dependabot security updates | off | on |

## 1. Protect `main`

Required checks are the job names CI reports on a pull request today:
`check`, `Docker starters`, and the four `native / <target>` builds.

```sh
gh api -X POST repos/lagos-sh/lagos/rulesets --input - <<'JSON'
{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "bypass_actors": [],
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "pull_request", "parameters": {
      "required_approving_review_count": 1,
      "dismiss_stale_reviews_on_push": true,
      "require_code_owner_review": false,
      "require_last_push_approval": true,
      "required_review_thread_resolution": true
    }},
    {"type": "required_status_checks", "parameters": {
      "strict_required_status_checks_policy": true,
      "required_status_checks": [
        {"context": "check"},
        {"context": "Docker starters"},
        {"context": "native / x86_64-unknown-linux-musl"},
        {"context": "native / aarch64-unknown-linux-musl"},
        {"context": "native / x86_64-apple-darwin"},
        {"context": "native / aarch64-apple-darwin"}
      ]
    }}
  ]
}
JSON
```

A pull request author cannot approve their own pull request. With a single
maintainer, either set `required_approving_review_count` to `0` (pull request
and checks still required) or add that maintainer to `bypass_actors` with
`"bypass_mode": "pull_request"` so an exception is visible on the PR rather
than silent. Apply the same ruleset to `dev` by adding `refs/heads/dev` to
`include` if `dev` is a release source.

## 2. Protect release tags

A pushed `v*` tag starts the release workflow, which publishes images and
GitHub releases. Restrict who can create, move or delete those tags:

```sh
gh api -X POST repos/lagos-sh/lagos/rulesets --input - <<'JSON'
{
  "name": "release tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
  "bypass_actors": [
    {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}
  ],
  "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}]
}
JSON
```

`actor_id: 5` is the built-in admin repository role: only admins can create
release tags, and nobody can move a published one without that bypass.

## 3. Release environment (optional, needs a workflow change)

To require a human approval before anything is published, create an
environment with reviewers, then add `environment: release` to the `build`,
`merge` and `downloads` jobs in `.github/workflows/release.yml`:

```sh
gh api -X PUT repos/lagos-sh/lagos/environments/release --input - <<'JSON'
{"reviewers": [{"type": "User", "id": <maintainer user id>}],
 "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
JSON
gh api -X POST repos/lagos-sh/lagos/environments/release/deployment-branch-policies \
  -f name='v*' -f type=tag
```

The workflow is deliberately not changed yet: referencing an environment that
does not exist creates it unprotected, which adds a step without adding a gate.

## 4. Actions and scanning

```sh
gh api -X PUT repos/lagos-sh/lagos/actions/permissions \
  -F enabled=true -f allowed_actions=all -F sha_pinning_required=true
gh api -X PATCH repos/lagos-sh/lagos --input - <<'JSON'
{"security_and_analysis": {
  "secret_scanning": {"status": "enabled"},
  "secret_scanning_push_protection": {"status": "enabled"}}}
JSON
gh api -X PUT repos/lagos-sh/lagos/automated-security-fixes
```

Dependabot already proposes action SHA updates weekly (`.github/dependabot.yml`),
so SHA pinning stays current without hand edits.

## Verifying release artifacts

Releases from this workflow carry GitHub build provenance:

```sh
gh attestation verify lagos-<version>-x86_64-unknown-linux-musl.tar.gz -R lagos-sh/lagos
gh attestation verify oci://ghcr.io/lagos-sh/lagos:<version> -R lagos-sh/lagos
```

Archives also ship with a checksum file; `install.sh` checks it before
installing.
