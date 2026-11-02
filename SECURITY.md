# Security

## Supported versions and support duration

Ironheights is a 0.x project with one release line at a time.

| Version | Supported |
| ------- | --------- |
| 0.29.x  | yes       |
| < 0.29  | no        |

- **Scope:** the newest published minor line (currently 0.29.x) gets bug fixes and security fixes for the npm package `ironheights`, the GitHub Action, the MCP server and the OpenClaw plugin shipped in this repository.
- **Duration:** a minor line is supported until the next minor release is published on npm. When a new minor ships, the previous line stops receiving security updates the same day; the release is announced in [CHANGELOG.md](CHANGELOG.md) and on the [GitHub releases page](https://github.com/Frank-Masciopinto/ironheights/releases). Fixes are not backported. Upgrade with `npm i -g ironheights@latest`.
- **End of security updates:** any version not marked "yes" in the table above no longer receives security updates.

## Reporting a vulnerability

Report privately through GitHub: open a [private security advisory](https://github.com/Frank-Masciopinto/ironheights/security/advisories/new). Do not open a public issue for a vulnerability. Please include the rule id if one exists, a minimal skill that triggers the issue, and the Ironheights version from `ironheights --version`.

What to expect:

- Acknowledgement within 3 business days.
- An initial assessment and severity rating within 7 days.
- A fix or mitigation for high and critical issues within 30 days, sooner when possible. We will keep you updated in the advisory.
- Coordinated disclosure: we publish the advisory and credit you (if you want) once a fixed release is on npm. Please wait for that before writing about the issue in public, or 90 days from your report, whichever comes first.

There is no bug bounty.

Do not send copies of real secrets or live malware. A synthetic snippet that matches the pattern is enough.

Ironheights does not phone home during `scan`. `fetch`, `safe-install`, `advisories update`, and `--online` are explicit network commands. `scan --llm` and `review` are the other network path, and they are off unless you pass them. Each download command prints the URL before connecting, talks only to `clawhub.ai` or `ironheights.dev` over HTTPS, and refuses redirects. A report you send to GitHub is the disclosure channel. The advisory feed is a signed document you choose to download. It is not telemetry.

## Advisory signatures

The production advisory private key is not in this repository. The CLI rejects a feed whose signature does not match the public key pinned in `src/advisories/pinned-key.ts` (`8424b837422792656e6e7500869395a5afe64bf163baa63acea83f1e97cc2b6c`). See [docs/advisories.md](docs/advisories.md).

## Runtime guard

The optional OpenClaw plugin logs tool calls on the machine and, in `enforce` mode, can block four kinds of call. The plugin runs inside the OpenClaw process. A caller who can change OpenClaw's config, the plugin file, or `~/.ironheights/guard-policy.json` can disable it. Treat that as defense in depth. The limits are in [docs/guard.md](docs/guard.md). The guard does not send the audit log anywhere.

## Optional model review

`scan --llm` and `review` are off unless you pass them. A localhost model server stays on the machine. Any other host needs `--llm-consent` and `IRONHEIGHTS_LLM_API_KEY`. Ironheights redacts common secret shapes before sending and prints the request body first. Redaction can miss a secret. Do not send a skill that contains a live secret to a remote model. Model notes are advisory and can be wrong. A report to GitHub should still use a synthetic snippet, not a live secret.

## Secrets and credentials policy

The project uses these credentials: the `NPM_TOKEN` GitHub Actions secret (npm publish/stage), the workflow `GITHUB_TOKEN`, GitHub OIDC tokens for npm provenance and Sigstore attestations, and the advisory feed signing key.

- **Storage:** secrets live only in GitHub Actions encrypted secrets or the maintainer's password manager and hardware-key-protected accounts. The advisory signing private key is kept offline and is never in this repository. No secret is committed; test fixtures use synthetic `FAKE` values, and GitGuardian plus GitHub secret scanning watch every push.
- **Access:** only the maintainer can read or change repository secrets. Workflows get a secret only in the job that needs it (`NPM_TOKEN` only in `release.yml` `publish`), every workflow defaults to `contents: read`, and secrets are never passed to `pull_request` workflows from forks. npm publishing requires 2FA approval of staged releases.
- **Rotation:** `NPM_TOKEN` is a granular, expiring token rotated at least every 90 days and immediately when a maintainer leaves, a token may have leaked, or a secret-scanning alert fires. OIDC tokens are short-lived per run. The advisory signing key is rotated by shipping a new pinned public key in a release if compromise is suspected.

## Dependency (SCA) policy

- Every pull request runs `npm audit --audit-level=high` in the required `test` jobs and [dependency review](.github/workflows/dependency-review.yml), which fails on any added dependency with a moderate-or-higher advisory, a malware advisory, or a license outside the allow list (permissive OSI licenses only).
- **Remediation thresholds:** critical and high findings that affect the shipped package are fixed within 7 days; moderate within 30 days; low at the next routine update. A license violation is removed before merge.
- **Before every release:** `npm audit` must report no high or critical issues and every open SCA finding must be fixed or recorded as not affecting Ironheights in the VEX document [.vex/ironheights.openvex.json](.vex/ironheights.openvex.json). A finding may only be suppressed through a VEX statement with a justification.
- Dependabot opens weekly update PRs for npm and GitHub Actions.

## Static analysis (SAST) policy

- CodeQL (JavaScript/TypeScript default security queries, [codeql.yml](.github/workflows/codeql.yml)), ESLint and strict TypeScript run on every push and pull request to `main`.
- **Remediation thresholds:** critical and high CodeQL alerts are fixed within 14 days and before the next release; medium within 30 days; low and notes are triaged. A false positive is dismissed in GitHub code scanning with a written reason.
- Pull requests are merged only when every check, including CodeQL, passes.
