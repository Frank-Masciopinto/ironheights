# Project threat model and attack surface analysis

This is the threat model for Ironheights itself (the CLI, MCP server, GitHub Action, OpenClaw plugin and release pipeline). It is reviewed for every minor release. For the `ironheights threatmodel` feature that users run on their own agents, see [threatmodel.md](threatmodel.md).

## Assets

- Users' machines and agent configs that Ironheights reads while scanning.
- The trust users place in a verdict (a false "pass" lets a malicious skill in).
- The npm package, GitHub releases and Action tags (supply chain).
- The advisory feed signing key and the `NPM_TOKEN` release secret.

## Attack surface and critical paths

| Entry point                                                                 | Threat                                                                                                 | Mitigation                                                                                                                                                                                                                                                                                 |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Scanned skill files (`scan`, MCP `scan_*`, Action)                          | Untrusted content: ReDoS, path traversal, symlink escape, huge files, prompt injection against `--llm` | Bounded regexes and CodeQL `js/redos`, file count and size limits, symlinks not followed out of the root, rules are pure functions with no network or filesystem access ([CONTRIBUTING.md](../CONTRIBUTING.md)), `--llm`, `--llm-stage`, and `--llm-rewrite` record a model opinion and do not change the grade, verdict, or exit code ([llm.md](llm.md)) |
| Evasion of detection                                                        | Attacker writes a skill that scores clean                                                              | Layered rules, plain-language intent rules, benchmark tracking ([benchmark.md](benchmark.md)), documented limits ([limits.md](limits.md))                                                                                                                                                  |
| Network commands (`fetch`, `safe-install`, `advisories update`, `--online`) | MITM, redirect to a hostile host, poisoned feed                                                        | HTTPS only, host allow list, redirects refused, advisory feed Ed25519 signature checked against a pinned key ([advisories.md](advisories.md))                                                                                                                                              |
| Report output (Markdown, SARIF, PR comments)                                | Markdown/SARIF injection from finding evidence                                                         | Evidence truncated and escaped (backslash, pipe, newline), secrets masked before they reach evidence                                                                                                                                                                                       |
| Runtime guard plugin                                                        | Bypass by anyone who can edit OpenClaw config                                                          | Documented as defense in depth ([guard.md](guard.md))                                                                                                                                                                                                                                      |
| Dependencies                                                                | Malicious or vulnerable package                                                                        | Four runtime dependencies, lockfile, `npm audit` blocking in required CI, Dependabot, no install scripts                                                                                                                                                                                   |
| CI/CD                                                                       | Workflow injection, token theft, tampered release                                                      | Least-privilege `permissions`, actions pinned by SHA, tag input validated, npm provenance plus staged publish with 2FA, Sigstore attestations, SHA256SUMS and CycloneDX SBOM on each release ([release-verification.md](release-verification.md))                                          |

## Out of scope

A local attacker who already controls the user's account, OpenClaw process or Node.js install.

## Review

Re-checked when a new entry point (command, network host, plugin hook) is added, and at least once per minor release.
