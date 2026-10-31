# OpenSSF Best Practices (passing level): self-assessment draft

Draft answers for https://www.bestpractices.dev. Registration needs a GitHub sign-in by the repo owner; paste these answers there, then add the badge it returns to the README.

| Criterion                                                                                   | Answer                            | Evidence                                                                             |
| ------------------------------------------------------------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------ |
| description_good                                                                            | Met                               | README intro: local-first security scanner that protects any AI bot that installs it |
| interact (how to get/give feedback)                                                         | Met                               | GitHub Issues, CONTRIBUTING.md                                                       |
| contribution / contribution_requirements                                                    | Met                               | CONTRIBUTING.md                                                                      |
| floss_license / floss_license_osi / license_location                                        | Met                               | Apache-2.0, `LICENSE` at repo root                                                   |
| documentation_basics / documentation_interface                                              | Met                               | README, `docs/`, CLI `--help`                                                        |
| sites_https                                                                                 | Met                               | github.com, npmjs.com, ironheights.dev all HTTPS                                     |
| discussion                                                                                  | Met                               | GitHub Issues and PRs, searchable and URL-addressable                                |
| english                                                                                     | Met                               | All docs in English                                                                  |
| maintained                                                                                  | Met                               | Regular releases (0.22.0, Oct 2026)                                                  |
| repo_public / repo_track / repo_interim / repo_distributed                                  | Met                               | Public git repo on GitHub                                                            |
| version_unique / version_semver / version_tags                                              | Met                               | SemVer, git tags `vX.Y.Z`                                                            |
| release_notes / release_notes_vulns                                                         | Met                               | CHANGELOG.md, GitHub releases                                                        |
| report_process / report_tracker / report_responses                                          | Met                               | GitHub Issues; maintainer responds                                                   |
| enhancement_responses / report_archive                                                      | Met                               | Public issue history                                                                 |
| vulnerability_report_process / vulnerability_report_private / vulnerability_report_response | Met                               | SECURITY.md (private reporting)                                                      |
| build / build_common_tools                                                                  | Met                               | `npm run build` (tsup)                                                               |
| build_floss_tools                                                                           | Met                               | Node.js, TypeScript, tsup, all FLOSS                                                 |
| test / test_invocation / test_most / test_continuous_integration                            | Met                               | Vitest with coverage (`npm test`), GitHub Actions CI on every PR                     |
| test_policy / tests_are_added / tests_documented_added                                      | Met                               | CONTRIBUTING.md; PRs add tests                                                       |
| warnings / warnings_fixed / warnings_strict                                                 | Met                               | ESLint + `tsc --noEmit` strict in CI                                                 |
| know_secure_design / know_common_errors                                                     | Met                               | Maintainer builds a security scanner (secrets, injection, supply chain)              |
| crypto\_\*                                                                                  | N/A                               | Project does not implement cryptography; uses Node.js built-in hashing only          |
| delivery_mitm / delivery_unsigned                                                           | Met                               | Delivered via npm over HTTPS; build provenance attestations in release workflow      |
| vulnerabilities_fixed_60_days / vulnerabilities_critical_fixed                              | Met                               | No unpatched known vulnerabilities (Snyk: none; Socket score 81)                     |
| no_leaked_credentials                                                                       | Met                               | No secrets in repo; test fixtures are synthetic `FAKE` values                        |
| static_analysis / static_analysis_fixed                                                     | Met                               | ESLint, TypeScript, OpenSSF Scorecard (code scanning SARIF)                          |
| dynamic_analysis                                                                            | Unmet/N/A for passing (SUGGESTED) | Candidate: Jazzer.js fuzzing of parsers (see below)                                  |

## OSS-Fuzz feasibility

OSS-Fuzz supports JavaScript via Jazzer.js. Effort: about 1 to 2 days to write `FuzzedDataProvider` harnesses for the skill/frontmatter parser, the rule engine over arbitrary file contents, and the MCP manifest parser; plus a `projects/ironheights` PR to google/oss-fuzz (Dockerfile, build.sh, project.yaml). Acceptance is discretionary and favours widely used or critical projects, so with current adoption it may be declined. Alternative now: run Jazzer.js locally or in CI (ClusterFuzzLite) without OSS-Fuzz acceptance. Not submitted.
