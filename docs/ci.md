# Use Ironheights in CI

The scanner does not use the network. The GitHub Action below is the piece that downloads a pinned npm release so the job can run it. `npx` runs in a temporary directory, so a checkout whose own package is also named `ironheights` does not shadow that pin. It does not take a token or any other secret. SARIF upload uses the workflow's `GITHUB_TOKEN` only when you set `upload-sarif: true`, and the workflow must grant `security-events: write`.

Exit codes are the scanner's:

| Exit | Meaning                                                                                                          |
| ---- | ---------------------------------------------------------------------------------------------------------------- |
| 0    | No findings at or above `--fail-on`, and no skipped file                                                         |
| 1    | Review                                                                                                           |
| 2    | Block                                                                                                            |
| 3    | Incomplete. A file was skipped, or `.git` / `node_modules` was not entered, and the rest was not review or block |
| 64   | Usage error, including a version that is not an exact `x.y.z` pin                                                |
| 70   | Internal error                                                                                                   |

`--allow-skipped` (`allow-skipped: true` on the action) keeps the skipped-file warning and returns 0, 1, or 2 instead of 3.

## Action inputs

| Input           | Default  | Meaning                                                   |
| --------------- | -------- | --------------------------------------------------------- |
| `version`       | required | Exact release, for example `0.3.0`. `latest` is rejected. |
| `path`          | `.`      | Directory passed to `ironheights scan`.                   |
| `fail-on`       | empty    | `info`, `low`, `medium`, `high`, or `critical`.           |
| `allow-skipped` | `false`  | Pass `--allow-skipped`.                                   |
| `config`        | empty    | `ironheights.config.json` path.                           |
| `sarif-file`    | empty    | Write SARIF 2.1.0 here.                                   |
| `upload-sarif`  | `false`  | Upload that file to code scanning.                        |
| `node-version`  | `20`     | Node used to run `npx`.                                   |

Outputs are `exit-code` and `sarif-file`.

Until you are ready to pin a tag, `uses: ./` runs the action in this repository. The in-repo workflow [`.github/workflows/action.yml`](../.github/workflows/action.yml) does that against `test/fixtures/benign` (must exit 0), `test/fixtures/malicious/IH-CRED-001` (must exit 1 or 2), and a file larger than 1 MiB (must exit 3). That workflow installs npm package `0.15.0`, the last release on the registry, until `0.16.0` is published.

## Example

Pin a tag once a release exists. `v0.3.0` is this release. Do not point production jobs at a floating branch. The example below works after `0.3.0` is on npm.

```yaml
name: ironheights
on:
  pull_request:
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Frank-Masciopinto/ironheights@v0.3.0
        with:
          version: '0.3.0'
          path: .
          fail-on: high
          sarif-file: ironheights.sarif
          upload-sarif: true
```

Omit `upload-sarif` and the `security-events` permission when you only want the job status. A review or block still fails the job. An incomplete scan fails the job with exit 3 unless `allow-skipped` is true.

## Pre-commit

[`.pre-commit-hooks.yaml`](../.pre-commit-hooks.yaml) defines the `ironheights` hook. It expects the `ironheights` command on `PATH` and does not install it:

```yaml
repos:
  - repo: https://github.com/Frank-Masciopinto/ironheights
    rev: v0.3.0
    hooks:
      - id: ironheights
```

The hook runs `ironheights scan . --fail-on high` when a change touches a `SKILL.md`. Override `args` to point it at one directory.
