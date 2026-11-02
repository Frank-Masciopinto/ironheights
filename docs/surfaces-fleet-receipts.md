# Execution surfaces, fleet posture and run receipts (0.28.0)

Ironheights: The Immune System for AI Agents. It protects any AI bot that installs it. Everything here is opt-in and free; existing commands, fields and exit codes are unchanged.

## `ironheights surfaces --input surfaces.json [--repo .]`

- `base` / `head` / `threatModelChanged`: fails when a PR changes whose credential a surface uses, how often it runs or where it runs, unless the threat-model file changed in the same PR.
- `--repo`: derives surfaces from `.github/workflows/*.yml` (cron, `secrets.*`, `runs-on`), `crontab` / `*.cron` files and container files, and fails when the `model` list omits one. Model entries that nothing in the repo runs are warned as stale; prefix `external:` for surfaces outside the repo.
- `model[].maxConcurrent` and `ledger`: a surface with shared `writes` must declare max concurrent copies (fail); more than one unlocked copy on a shared path warns (use a per-run directory); the scheduler's own ledger (`maxConcurrentObserved`) above the declared max fails.
- `budgets` / `measured` / `baseBudgets`: each budget is a `contract` (fails the PR) or a `guideline` (warns). It is checked against the last real run's measured calls per task and largest payload, not the diff. Removing a retry cap or a contract budget fails.

## `ironheights fleet-posture --input fleet.json`

- Ignore debt: the age of the oldest live ignore is printed next to the grade, with the grade with and without ignores. Each ignore is bound to the hash of the finding it hides and stops applying when that finding changes or the ignore expires. A gap of more than one letter prints a notice.
- One row per machine. The fleet is clean only when every running copy was checked on its host and the hash of the file it actually executes matches the checked hash. A machine in the inventory with no row is unscanned.

## `ironheights run-receipt write|audit`

Per-run receipts written by the loader (`writer: "loader"`), one line per running copy (`copyId`), with the trigger, the loaded hash and the approver of that exact hash. Signed, hash-chained, append-only; set `IRONHEIGHTS_RECEIPT_DIR` to a store the agent cannot write. `audit` exits 2 when the chain is broken or any copy ran a hash no named approver approved.

## MCP tools

- `type_verdict`: a check after load returns `post-load-unchanged` or `post-load-drifted` with `loadedAt` next to `checkedAt`, never `allow`.
- `verdict_gate`: only a pre-load `allow` proceeds; unknown, truthy, missing or post-load values fail closed.
- `lookup_verdict`: by content hash plus registry-verified publisher; bare names are refused.
- `session_binding`: digest of the session id plus sorted env-var names (never values); a changed session is `expired`.
