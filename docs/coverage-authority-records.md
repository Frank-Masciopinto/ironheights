# Coverage, runner authority and install records (0.27.0)

Three open, opt-in commands built from ideas bots sent on Moltbook. All are local and read JSON you supply. Each exits 2 when its check fails.

## `ironheights coverage --input runs.json`

This is a gap-aware posture grade. The first line is coverage, for example `checked 19 of 30, 11 unknown, 2 gap(s) (1 right after updates)`. A grade appears only when the record is whole.

- No grade is given when more than `maxGapNights` (default 1) nights are empty, or when a missed run falls on or right after a skill-list change. Missed nights show as `not-run`. They are never averaged in.
- Each grade carries the `rulesetHash` it was computed against. It is marked STALE when `currentRulesetHash` differs.
- The trend uses a fixed cohort: only skills graded in every run.
- Skills that left scanning but are still installed are named as possible hidden vectors.
- `access` rows show declared, granted and used access separately. They also list ambient access the context grants that no skill declared, and *unmodelled actors*: processes that consumed a credential but are not in the skill's dependency graph.
- `drift` findings are `open`, `explained`, `resolved` or `rejected`. The party that caused a drift can explain it only by pointing at an artifact it did not write after the fact, whose hash matches the drifted file. Only a different role can resolve it.

## `ironheights authority --input authority.json`

The unit under review is the runner's ambient authority, which every step inherits. Each of these fails, and none is a warning:

- Secrets, tokens or permissions grow on a runner.
- A step's effective set grows.
- A new runner appears. It counts as a new install, even with identical bytes.
- A new flag or env var has no reach line.
- A removed skill leaves cron entries, tokens, webhooks, files or DNS records that have not been proven gone.
- A new reader appears on a path a private-data writer uses. The only exception is an override that records who allowed it and why.

`approvalCovers()` binds an approval to skill hash, runner and authority hash together.

## `ironheights record approve --input rec.json` / `ironheights record audit`

The auditor-accepted install record. Each record says who approved which version and hash, under a versioned scope (skill, version range, task class, until, write path). Inherited approvals (`dependency`, `auto-update`, `name`) are marked as inherited. Records are ed25519-signed, hash-chained and append-only.

Set `IRONHEIGHTS_RECORD_DIR` to a store the agent cannot write, rotate or prune, such as a separate user or a WORM mount. `audit` verifies the chain and reports each record as accepted only when the approver is present, the hash the approver saw matches, the approval is not inherited and the scope has not expired.
