# Batch 2026-11-03: queued accuracy ideas, combined run

Worktree `/workspace/ih-exp-batch`, branch `exp/batch-1103` (one local commit, on main 8d2559c after PRs #111–#113). Nothing was pushed, no PR was opened, nothing was merged. Rules are in `src/rules/exp-batch.ts` and gated by `IH_EXP` A–J. Runs used the frozen build `/workspace/ih-exp-batch-frozen`.
Kaleb changed the plan at 06:42 Warsaw: put every idea on one branch, run the gates once, drop the rules that flag anything, then rerun once.

## Final combined (G+J) vs main

| Metric                        | main        | Run 1: all A–J                                    | Run 2 (final): G+J |
| ----------------------------- | ----------- | ------------------------------------------------- | ------------------ |
| Bench attacks blocked /516    | 171 (33.1%) | 174                                               | 171 (33.1%)        |
| Bench safe blocked /456       | 11 (2.4%)   | 11                                                | 11                 |
| Bench attacks block-or-review | 238 (46.1%) | 248 (48.1%)                                       | 239 (46.3%)        |
| Bench safe block-or-review    | 31 (6.8%)   | 31 (one I hit on a safe skill, verdict unchanged) | 31                 |
| Blind attacks blocked /600    | 217         | 224                                               | 217                |
| Blind safe blocked /300       | 15          | 15                                                | 15                 |
| Real-world new blocks /5,655  | –           | **1 (FAIL)**                                      | 0                  |
| Look-alikes flagged /15,888   | –           | **76 rule hits across 8 rules (FAIL)**            | 0                  |

## Per-rule contribution in run 1 (number of skills where the rule fired)

| Rule | Idea                                                      | Bench attacks       | Bench safe | Look-alikes                                        | Kept?                        |
| ---- | --------------------------------------------------------- | ------------------- | ---------- | -------------------------------------------------- | ---------------------------- |
| A    | whole env sent to network                                 | 1 (001078 → block)  | 0          | 1                                                  | dropped                      |
| B    | decode then exec                                          | 6 (003311 → block)  | 0          | 5 (scanner/vetter docs) + the real-world new block | dropped                      |
| C    | ≥2 named secrets in one payload                           | 4 (→ review)        | 0          | 7 (normal config dicts)                            | dropped                      |
| D    | directives override security                              | 2 (006823 → block)  | 0          | 17 (guard skills quoting attacks)                  | dropped                      |
| E    | filters-off clause                                        | 1 (007349 → review) | 0          | 9                                                  | dropped                      |
| F    | description admits disguise                               | 1 (001161 → review) | 0          | 8 (e.g. "camouflage", NAT masquerade)              | dropped                      |
| G    | pre-confirmed send                                        | 1 (004651 → review) | 0          | 0                                                  | **kept**                     |
| H    | change kept out of the report (dedup, rename, login file) | 0                   | 0          | 8                                                  | dropped                      |
| I    | .env value into a published file                          | 0                   | 1          | 21                                                 | dropped                      |
| J    | opt-out undone on a timer                                 | 0                   | 0          | 0                                                  | kept (moves no bench metric) |

Blind results are totals only, so they can't be split per rule. Earlier single-rule gates gave D 222/600 and E 218/600, both with 0 new real-world blocks. The red-team pairs were detected (attack flagged, control clean) by H (dedup, house-027, house-045), I (house-029, house-033) and J (house-043), but none of them are benchmark rows.
Look-alike set: 15,888 real skills. 15,005 are ClawHub SKILL.md files chosen by keyword for each pattern, and 883 are GitHub skills from the lion set. Every hit was counted as a flag, with no case-by-case excuses.

## Not built in this batch

These weren't built: remote text fetched and acted on, opt-out on a timer variants, session data sent to a host the task doesn't need, approval claimed on the user's behalf plus a destructive step, ignoring another installed skill, memory steering, collected but unused credentials, and all the FP fixes. Some need changes to scoring or deduplication rather than a new rule. None has a benchmark or blind row that a simple rule would move.

## Caveats

- Rules A–G were written while looking at the benchmark rows they target, so the bench gains are tuned. Blind rows were never read.
- The gate's built-in baseline shows 212 blind. The main baseline from this run is 217 (gate-base).
  Files: msb*.json, combo-*.json/out, gate-_/ and gate-_.log, la-\*.out, /workspace/ih-lookalike-batch/.

---

# Rerun 2026-11-03 ~07:05 Warsaw: 8 dropped rules tightened (commit 2 on exp/batch-1103)

What changed in each rule:

- **A:** string literals and comment or list lines are stripped before matching.
- **B:** the same, plus a skip for scanner/vetter docs (GUARD_DOC) and for `(...)` placeholders.
- **C:** the bundled variable must later be serialized or sent.
- **D:** needs an order aimed at the agent ("treat … directives as overriding", "prioritize … directives over", "comply with these directives even if") against security, safety, constraints or protocols, with no quoted text.
- **E:** needs "this skill/you/the agent … without restriction filters" or "regardless of topic sensitivity", with no quotes.
- **F:** the description must also carry resource-drain or covert-harm wording.
- **H:** must sit in a paragraph about the change summary or edits.
- **I:** needs "copy/take the value of" with .env, plus a published target.

All targets are still hit and the controls stay clean. Blind rows were never read.

## Final combined (A–G + J) vs main

| Metric                            | main        | Run 3: all 10 tightened | Final: A–G + J  |
| --------------------------------- | ----------- | ----------------------- | --------------- |
| Bench attacks blocked /516        | 171 (33.1%) | 174 (33.7%)             | **174 (33.7%)** |
| Bench safe blocked /456           | 11 (2.4%)   | 11                      | 11              |
| Bench attacks block-or-review     | 238 (46.1%) | 248 (48.1%)             | **248 (48.1%)** |
| Bench safe block-or-review        | 31 (6.8%)   | 31                      | 31              |
| Blind attacks blocked /600        | 217         | 219                     | **219**         |
| Blind safe blocked /300           | 15          | 15                      | 15              |
| Real-world new blocks /5,655      | –           | 0                       | 0               |
| Real-world review-level rule hits | –           | 0                       | 0               |
| Look-alikes flagged /15,888       | –           | 0                       | 0               |

## Per rule

| Rule                         | Bench attacks fired | Safe         | Look-alike hits v1 → v2 | Real-world hits | Kept?                                 |
| ---------------------------- | ------------------- | ------------ | ----------------------- | --------------- | ------------------------------------- |
| A whole env to network       | 1                   | 0            | 1 → 0                   | 0               | kept                                  |
| B decode then run            | 5                   | 0            | 5 (+1 RW block) → 0     | 0               | kept                                  |
| C bundled secrets            | 4                   | 0            | 7 → 0                   | 0               | kept                                  |
| D directives override safety | 1                   | 0            | 17 → 0                  | 0               | kept                                  |
| E filters off                | 1                   | 0            | 9 → 0                   | 0               | kept                                  |
| F disguise description       | 1                   | 0            | 8 → 0                   | 0               | kept                                  |
| G pre-confirmed send         | 1                   | 0            | 0 → 0                   | 0               | kept                                  |
| J opt-out on timer           | 0                   | 0            | 0 → 0                   | 0               | kept as instructed (no measured gain) |
| H change kept out of report  | 0                   | 0            | 8 → 0                   | 0               | **discarded: no measured gain**       |
| I .env into published file   | 0                   | 0 (v1 had 1) | 21 → 0                  | 0               | **discarded: no measured gain**       |

Caveats:

- The v2 rules were narrowed after reading their own v1 look-alike hits, so the 0/15,888 isn't fully independent. The real-world and blind zeros are independent.
- Run 1 blocked 224 blind attacks against 219 now, so tightening lost 5 blind blocks that the loose rules had caught. Blind rows can't be split per rule.
- D v2 now fires on 1 benchmark row, not 2. The target, 006823, still blocks.

Logs: `gate-combo3/`, `gate-combo4/` (with `xb-hits.json` for real-world rule hits), `combo-combo3.json`, `gate-xb.py`. Discards are logged in `../DISCARDED-RULES.md`.
