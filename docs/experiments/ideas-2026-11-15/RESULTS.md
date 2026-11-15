# Moltbook ideas, 2026-11-15 — one experiment

Branch `exp/ideas-1115`, based on main 717de52 (after #150, script scanning). Deterministic only; no model column was run. Model opinions stay separate from these findings.

## How it was run

- **Dev set** (design): 51 attacks and 26 honest twins built from `benchmark-candidates/missed-attacks/2026-11-15-*`, house rows 520–538 and red-team r264/r265/r267.
- **Fresh set** (written after the rules were frozen, scored, not tuned): 22 attacks, 10 honest twins.
- **Scored only, never tuned on:** MaliciousSkillBench, blind, prose, real-world (5,655), settings-change held-out, settings-change-fresh, script-skills (1,028 attacks / 1,026 twins, held-out 539).
- **Look-alikes:** 173,071 honest skills (ClawHub 34,938 + GitHub 138,133), full scan on main and on the PR.
- Run 1 → dropped or narrowed failing rules → run 2 (single re-run) → dropped IH-CRED-011, which failed run 2 on a look-alike. Dropping a rule only removes findings; the final build was re-scored on dev, fresh, settings-change and script-skills.

## Before / after

Cisco skill-scanner 2.3.2 and NVIDIA SkillSpector v2.12.0 numbers are reused from the 0.36.0 changelog, `bench/settings-change/results/baseline.md` and `bench/script-skills/results/baseline.md` (same sets, not re-run).

| Set | main 717de52 | This PR | Cisco 2.3.2 | SkillSpector v2.12.0 |
| --- | --- | --- | --- | --- |
| MSB attacks blocked | 260/516 | 260/516 | 113/516 | 134/516 |
| MSB safe skills wrongly blocked | 6/456 | 6/456 | 9/456 | 48/456 |
| MSB block or review | 314/516 | 314/516 | 115/516 | 220/516 |
| Blind attacks blocked | 335/600 | 335/600 | 190/600 | 173/600 |
| Blind safe skills blocked | 13/300 | 13/300 | 6/300 | 35/300 |
| Prose-only attacks blocked | 40/98 | 40/98 | 5/98 | 7/98 |
| Real-world clean skills blocked | 232/5,655 | 230/5,655 | — | — |
| Real-world clean skills sent to review | 452/5,655 | 453/5,655 (no new ids) | — | — |
| Settings-change held-out attacks blocked | 8/21 | 8/21 | 0/21 | 0/21 |
| Settings-change held-out safe blocked | 0/23 | 0/23 | 0/23 | 0/23 |
| Settings-change-fresh attacks blocked | 26/67 | 26/67 | not run | not run |
| Script-skills attacks blocked | 405/1,028 | 405/1,028 | 342/1,028 | 295/1,028 |
| Script-skills honest twins blocked | 0/1,026 | 0/1,026 | 231 | 225 |
| Script-skills block or review | 598/1,028 | 598/1,028 | 415 | 703 |
| Script-skills held-out attacks blocked | 214/539 | 214/539 | 174/539 | 154/539 |
| Look-alikes (173,071) new block/review | — | 0 | — | — |
| Dev attacks blocked (design set) | 5/51 | 35/51 | not run | not run |
| Dev attacks block or review | 12/51 | 41/51 | not run | not run |
| Dev twins flagged | 1/26 (review) | 0/26 | not run | not run |
| Fresh attacks blocked (post-freeze) | 4/22 | 17/22 | not run | not run |
| Fresh attacks block or review | 7/22 | 20/22 | not run | not run |
| Fresh twins flagged | 1/10 (review) | 0/10 | not run | not run |

The real-world change comes from the IH-INJ-003 negation guard: two safety skills whose "never edit …" lines were read as orders moved from block to review, and one memory skill moved from review to no findings. The gate passed with no new block or review ids.

**Honest caveat.** The held-out sets did not move. None of today's attack families (trust-anchor redirect, remote mutable instructions, MCP description poisoning, standing triggers, payee swap, auto-approve wildcard, credential links to a skill-picked address) appear in MSB, blind, prose or the held-out splits. The gain shows only on the dev rows and the fresh set, which was written by the same author after design. Under the "strong on dev, weak on held-out" rule this is a no-measured-gain risk on public sets; it is not a regression.

## Per-rule counts (final build)

Attacks = medium-or-higher hits on attack rows. Safe = hits on honest twins / MSB benign. Look-alikes = new verdicts on the 173,071 pool.

| Rule | Dev attacks | Fresh attacks | MSB attacks | Safe (dev, fresh, MSB, script twins) | Look-alikes | Real-world new |
| --- | --- | --- | --- | --- | --- | --- |
| IH-NET-014 package source moved machine-wide + integrity check off for it | 4 | 4 | 0 | 0 | 0 (run 1: 12) | 0 |
| IH-NET-015 shipped key/cert added to a global trust store | 2 | 2 | 0 | 0 | 0 | 0 |
| IH-INJ-030 remote, changeable instructions given authority | 3 | 2 | 0 | 0 | 0 (run 1: 10) | 0 |
| IH-MCP-004 tool description reaches into other tools or outside data | 3 | 2 | 0 | 0 | 0 | 0 |
| IH-PERSIST-009 standing every-task trigger written into agent memory/shell | 2 | 1 | 0 | 0 | 0 (run 1: 45) | 0 (run 1: 1 review) |
| IH-PRIV-006 payee/refund/recovery field written from a skill-supplied value | 3 | 2 | 0 | 0 | 0 | 0 |
| IH-PRIV-007 wildcard added to auto-approve list | 2 | 1 | 0 | 0 | 0 (run 1: 2) | 0 |
| IH-NET-016 sign-in links / tokens / ID numbers sent to a skill-picked address | 2 | 1 | 0 | 0 | 0 (run 1: 3) | 0 |
| IH-PRIV-004 / PRIV-003 settings-change additions | 19 / 2 | 5 / 1 | 0 | 0 | 0 (run 1: 14 / 1) | 0 |
| IH-INJ-003 negation guard (fix) | — | — | 0 change | removed 1 dev twin review | 52 look-alikes lost an INJ-003 hit (34 verdicts went down) | 2 blocks and 1 review removed |
| IH-CRED-011 outside credential stores copied into a commit/upload — **dropped** | (2) | (1) | 0 | 0 | 1 new block in run 2 (Figma policy-guardrails doc) | 0 |

## Ideas: implemented, dropped, skipped

See the PR description for the full list; dropped and skipped items with reasons are in `docs/experiments/DISCARDED-RULES.md` (2026-11-15 Moltbook ideas section).
