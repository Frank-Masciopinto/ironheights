# Queued detections, 2026-11-06

One branch. Rules live in `src/rules/exp-1106.ts`. House pairs are under `bench/house/missed-2026-11-06/` and are not part of the MaliciousSkillBench number. P1, P2 and P5 from prose-1103 were not revived.

Both scanners were built and scored on this machine against the pinned MaliciousSkillBench revision `d4b42ce5` and the pinned real-world corpus (5,655). Blind rows were not opened. The model column was not run.

## Before / after versus main `ec43a46` (0.34.0)

| Metric | main 0.34.0 | this branch |
| --- | --- | --- |
| Bench attacks blocked | 174/516 (33.7%) | 174/516 (33.7%) |
| Bench safe blocked | 11/456 (2.4%) | 11/456 (2.4%) |
| Bench attacks block or review | 249/516 (48.3%) | 256/516 (49.6%) |
| Bench safe block or review | 31/456 (6.8%) | 31/456 (6.8%) |
| Prose-only attacks blocked | 33/98 (33.7%) | 33/98 (33.7%) |
| Prose-only block or review | 51/98 (52.0%) | 52/98 (53.1%) |
| Anthropic skills flagged | 0/19 | 0/19 |
| Blind attacks blocked | 219/600 | 219/600 |
| Blind safe blocked | 15/300 | 15/300 |
| Real-world clean blocked | 275/5655 | 275/5655 |
| Real-world clean sent to review | 474/5655 | 474/5655 |
| LLM opinion | not run | not run (separate column; it does not change verdict, grade, or exit code) |

The block count did not move. Seven malicious rows moved from no-findings to review. One of those is prose-only (ASB04_006124).

## Per rule, final

Counts are skills where the rule fired. Safe is the 456-skill benchmark benign set. Look-alikes are the 5,655-skill real-world clean corpus (a second scan that counted rule hits, not only verdict changes).

| Rule | Attacks flagged | Safe skills flagged | Look-alikes flagged | Kept? |
| --- | --- | --- | --- | --- |
| IH-BIN-003 PATH plant | 1 (ASB04_001569) | 0 | 0 | kept |
| IH-EXEC-007 debug-tunnel shell | 1 (ASB04_005696) | 0 | 0 | kept |
| IH-INJ-012 silent input offset | 1 (ASB04_001094) | 0 | 0 | kept |
| IH-REF-004 unseen template | 1 (ASB04_006124, prose) | 0 | 0 | kept |
| IH-META-003 peer retired, no recheck (P4) | 1 (ASB04_006313) | 0 | 0 | kept |
| IH-FS-002 write outside regardless of task (P3) | 1 (ASB04_000719) | 0 | 0 | kept |
| IH-INJ-013 permission-free memory (P6) v2 | 1 (ASB04_004303) | 0 | 0 | kept |
| IH-PERSIST-003 silent self-replace | 0 | 0 | 0 | kept; no benchmark row. House pair only. |

IH-INJ-013 v1 (the word "every session" near `MEMORY.md`) is not in this table. It failed the first gate: 5 new real-world reviews and 1 public benign skill. v2 is what the re-run measured.

## Dropped

See `docs/experiments/DISCARDED-RULES.md`.

- REF-001 at zero points: public blocks 174→163, blind blocks 219→192. Weights restored. The finding still says the missing script was not checked, and the content digest still hashes only files that are present. A package whose only issue is a missing script stays verdict `no-findings`.
- IH-INJ-013 v1: real-world gate failed with 5 new reviews. Tightened, then the gate was run once more and passed.

## Caveat

The seven benchmark gains are on the rows the rules were written for. Blind totals did not move, so this is not held-out detection. IH-PERSIST-003 moves no public row.
