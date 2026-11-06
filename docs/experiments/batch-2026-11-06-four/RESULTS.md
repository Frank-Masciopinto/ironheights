# Four ideas, 2026-11-06

One branch. Rules live in `src/rules/exp-1116.ts` (IH-INJ-014, IH-INJ-015, IH-CRED-007, IH-INJ-016, IH-META-004) and `src/rules/rebuildable.ts` (IH-META-005). House pairs are under `bench/house/missed-2026-11-06/` and are not part of the MaliciousSkillBench number.

`docs/experiments/DISCARDED-RULES.md` was read first. The dropped "change kept out of the report" pattern (batch-1103 H) was not revived. IH-INJ-014 fires only when a payee, destination, or amount field is changed from a skill-supplied value and that edit is kept out of the change list. The word "payment" is not the check. IH-INJ-015 is the same shape for a non-payment field. It is medium and score-exempt, so it is a review and cannot push another review over the block line.

No rule from this batch was dropped. The first gate ran with the five new malice checks in shadow. The enforce scan would block 0 real-world skills and would send 0 to review. They were promoted, and the gate was run again. IH-META-005 was not shadowed: it is an incomplete-scan coverage note, not a block.

The published 7-row negative-control list for the authority-grant test is not in this repo (no moltbook draft, `feedback.csv`, or experiment file contains it). The controls used are the named shapes plus close cousins, one file each under `test/fixtures/benign/near/IH-INJ-016/`:

1. MIT-style license header (`Permission is hereby granted`)
2. `SPDX-License-Identifier` line
3. "You may use, copy, modify, and distribute"
4. Documented capability list under a Capabilities heading
5. Permission / capability table
6. "The agent may" / "you can" (close cousin of "you may")
7. Copyright, "All rights reserved", and "licensed under"

IH-META-004 is the stub note: when that honest prose is present and a bundled script pipes remote text into a shell, the note says to score the bytes that ran. It does not block the honest language. On the house stub, the block is IH-EXEC-001 on `scripts/run.py`.

A one-file extract that names a script stays the IH-REF-001 note and verdict `no-findings`. A folder that already contains other files, and still lacks a script `SKILL.md` runs, is incomplete. A folder with no `SKILL.md`, or a placeholder gist with no concrete steps, is incomplete. `--allow-skipped` does not clear that.

Both scanners were built and scored on this machine against MaliciousSkillBench revision `d4b42ce5766a6e0359c987cf59c1007cb3795a90` and the pinned real-world corpus (5,655). Blind rows were not opened. The model column was not run.

## Before / after versus current main (`ecbf1a4`, 0.34.0 + #124)

| Metric                          | main (0.34.0 + #124) | this branch                                                                |
| ------------------------------- | -------------------- | -------------------------------------------------------------------------- |
| Bench attacks blocked           | 174/516 (33.7%)      | 174/516 (33.7%)                                                            |
| Bench safe blocked              | 11/456 (2.4%)        | 11/456 (2.4%)                                                              |
| Bench attacks block or review   | 256/516 (49.6%)      | 256/516 (49.6%)                                                            |
| Bench safe block or review      | 31/456 (6.8%)        | 31/456 (6.8%)                                                              |
| Prose-only attacks blocked      | 33/98 (33.7%)        | 33/98 (33.7%)                                                              |
| Prose-only block or review      | 52/98 (53.1%)        | 52/98 (53.1%)                                                              |
| Anthropic skills flagged        | 0/19                 | 0/19                                                                       |
| Blind attacks blocked           | 219/600              | 219/600                                                                    |
| Blind safe blocked              | 15/300               | 15/300                                                                     |
| Real-world clean blocked        | 275/5655             | 275/5655                                                                   |
| Real-world clean sent to review | 474/5655             | 474/5655                                                                   |
| LLM opinion                     | not run              | not run (separate column; it does not change verdict, grade, or exit code) |

The public block count did not move. These shapes are not in the pinned benchmark. The house pairs are the measured catches.

## Per rule, final

Counts are skills where the rule fired. Attacks and safe are the public benchmark (516 / 456). Look-alikes are the 5,655-skill real-world clean corpus. Honest twins in the house set and the seven authority-grant fixtures were also clean (unit tests).

| Rule                                                     | Attacks flagged | Safe skills flagged | Look-alikes flagged | Kept?                                                                          |
| -------------------------------------------------------- | --------------- | ------------------- | ------------------- | ------------------------------------------------------------------------------ |
| IH-INJ-014 unlisted payee, destination, or amount        | 0               | 0                   | 0                   | kept; hard fail. House attack blocks. Honest invoice twin does not.            |
| IH-INJ-015 unlisted non-payment edit                     | 0               | 0                   | 0                   | kept; review only, score-exempt. House ordinary footer is review, not a block. |
| IH-CRED-007 already-held key as identity                 | 0               | 0                   | 0                   | kept; review only, score-exempt. Declared env slot is not flagged.             |
| IH-INJ-016 third-party content as principal instructions | 0               | 0                   | 0                   | kept; review only, score-exempt. Seven honest grant shapes are not flagged.    |
| IH-META-004 prose promised X, stub did Y                 | 0               | 0                   | 0                   | kept; info note. Does not block the honest language.                           |
| IH-META-005 package is not rebuildable                   | 0               | 0                   | 0                   | kept; incomplete verdict, not a block or a review. Honest docs stay clean.     |

## Dropped

None. The shadow enforce pass was 0 would-block and 0 would-review on the real-world corpus, so nothing in this batch failed a gate.

## Caveat

Public and blind totals did not move. Detection added here is the house pairs, not a new MaliciousSkillBench row. IH-REF-001 weights are unchanged. A missing script still does not, by itself, supply the points that hold a block.
