# 142 accuracy rows, one experiment, 2026-11-07

One branch off `fa05c6922fcd6f8de05f85c5a7ebdd398a9b604c` (main after #124 and #125). Seven new checks live in `src/rules/exp-1107.ts`. House pairs live under `bench/house/missed-2026-11-07/` and are not part of the MaliciousSkillBench number. The model column was not run.

`docs/experiments/DISCARDED-RULES.md` was read first. The handoff copy of that log had two sections this repo was missing (the 2026-11-03 verdict fix, and P1–P6). Those sections are restored in the log. P1, P2, and P5 were not revived. The REF-001 zero-weight change was not repeated.

## What the 142 is

The window is 2026-11-05T23:00Z through 2026-11-06T19:14Z (Warsaw Nov 6 00:00–20:14). That window holds 142 accuracy rows. A strict 20:10 Warsaw cutoff is 140. Rows 141 and 142 were logged at 19:14Z while the summary was being written. They are in the ledger. The excluded-after-cutoff file was not implemented.

Rows 26–31 have a shifted source column in the raw export. The `shipped` bucket on those rows is wrong. Row 124 mentions the discarded-rules log and is not a rejection. Dispositions below follow the text, not the queue status.

## Ledger

Every row is in [dispositions.csv](dispositions.csv). The grouped read is [INVENTORY.md](INVENTORY.md).

| Disposition | Rows |
| --- | ---: |
| implemented | 7 |
| already-covered | 7 |
| duplicate | 44 |
| dropped | 5 |
| limited | 79 |
| **sum** | **142** |

Implemented means a new check, with fixtures and tests, not a fixture-only change. Already-covered means the check was on this main before the branch. Duplicate points at the canonical row. Dropped means a measured gate failure, listed in the discarded-rules log. Limited means the ask needs a runtime fact, a registry, a model, or a match-process ruling this static scan does not have, and the note says which.

## Reproduce

From a clean checkout, with `bench/msb/requirements.txt` installed into `.venv`:

```
npm run build
IH_GATE_CACHE=~/.cache/ih-gate .venv/bin/python scripts/realworld-gate.py dist/cli/index.js docs/experiments/batch-2026-11-07/gate
.venv/bin/python scripts/benchmark-msb.py dist/cli/index.js docs/experiments/batch-2026-11-07/public
```

Do not pass `--llm`. The model opinion is a separate column and was not run. It does not change verdict, grade, or exit code.

Pins: MaliciousSkillBench `d4b42ce5766a6e0359c987cf59c1007cb3795a90`, Anthropic skills `ca45fc496a3436251f191354091d557da31c15b5`, real-world ClawHub `GokuScraper/clawhub-skills` @ `240122b936774532c3ec5df8610c72938a3ce751`, signals filter `OpenClaw/clawhub-security-signals` @ `69dcbd323c155312fb000ec89ea0b1efdf6a5757`, GitHub skills `FayeZC/SkillMD-138K` @ `0d73048abf2fb6ee91f6f9f5ac598d5be8d6bdd7`.

## Before / after versus current main

Fresh main was scanned on this machine before the rule changes. That scan is the baseline. The committed `bench/realworld/baseline.json` still says blind 217/600 because it was written on an older build. The fresh scan of this main is 219/600.

| Metric | main `fa05c69` | this branch |
| --- | --- | --- |
| Public attacks blocked | 174/516 | 174/516 |
| Public attacks block or review | 256/516 | 256/516 |
| Public safe blocked | 11/456 | 11/456 |
| Public safe block or review | 31/456 | 31/456 |
| Prose-only attacks blocked | 33/98 | 33/98 |
| Prose-only block or review | 52/98 | 52/98 |
| Anthropic skills flagged | 0/19 | 0/19 |
| Blind attacks blocked | 219/600 | 219/600 |
| Blind safe blocked | 15/300 | 15/300 |
| Real-world clean blocked | 275/5655 | 275/5655 |
| Real-world clean sent to review | 474/5655 | 474/5655 |
| LLM opinion | not run | not run |

No public skill changed verdict. The real-world gate added no block and no review.

## Per rule

Public attacks are 516 and public safe skills are 456, from the pinned manifest. Look-alikes are the pinned real-world corpus: 5,655 skills (4,500 ClawHub, 1,155 GitHub). A skill can sit in more than one look-alike category: monitoring 1,330, API key 1,267, scheduler 914, installer 860, backup 642. House attacks and house controls are the defensive pairs in this folder's sibling `bench/house` tree. They are counted on their own denominators.

| Rule | Public attacks | Public safe | Real-world look-alikes | House attacks | House controls |
| --- | --- | --- | --- | --- | --- |
| IH-INJ-017 content as orders | 0/516 | 0/456 | 0/5655 | 4/4 review | 0/4 |
| IH-INJ-018 catalog disguise | 0/516 | 0/456 | 0/5655 | 2/2 review | 0/2 |
| IH-INJ-019 payee overwrite | 0/516 | 0/456 | 0/5655 | 1/1 block | 0/1 |
| IH-NET-005 hidden full-file upload | 0/516 | 0/456 | 0/5655 | 2/2 review | 0/2 |
| IH-PERSIST-004 template residue | 0/516 | 0/456 | 0/5655 | 1/1 review | 0/1 |
| IH-PERSIST-005 silent unpack | 0/516 | 0/456 | 0/5655 | 1/1 review | 0/1 |
| IH-INJ-020 candor suspends review | 1/516 | 0/456 | 0/5655 | no house pair | no house pair |

The one public hit is ASB04_005544 (prose). Main already blocked it with IH-INJ-007. IH-INJ-020 is new coverage of that shape. It does not add a prose block, and the prose totals above do not move.

Review-tier checks are score-exempt, so one hit is a review and does not push another review over the block line. IH-INJ-019 is critical, same harm as IH-INJ-014, because the hidden field is the payee.

`metadata.requires.apis` entries that are URLs or bare hosts are now declared hosts, same as `homepage`. Product names such as "DeBank API" are not mapped to hosts. That mapping was not shipped: dropping IH-NET-001 points is how the sibling-markdown exemption lost a block.

## Shadow

The six checks other than candor were in `SHADOW_CHECKS` for one enforce pass (`IRONHEIGHTS_SHADOW=enforce` on the 5,655). That pass would block 0 and would review 0. Candor was added after that pass and was then enforced. The enforced gate added 0 real-world blocks and 0 real-world reviews. The names were removed from `SHADOW_CHECKS`. The final scan in this folder is the promoted scanner.

## Labels

Public labels and the prose/code kind come from `bench/msb/manifest.json`. This run did not relabel them. House attack/control labels are the red-team pair: the attack instructs the extra step, the control asks or refuses. They are not MaliciousSkillBench rows. Blind rows are not listed per sample. [public/blind-aggregate.json](public/blind-aggregate.json) has the counts and a digest. Real-world skills are the clean corpus defined by `bench/realworld/manifest.json`.

Per-sample public verdicts: [public/results.csv](public/results.csv). Per-rule public hits: [public/rules.json](public/rules.json). Real-world gate: [gate/realworld-gate.json](gate/realworld-gate.json).

## Dropped

See `docs/experiments/DISCARDED-RULES.md`. Short form: sibling-markdown info, the credential-advice skip, the "when the user asks" skip on IH-INJ-003, and the high-to-medium downgrade for placeholder webhooks and tunnel hosts. Each was removed. The scan in this folder is the rerun without them.

## Limitations

- These checks do not move the public or blind block totals. The new catches are the house pairs, plus one already-blocked public prose row.
- A whole-disk diff after a removal claim, a post-install hash, a signed registry, a live socket bind, and a nonce attestation are outside this static scan. Rows that ask for those are `limited` in the ledger.
- IH-NET-001 points still hold some blocks even though the rule is context-only when it is the only signal. That is why host-severity downgrades were not kept.
- No separate keyword look-alike download was added on top of the 5,655. That corpus is the look-alike set, including the category counts above.
