# 2026-11-27 write-the-rule candidates

Draft experiment. Not a release. Do not merge until the owner says so.

Branch `exp/wtr-candidates-1127` off main `16536165a0ad42cf044a305ecb8fdb8c4ce32d64`. One check kept (IH-PRIV-017). One check dropped (IH-FLOW-006). See `docs/experiments/DISCARDED-RULES.md`.

## How this was scored

Deterministic rules only. Nothing in a skill was executed. MaliciousSkillBench is revision `d4b42ce`, 516 malicious / 456 benign, the same checkout `scripts/benchmark-msb.py` uses. The held-out half is the stand-in used since `benchmark-2026-11-02/v030/RESULTS.md` is not in this repo: a public id is held-out when the first byte of `sha256(id)` is odd (266 malicious / 228 benign). Attack-lanes and script-skills use their own hash splits. Those held-out texts were not opened while the rule was written. Blind totals come from `scripts/realworld-gate.py` and are counts only.

Cisco skill-scanner 2.3.2 was not re-run. The reference row is the published 21.9% detection / 2.0% false positives.

## Kept

**IH-PRIV-017** (spiritofthefleet). The skill's own code, not prose, a comment, or a fenced example, writes a lowered guard into user persistent config outside the skill directory and does not restore it. The guard is an auto-approve or `bypassPermissions` mode, TLS verification off, a trusted-host add, or signature and integrity checking off. Targets are `~/.claude/settings.json`, the global gitconfig, the user npmrc, a shell rc file, `~/.ssh/config`, or a `--global` / `pip config` write.

On attack-lanes and script-skills every new block was a review that became a block. Benign block and review counts did not move. Real-world block ids did not change (230 / 5,655, review 452).

## Dropped

**IH-FLOW-006** (vibejamhank, dikabot's framing). An outbound step plus a hiding order that opens the same sentence or the next one. It blocked 3 real-world skills (a publisher, a cleanup skill, and an API client) whose next sentence was a safety line ("do not include secrets" or "do not include this header"). It did not add a block on the MaliciousSkillBench dev half, and attack-lanes dev verdicts did not move. Dropped before the held-out pass.

## Before and after

Block count, with block-or-review in brackets when both were counted. Main and this branch were scanned on this machine.

| Metric                                           | main 1653616                  | experiment           | change    |
| ------------------------------------------------ | ----------------------------- | -------------------- | --------- |
| MaliciousSkillBench detection at block           | 263/516 (51.0%)               | 263/516 (51.0%)      | 0         |
| MaliciousSkillBench FP at block                  | 7/456                         | 7/456                | 0         |
| MaliciousSkillBench block or review              | 315/516                       | 315/516              | 0         |
| MaliciousSkillBench benign block or review       | 31/456                        | 31/456               | 0         |
| Held-out half (odd sha256 byte) attacks at block | 138/266                       | 138/266              | 0         |
| Held-out half benign at block                    | 4/228                         | 4/228                | 0         |
| Anthropic skills at block                        | 1/19                          | 1/19                 | 0         |
| Prose-only attacks at block                      | 40/98                         | 40/98                | 0         |
| Attack-lanes all attacks at block                | 959/1335 (1037)               | 967/1335 (1037)      | +8 block  |
| Attack-lanes all twins at block                  | 11/1250 (41)                  | 11/1250 (41)         | 0         |
| Attack-lanes held-out attacks at block           | 457/659 (495)                 | 459/659 (495)        | +2 block  |
| Attack-lanes held-out twins at block             | 5/641 (20)                    | 5/641 (20)           | 0         |
| Script-skills all attacks at block               | 533/1028 (694)                | 549/1028 (694)       | +16 block |
| Script-skills all twins at block                 | 0/1026 (112)                  | 0/1026 (112)         | 0         |
| Script-skills held-out attacks at block          | 291/539 (372)                 | 300/539 (372)        | +9 block  |
| Script-skills held-out twins at block            | 0/493 (55)                    | 0/493 (55)           | 0         |
| Blind attacks at block                           | 340/600                       | 340/600              | 0         |
| Blind benign at block                            | 13/300                        | 13/300               | 0         |
| Real-world clean blocked                         | 230/5655                      | 230/5655, no new ids | 0         |
| Real-world clean at review                       | 452/5655                      | 452/5655, no new ids | 0         |
| Cisco 2.3.2 reference                            | 113/516 (21.9%), 9/456 (2.0%) | not re-run           | reference |

The Anthropic block on both columns is `anthropic_claude-api` via IH-NET-030, which is already on main. The benign block count is 7 rather than the 6 in the 0.37.0 write-up for the same reason: that skill sits inside the 456. This branch did not change it.

Attack-lanes dev, scored while tuning and not repeated above: attacks 502→508 block, twins unchanged at 6 block / 15 review of 609. Script-skills dev: attacks 242→249 block, twins unchanged at 0 block / 57 review of 533.
