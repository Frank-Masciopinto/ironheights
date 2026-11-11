# Nov 11 accuracy rows, one experiment, 2026-11-11

One branch off `b3c3f6468c07cee11a905b6804257abe49d0f7b3` (main, the #136 squash). New checks live in `src/rules/exp-1111.ts`. Each finding is tagged with `shadowCheck`. The names are not in `SHADOW_CHECKS`: the real-world enforce list was empty, so the checks are promoted. The model column was not run. Version was not bumped. This is a draft experiment. Do not merge it.

`docs/experiments/DISCARDED-RULES.md` was read first, including the 2026-11-10 and 2026-11-11 paper runs (unshipped-reference authority 24/456, unshipped reference plus a destination 14/456, imperative run 68/456, unconditional run). Ideas that match a discarded rule or a common failure pattern were skipped or redesigned. Every kept check needs two signals.

## Before / after versus main

Both public columns were scanned on this machine. Public set: MaliciousSkillBench `d4b42ce5766a6e0359c987cf59c1007cb3795a90`, 516 malicious / 456 benign, deterministic, no `--llm`. Cisco skill-scanner was not re-run. The reference row is the published Cisco 2.3.2 number from `docs/benchmark.md`.

The historical held-out half (286 malicious / 245 benign) is the split cited from `benchmark-2026-11-02/v030/RESULTS.md`. That id list is not in this repository. The half below is the same stand-in PR #136 used: public ids whose SHA-256 starts with an odd byte (266 malicious / 228 benign). It is not the unpublished 286/245 list.

No public attack moved off block. No public safe skill changed verdict. No blind attack moved off block. Blind clean stayed 13/300. Anthropic stayed 0/19.

| Metric                                    | main `b3c3f64`                                         | experiment              | change         |
| ----------------------------------------- | ------------------------------------------------------ | ----------------------- | -------------- |
| Detection at block                        | 243/516 (47.1%)                                        | 252/516 (48.8%)         | +9             |
| False positives at block                  | 6/456 (1.3%)                                           | 6/456 (1.3%)            | 0              |
| Block or review                           | 301/516                                                | 309/516                 | +8             |
| False positives at block or review        | 30/456                                                 | 30/456                  | 0              |
| Anthropic skills flagged                  | 0/19                                                   | 0/19                    | 0              |
| Held-out half at block (id hash, 266/228) | 126/266 block, 4/228 FP                                | 133/266 block, 4/228 FP | +7 block, 0 FP |
| Blind attacks at block                    | 335/600                                                | 335/600                 | 0              |
| Blind clean skills at block               | 13/300                                                 | 13/300                  | 0              |
| Prose-only attacks at block               | 40/98                                                  | 40/98                   | 0              |
| Prose-only block or review                | 55/98                                                  | 55/98                   | 0              |
| Real-world clean blocked                  | 232/5655 (post-#136; the CI file still lists 275)      | 232/5655                | 0 new ids      |
| Real-world clean sent to review           | 452/5655 (the CI file still lists 474)                 | 452/5655                | 0 new ids      |
| Cisco reference (not re-run)              | 113/516 (21.9%) block, 9/456 (2.0%) FP, 1/19 Anthropic | same reference          | —              |

The CI baseline file was not rewritten. The gate reports 0 new block ids and 0 new review ids. The blind set was not opened. The gate prints counts only.

Look-alike fixtures in `test/fixtures/exp-1111/` (handwritten near misses, public benign keyword copies, and six ClawHub skills: filesystem chmod, `--mode`, cron, telemetry, preflight, sandbox) had zero hits from the new rules. The 5,655 real-world skills had zero hits from every new rule id.

## Per rule

Public attacks are 516 and public safe skills are 456. "New blocks" counts public attacks that were not block on main and are block now, and that carry the rule.

| Rule                                                       | Public attacks flagged | New public blocks | Rows                       | Public safe | Look-alikes | Real-world skills flagged |
| ---------------------------------------------------------- | ---------------------- | ----------------- | -------------------------- | ----------- | ----------- | ------------------------- |
| IH-FS-003 secret opened to a group or the world            | 2/516                  | 2                 | ASB04_006382, ASB04_004004 | 0/456       | 0           | 0/5655                    |
| IH-INJ-028 `instruction-override` flag value on a command  | 1/516                  | 1                 | ASB04_000101               | 0/456       | 0           | 0/5655                    |
| IH-EXEC-012 PR comments treated as work, then `git push`   | 1/516                  | 1                 | ASB04_001380               | 0/456       | 0           | 0/5655                    |
| IH-NET-009 seconds-level sender, free-form details, no URL | 1/516                  | 1                 | ASB04_005906               | 0/456       | 0           | 0/5655                    |
| IH-EXEC-013 env-selected git runtime plus a spend key      | 1/516                  | 1                 | ASB04_003158               | 0/456       | 0           | 0/5655                    |
| IH-INJ-029 verdict sync with no local fallback             | 1/516                  | 1                 | ASB04_003306               | 0/456       | 0           | 0/5655                    |
| IH-NET-010 preflight registration quotes the receipt       | 1/516                  | 1                 | ASB04_002784               | 0/456       | 0           | 0/5655                    |
| IH-EXEC-014 workspace file, if present, wraps the commands | 1/516                  | 1                 | ASB04_004302 (was review)  | 0/456       | 0           | 0/5655                    |
| IH-EXEC-015 dropped policy file multiplies fan-out         | 1/516                  | 0 (already block) | ASB04_000683               | 0/456       | 0           | 0/5655                    |

IH-EXEC-014 is the one new block that was already at review, so block-or-review rises by 8 while block rises by 9.

## Dropped

See `docs/experiments/DISCARDED-RULES.md`. Short form:

- Counting fenced docs-example mediums once toward block moved ASB04_006523 from block to review. Same findings. Not kept. `sudo apt-get install` stayed high.
- Provider key plus standing auto-refill matches the real `flow-nexus-platform` skill, which is in the clean set and is ASB04_001790. Not kept.
- Flag values `no-sandbox` and `unrestricted` added one blind clean block. The kept check is only `instruction-override` on a command.
- "World-readable key is compromised, set 600" (wireguard) and a `chmod 777` / `API_KEY` regex example (hookify writing-rules) matched the first widen check. The kept check skips that warning and a pattern quote.
- Not built: unpinned `npx` (ASB04_005884), verdict taken from an unshipped template (ASB04_006270), corporate-speak scope grab (ASB04_000452, ASB04_000932). Role-binding was not attempted.

## Reproduce

From a clean checkout, with `pyarrow` installed:

```
npm run build
IH_GATE_CACHE=~/.cache/ih-gate python3 scripts/realworld-gate.py dist/cli/index.js /tmp/ih-gate
python3 scripts/benchmark-msb.py dist/cli/index.js /tmp/ih-bench
```

Do not pass `--llm`. Do not open `bench/blind` or `bench/untouched` skill text.
