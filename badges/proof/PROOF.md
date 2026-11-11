# Benchmark proof

Every number in the README benchmark table comes from this run.

- Workflow run: https://github.com/Frank-Masciopinto/ironheights/actions/runs/43008857319
- Commit: `12b03205784a73791466d4471c527ca44e561437`
- Time (UTC): 2026-11-11T11:07:02+00:00
- Ironheights 0.35.0; Cisco skill-scanner 2.3.2 (static analyzers only, no LLM)
- MaliciousSkillBench revision `d4b42ce5766a6e0359c987cf59c1007cb3795a90`

| Row | Ironheights | Cisco |
|---|---|---|
| Malicious detected (block) | 243/516 | 113/516 |
| Clean false positives (block) | 6/456 | 9/456 |
| Malicious block or review | 58.3% (301/516) | 22.3% (115/516) |
| Clean block or review | 6.6% (30/456) | 2.4% (11/456) |
| Blind attacks blocked | 55.8% (335/600) | 31.7% (190/600) |
| Blind clean blocked | 4.3% (13/300) | 2.0% (6/300) |
| Prose-only attacks blocked | 40.8% (40/98) | 5.1% (5/98) |
| Prose-only attacks block or review | 56.1% (55/98) | 5.1% (5/98) |
| Anthropic skills flagged | 0/19 | 1/19 |

Prose-only = the 98 attacks with no code fence or shell/python line (`kind: prose` in the manifest; regex tag, see docs/benchmark.md).
Cisco has no review verdict: block = max severity HIGH or CRITICAL, block-or-review = MEDIUM or above.

Files: [results.csv](results.csv) (one row per skill and scanner), [blind-aggregate.json](blind-aggregate.json)
(blind set counts and a digest only), [benchmark-summary.json](benchmark-summary.json).
How to reproduce: [docs/benchmark-proof.md](https://github.com/Frank-Masciopinto/ironheights/blob/main/docs/benchmark-proof.md).
