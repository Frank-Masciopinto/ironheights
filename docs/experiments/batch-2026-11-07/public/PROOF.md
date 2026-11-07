# Benchmark proof

Every number in the README benchmark table comes from this run.

- Workflow run: local run
- Commit: `fa05c6922fcd6f8de05f85c5a7ebdd398a9b604c`
- Time (UTC): 2026-11-07T07:23:15+00:00
- Ironheights 0.34.0; Cisco skill-scanner not run (static analyzers only, no LLM)
- MaliciousSkillBench revision `d4b42ce5766a6e0359c987cf59c1007cb3795a90`

| Row | Ironheights | Cisco |
|---|---|---|
| Malicious detected (block) | 174/516 |  |
| Clean false positives (block) | 11/456 |  |
| Malicious block or review | 49.6% (256/516) |  |
| Clean block or review | 6.8% (31/456) |  |
| Blind attacks blocked | 36.5% (219/600) |  |
| Blind clean blocked | 5.0% (15/300) |  |
| Prose-only attacks blocked | 33.7% (33/98) |  |
| Prose-only attacks block or review | 53.1% (52/98) |  |
| Anthropic skills flagged | 0/19 |  |

Prose-only = the 98 attacks with no code fence or shell/python line (`kind: prose` in the manifest; regex tag, see docs/benchmark.md).
Cisco has no review verdict: block = max severity HIGH or CRITICAL, block-or-review = MEDIUM or above.

Files: [results.csv](results.csv) (one row per skill and scanner), [blind-aggregate.json](blind-aggregate.json)
(blind set counts and a digest only), [benchmark-summary.json](benchmark-summary.json).
How to reproduce: [docs/benchmark-proof.md](https://github.com/Frank-Masciopinto/ironheights/blob/main/docs/benchmark-proof.md).
