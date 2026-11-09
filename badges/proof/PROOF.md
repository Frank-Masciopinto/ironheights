# Benchmark proof

Every number in the README benchmark table comes from this run.

- Workflow run: https://github.com/Frank-Masciopinto/ironheights/actions/runs/42580335327
- Commit: `6c6c022ef072edbf25a63c37231008a9f23d8ea6`
- Time (UTC): 2026-11-09T07:38:00+00:00
- Ironheights 0.34.0; Cisco skill-scanner 2.3.2 (static analyzers only, no LLM)
- MaliciousSkillBench revision `d4b42ce5766a6e0359c987cf59c1007cb3795a90`

| Row | Ironheights | Cisco |
|---|---|---|
| Malicious detected (block) | 174/516 | 113/516 |
| Clean false positives (block) | 11/456 | 9/456 |
| Malicious block or review | 49.6% (256/516) | 22.3% (115/516) |
| Clean block or review | 6.8% (31/456) | 2.4% (11/456) |
| Blind attacks blocked | 36.5% (219/600) | 31.7% (190/600) |
| Blind clean blocked | 5.0% (15/300) | 2.0% (6/300) |
| Prose-only attacks blocked | 33.7% (33/98) | 5.1% (5/98) |
| Prose-only attacks block or review | 53.1% (52/98) | 5.1% (5/98) |
| Anthropic skills flagged | 0/19 | 1/19 |

Prose-only = the 98 attacks with no code fence or shell/python line (`kind: prose` in the manifest; regex tag, see docs/benchmark.md).
Cisco has no review verdict: block = max severity HIGH or CRITICAL, block-or-review = MEDIUM or above.

Files: [results.csv](results.csv) (one row per skill and scanner), [blind-aggregate.json](blind-aggregate.json)
(blind set counts and a digest only), [benchmark-summary.json](benchmark-summary.json).
How to reproduce: [docs/benchmark-proof.md](https://github.com/Frank-Masciopinto/ironheights/blob/main/docs/benchmark-proof.md).
