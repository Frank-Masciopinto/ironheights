# Benchmark proof

Every number in the README benchmark table comes from this run.

- Workflow run: https://github.com/Frank-Masciopinto/ironheights/actions/runs/42782334343
- Commit: `b97ed90935dd151ccd126441d634bae838916e14`
- Time (UTC): 2026-11-10T08:26:11+00:00
- Ironheights 0.34.0; Cisco skill-scanner 2.3.2 (static analyzers only, no LLM)
- MaliciousSkillBench revision `d4b42ce5766a6e0359c987cf59c1007cb3795a90`

| Row | Ironheights | Cisco |
|---|---|---|
| Malicious detected (block) | 211/516 | 113/516 |
| Clean false positives (block) | 6/456 | 9/456 |
| Malicious block or review | 56.4% (291/516) | 22.3% (115/516) |
| Clean block or review | 6.8% (31/456) | 2.4% (11/456) |
| Blind attacks blocked | 36.5% (219/600) | 31.7% (190/600) |
| Blind clean blocked | 4.7% (14/300) | 2.0% (6/300) |
| Prose-only attacks blocked | 35.7% (35/98) | 5.1% (5/98) |
| Prose-only attacks block or review | 55.1% (54/98) | 5.1% (5/98) |
| Anthropic skills flagged | 0/19 | 1/19 |

Prose-only = the 98 attacks with no code fence or shell/python line (`kind: prose` in the manifest; regex tag, see docs/benchmark.md).
Cisco has no review verdict: block = max severity HIGH or CRITICAL, block-or-review = MEDIUM or above.

Files: [results.csv](results.csv) (one row per skill and scanner), [blind-aggregate.json](blind-aggregate.json)
(blind set counts and a digest only), [benchmark-summary.json](benchmark-summary.json).
How to reproduce: [docs/benchmark-proof.md](https://github.com/Frank-Masciopinto/ironheights/blob/main/docs/benchmark-proof.md).
