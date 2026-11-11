# Benchmark proof

Every number in the README benchmark table comes from this run.

- Workflow run: https://github.com/Frank-Masciopinto/ironheights/actions/runs/43008957367
- Commit: `66108f237fd73aef23a1b82011f9a4c2a3276941`
- Time (UTC): 2026-11-11T11:19:16+00:00
- Ironheights 0.35.0; Cisco skill-scanner 2.3.2; NVIDIA SkillSpector SkillSpector v2.12.0 commit `7d9b4be35d0f995cc33db72875a62bdbad00db5d` (static analyzers only, no LLM)
- MaliciousSkillBench revision `d4b42ce5766a6e0359c987cf59c1007cb3795a90`

| Row | Ironheights | Cisco | NVIDIA SkillSpector |
|---|---|---|---|
| Malicious detected (block) | 243/516 | 113/516 | 134/516 |
| Clean false positives (block) | 6/456 | 9/456 | 48/456 |
| Malicious block or review | 58.3% (301/516) | 22.3% (115/516) | 42.6% (220/516) |
| Clean block or review | 6.6% (30/456) | 2.4% (11/456) | 30.9% (141/456) |
| Blind attacks blocked | 55.8% (335/600) | 31.7% (190/600) | 28.8% (173/600) |
| Blind clean blocked | 4.3% (13/300) | 2.0% (6/300) | 11.7% (35/300) |
| Prose-only attacks blocked | 40.8% (40/98) | 5.1% (5/98) | 7.1% (7/98) |
| Prose-only attacks block or review | 56.1% (55/98) | 5.1% (5/98) | 11.2% (11/98) |
| Anthropic skills flagged | 0/19 | 1/19 | 4/19 |

Prose-only = the 98 attacks with no code fence or shell/python line (`kind: prose` in the manifest; regex tag, see docs/benchmark.md).
Cisco has no review verdict: block = max severity HIGH or CRITICAL, block-or-review = MEDIUM or above.
NVIDIA SkillSpector (`--no-llm`): block = risk severity or max issue severity CRITICAL or HIGH, or recommendation DO_NOT_INSTALL. Block-or-review also counts MEDIUM or recommendation CAUTION. A skill that fails to scan counts as not blocked and stays in the denominator.

Files: [results.csv](results.csv) (one row per skill and scanner), [blind-aggregate.json](blind-aggregate.json)
(blind set counts and a digest only), [benchmark-summary.json](benchmark-summary.json).
How to reproduce: [docs/benchmark-proof.md](https://github.com/Frank-Masciopinto/ironheights/blob/main/docs/benchmark-proof.md).
