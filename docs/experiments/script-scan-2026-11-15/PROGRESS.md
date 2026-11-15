# Script-scan experiment — progress

Updated: 2026-11-15 19:55 Europe/Warsaw

Branch: `exp/script-scan`, draft PR https://github.com/Frank-Masciopinto/ironheights/pull/150.
Rebased onto `590ac5f` (0.36.0). Do NOT merge.

## Status: shipped-script set scored and added to the README/docs tables on the PR branch.

### Set
- 1028 malicious + 1026 honest twins (2054). 2048 generated (16 families × 16 disguises × 4 langs) + 6 real-derived missed-attack fixtures.
- Seed `script-skills-20261115`, tree `64730fbc…`. Held-out scored once, not used to tune.
- Dataset fix only: log-rotate twin official host was `.invalid` (14 false IH-SCR-001 blocks); changed to api.datadoghq.com and re-scored. No rule changes.

### Scores (all / held-out)
- IH PR: 405/1028 block (39.4%), 598 bor, 0/1026 FP. Held-out 214/539, 0/493 FP.
- IH main 590ac5f: 287/1028 (27.9%), 566 bor, 0 FP. Held-out 159/539, 0 FP.
- Cisco 2.3.2: 342/1028, 415 bor, 231/1026 FP.
- SkillSpector v2.12.0: 295/1028, 703 bor, 225/1026 FP.

Tables are in README, docs/benchmark.md, bench/script-skills/results/baseline.md, and RESULTS.md. One-command: npm run bench:script-skills. CI: generate.py --check test + badge workflow also scores the set. Waiting on Kaleb; do not merge.
