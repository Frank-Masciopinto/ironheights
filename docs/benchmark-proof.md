# Benchmark proof and how to reproduce it

Every cell of the README benchmark table links to
[`PROOF.md` on the `badges` branch](https://github.com/Frank-Masciopinto/ironheights/blob/badges/badges/proof/PROOF.md).
The `benchmark badge` workflow (`.github/workflows/benchmark-badge.yml`) rewrites that page on every
release tag, every merge to `main` and every Monday, together with:

- `results.csv`: one row per skill and scanner on the public set (516 malicious, 456 clean):
  row id, label, scanner, scanner version, verdict (Cisco: max severity), whether it counts as
  block and as block-or-review, UTC timestamp and commit SHA.
- `blind-aggregate.json`: counts for the blind held-out set (600/300) plus a SHA-256 over the
  sorted `id:verdict` lines. Per-skill blind verdicts are never published, so the set stays blind
  (see [accuracy-gates.md](accuracy-gates.md)); a rerun reproduces the digest.
- `benchmark-summary.json`: every number in the table, the workflow run URL and the commit.

The workflow run page linked from `PROOF.md` keeps the same files as the `benchmark-badge`
artifact for 30 days.

## Scoring

| Row                                    | Ironheights                 | Cisco skill-scanner                                                                   |
| -------------------------------------- | --------------------------- | ------------------------------------------------------------------------------------- |
| Detected / false positives / Anthropic | verdict `block`             | max severity HIGH or CRITICAL                                                         |
| Blocked or sent to review              | verdict `block` or `review` | max severity MEDIUM or above (Cisco has no review verdict; LOW and INFO are advisory) |
| Blind held-out                         | verdict `block`             | max severity HIGH or CRITICAL                                                         |

Cisco runs with its default static analyzers only (no LLM, VirusTotal or behavioral analyzer, no API key).
The workflow installs the hashed pin in `bench/msb/requirements-cisco.txt`, then upgrades to the
newest `cisco-ai-skill-scanner` release on PyPI; the version used is printed in `PROOF.md`.

## Reproduce locally

```sh
npm ci && npm run build
python3 -m venv .venv
.venv/bin/pip install pyarrow cisco-ai-skill-scanner
.venv/bin/python scripts/benchmark-msb.py dist/cli/index.js out .venv/bin/skill-scanner
cat out/PROOF.md
```

Skill text is fetched from the pinned MaliciousSkillBench revision and anthropics/skills commit and
hash-checked; nothing is executed.
