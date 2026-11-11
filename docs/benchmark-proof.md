# Benchmark proof and how to reproduce it

Every cell of the README benchmark table links to
[`PROOF.md` on the `badges` branch](https://github.com/Frank-Masciopinto/ironheights/blob/badges/badges/proof/PROOF.md).
The `benchmark badge` workflow (`.github/workflows/benchmark-badge.yml`) rewrites that page on every
release tag, every merge to `main` and every Monday, together with:

- `results.csv`: one row per skill and scanner on the public set (516 malicious, 456 clean):
  row id, label, scanner, scanner version, verdict (Cisco: max severity; NVIDIA SkillSpector:
  `severity|max_issue_severity|recommendation|score`), whether it counts as
  block and as block-or-review, UTC timestamp and commit SHA.
- `blind-aggregate.json`: counts for the blind held-out set (600/300) plus a SHA-256 over the
  sorted `id:verdict` lines. Per-skill blind verdicts are never published, so the set stays blind
  (see [accuracy-gates.md](accuracy-gates.md)); a rerun reproduces the digest.
- `benchmark-summary.json`: every number in the table, the workflow run URL and the commit.

The workflow run page linked from `PROOF.md` keeps the same files as the `benchmark-badge`
artifact for 30 days.

## Scoring

| Row                                    | Ironheights                 | Cisco skill-scanner                                                                   | NVIDIA SkillSpector                                                                                                                                                          |
| -------------------------------------- | --------------------------- | ------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Detected / false positives / Anthropic | verdict `block`             | max severity HIGH or CRITICAL                                                         | risk severity or max issue severity CRITICAL or HIGH, or recommendation `DO_NOT_INSTALL`                                                                                     |
| Blocked or sent to review              | verdict `block` or `review` | max severity MEDIUM or above (Cisco has no review verdict; LOW and INFO are advisory) | a block, or risk severity or max issue severity MEDIUM, or recommendation `CAUTION`                                                                                          |
| Blind held-out                         | verdict `block`             | max severity HIGH or CRITICAL                                                         | same block rule as the detected row                                                                                                                                          |

Cisco runs with its default static analyzers only (no LLM, VirusTotal or behavioral analyzer, no API key).
The workflow installs the hashed pin in `bench/msb/requirements-cisco.txt`, then upgrades to the
newest `cisco-ai-skill-scanner` release on PyPI; the version used is printed in `PROOF.md`.

NVIDIA SkillSpector runs as `skillspector scan <skill-dir> --no-llm --format json`. `--no-llm` is
static analysis only, with no API key, same as the Cisco column. The commit is the `SkillSpector.git@`
pin in `bench/msb/requirements-nvidia.txt` (lock generated like `requirements-cisco.txt`). Score bands
at that commit: CRITICAL at 81, HIGH at 51, MEDIUM at 21, otherwise LOW. Recommendations are `SAFE`,
`CAUTION`, and `DO_NOT_INSTALL`. `max_issue_severity` is the worst finding and can be HIGH while the
score band is still LOW, so a critical or high finding counts as block even when the score does not.
A skill that produces no report counts as not blocked and stays in the denominator. The public ids are
listed in `benchmark-summary.json`; blind failures are a count only.

The green check on a row is the unique best of the three. A tie gets no check. Higher is better for
detection rows. Lower is better for false positives, clean skills sent to review, and Anthropic skills.

## Reproduce locally

```sh
npm ci && npm run build
python3 -m venv .venv
.venv/bin/pip install pyarrow cisco-ai-skill-scanner
pin="$(sed -n 's/.*SkillSpector\.git@\([0-9a-f]\{40\}\).*/\1/p' bench/msb/requirements-nvidia.txt)"
.venv/bin/pip install --only-binary=:all: "skillspector @ git+https://github.com/NVIDIA/SkillSpector.git@${pin}"
.venv/bin/python scripts/benchmark-msb.py dist/cli/index.js out .venv/bin/skill-scanner .venv/bin/skillspector
cat out/PROOF.md
```

Skill text is fetched from the pinned MaliciousSkillBench revision and anthropics/skills commit and
hash-checked; nothing is executed.
