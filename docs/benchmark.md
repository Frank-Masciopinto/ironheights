# Benchmark

`ironheights bench <corpus>` scores the scanner against a folder of skills and a `labels.json` file. The file is validated with `bench/labels.schema.json`.

Metrics are computed twice:

- a positive result is `review` or `block`
- a positive result is `block` only

Each pass reports true and false positives and negatives, precision, recall, F1, and the false-positive rate. The report also lists per-rule hit counts, missed skills, and wrongly flagged skills.

The public corpus under `bench/corpus` is synthetic. The files are harmless text that matches rules. Every URL uses `.invalid` or `example.com`.

## Real samples

Do not commit real malicious skills. On an isolated machine:

1. Keep the samples on a read-only mount.
2. Do not execute them, and do not let an agent follow them.
3. Point the harness at that folder with `ironheights bench --corpus /path/to/private-corpus` or `IH_CORPUS_DIR`.

`--external other.json` compares another tool. The file looks like this:

```json
{
  "tool": "other",
  "skills": [{ "path": "benign/meeting-notes", "verdict": "no-findings" }]
}
```

Reports are written to `bench/results/latest.md` and `bench/results/latest.json`.

## MaliciousSkillBench results (0.35.0)

Run on 11 Nov 2026 against the same MaliciousSkillBench checkout as 0.34.0 (revision `d4b42ce5`): 516 malicious and 456 clean skills, plus 19 Anthropic skills. Static rules only. No `--llm`. Cisco skill-scanner was not re-run.

| Setting                             | Result          |
| ----------------------------------- | --------------- |
| `block` only                        | 243/516 = 47.1% |
| False positives at `block`          | 6/456 = 1.3%    |
| `review` or `block`                 | 301/516         |
| Clean skills at `review` or `block` | 30/456          |
| Blind held-out attacks at `block`   | 335/600 = 55.8% |
| Blind held-out clean at `block`     | 13/300 = 4.3%   |
| Anthropic skills flagged            | 0/19            |
| Prose-only attacks at `block`       | 40/98 = 40.8%   |
| Prose-only at `review` or `block`   | 55/98 = 56.1%   |
| Real-world clean skills blocked     | 232/5655        |

0.34.0 on the same set was 174/516 block and 11/456 false positives. Cisco skill-scanner 2.3.2: 113/516 (21.9%), 9/456 (2.0%), 1/19 Anthropic. One public attack leaves block (ASB04_003303): its only signal was an emoji joiner. A joiner next to ASCII still blocks. The write-up is [docs/experiments/batch-2026-11-10/RESULTS.md](experiments/batch-2026-11-10/RESULTS.md).

### Ironheights, Cisco, and NVIDIA SkillSpector

Same samples as the table above. Ironheights 0.35.0 and Cisco skill-scanner 2.3.2 are the published figures and were not replaced. NVIDIA SkillSpector v2.12.0 was run on 11 Nov 2026 at commit `7d9b4be35d0f995cc33db72875a62bdbad00db5d`, static mode only (`skillspector scan <skill-dir> --no-llm --format json`, no API key). The 1,872 skill directories (516 + 456 public, 600 + 300 blind; the 19 Anthropic skills are inside the 456) finished in 240 seconds. None failed to scan. A failed scan would stay in the denominator and count as not blocked. ✅ is the best of the three on that row.

| MaliciousSkillBench | Ironheights | Cisco skill-scanner | NVIDIA SkillSpector |
| --- | --- | --- | --- |
| Malicious skills detected (higher is better) | 47.1% (243/516) ✅ | 21.9% (113/516) | 26.0% (134/516) |
| False positives on clean skills (lower is better) | 1.3% (6/456) ✅ | 2.0% (9/456) | 10.5% (48/456) |
| Malicious skills blocked or sent to review (higher is better) | 58.3% (301/516) ✅ | 22.3% (115/516) | 42.6% (220/516) |
| Clean skills blocked or sent to review (lower is better) | 6.6% (30/456) | 2.4% (11/456) ✅ | 30.9% (141/456) |
| Blind held-out attacks blocked (higher is better) | 55.8% (335/600) ✅ | 31.7% (190/600) | 28.8% (173/600) |
| Blind held-out clean skills blocked (lower is better) | 4.3% (13/300) | 2.0% (6/300) ✅ | 11.7% (35/300) |
| Official Anthropic skills flagged (lower is better) | 0/19 ✅ | 1/19 | 4/19 |

NVIDIA verdicts use `risk_assessment` from that JSON report:

- **Block:** score-band severity or `max_issue_severity` is CRITICAL or HIGH, or `recommendation` is `DO_NOT_INSTALL`.
- **Block or review:** a block, or either severity is MEDIUM, or `recommendation` is `CAUTION`.

Score bands at this commit are CRITICAL at 81, HIGH at 51, MEDIUM at 21, and LOW below that. Recommendations are `SAFE`, `CAUTION`, and `DO_NOT_INSTALL`. `max_issue_severity` is the worst finding. It can be HIGH while the score band is still LOW and the recommendation is still `SAFE`; that finding counts as block, the same way Cisco counts its highest severity. `CAUTION` is SkillSpector's review-level label. An incomplete scan that would have been `SAFE` is raised to `CAUTION` by SkillSpector, and that counts as review. LOW with no finding and recommendation `SAFE` counts as neither.

Per-skill public verdicts are `severity|max_issue_severity|recommendation|score` in `results.csv`, one row per scanner, same as the Cisco rows. Blind verdicts stay aggregate-only. The pin and the hashed dependency lock are `bench/msb/requirements-nvidia.txt`.

## MaliciousSkillBench results (0.34.0)

0.34.0 does not change scanner rules beyond what was already merged on main after 0.33.0. The numbers below are the ones those pull requests and the README recorded. They were not re-scored for this release note.

| Setting                             | Result          |
| ----------------------------------- | --------------- |
| `block` only                        | 174/516 = 33.7% |
| False positives at `block`          | 11/456 = 2.4%   |
| `review` or `block`                 | 249/516         |
| Clean skills at `review` or `block` | 31/456          |
| Blind held-out attacks at `block`   | 219/600 = 36.5% |
| Blind held-out clean at `block`     | 15/300 = 5.0%   |
| Anthropic skills flagged            | 0/19            |
| Prose-only attacks at `block`       | 33/98 = 33.7%   |
| Prose-only at `review` or `block`   | 51/98 = 52.0%   |

Prose-only (plain-language) numbers were re-scored on main `de19a25` (0.34.0) on 3 Nov 2026. The 6/98 and 2/98 figures further down are the historical 0.32.0 and 0.29.0 results. The benchmark badge workflow now writes the prose-only rows to the proof page on every run, so this number is kept current there.

Block-or-review was 248/516 (48.1%) after the detection experiment and 249/516 after IH-NET-001 on a cloud-metadata host started counting toward the verdict. Cisco skill-scanner 2.3.2 on the same set: 21.9% detection (113/516), 2.0% false positives (9/456), 1/19 Anthropic skills flagged.

## MaliciousSkillBench results (0.33.0)

Run on 2 Nov 2026 against MaliciousSkillBench (Hugging Face revision `d4b42ce5`): 516 malicious and 456 clean skills, plus 19 Anthropic skills as an extra clean set. Static rules only. 0.33.0 is merged on `main`; on npm it is staged and goes live after maintainer approval.

| Setting             | Detection       | False positives | Anthropic skills flagged |
| ------------------- | --------------- | --------------- | ------------------------ |
| `block` only        | 162/516 = 31.4% | 11/456 = 2.4%   | 0/19                     |
| `review` or `block` | 225/516 = 43.6% | 32/456 = 7.0%   | 0/19                     |

- Held-out half: 33.2% detection (95/286), 3.3% false positives (8/245) at `block`. The new patterns were written after reading missed examples from both halves, so this half is not fully blind for 0.33.0.
- Prose-only (plain-language) attacks: 24/98 caught at `block`, 35/98 at `review` or `block`.
- Cisco skill-scanner 2.3.2 on the same set: 21.9% detection, 2.0% false positives at `block`, 1/19 Anthropic skills flagged.
- Earlier block numbers: 0.32.0 26.6%, 0.30.0/0.31.0 22.7%, 0.29.0 19.8%, all at 2.4% false positives.

## MaliciousSkillBench results (0.32.0)

Run on 2 Nov 2026 against MaliciousSkillBench (Hugging Face revision `d4b42ce5`): 516 malicious and 456 clean skills, plus 19 Anthropic skills as an extra clean set. Static rules only. 0.32.0 is merged on `main`; on npm it is staged and goes live after maintainer approval.

| Setting             | Detection       | False positives | Anthropic skills flagged |
| ------------------- | --------------- | --------------- | ------------------------ |
| `block` only        | 137/516 = 26.6% | 11/456 = 2.4%   | 0/19                     |
| `review` or `block` | 206/516 = 39.9% | 32/456 = 7.0%   | 0/19                     |

- Held-out half (rules were tuned on the other half only): 27.3% detection (78/286), 3.3% false positives (8/245) at `block`.
- Prose-only (plain-language) attacks: 6/98 caught at `block`, 23/98 at `review` or `block`.
- Cisco skill-scanner 2.3.2 on the same set: 21.9% detection, 2.0% false positives at `block`, 1/19 Anthropic skills flagged.
- Earlier block numbers: 0.30.0/0.31.0 22.7% detection, 0.29.0 19.8%, both at 2.4% false positives.

Most malicious skills in this corpus are not caught at `block`. Treat a clean result as "no known patterns found", not as proof of safety.

## MaliciousSkillBench results (0.31.0)

0.31.0 does not change scanner rules, verdicts or grade thresholds. The 0.30.0 block numbers therefore stand: detection 22.7%, false positives 2.4%, Anthropic skills 0/19, on the 2 Nov 2026 set (516 malicious / 456 benign + 19 Anthropic skills). That checkout (`benchmark-2026-11-02`, MaliciousSkillBench revision `d4b42ce5`) is not in this repository, so 0.31.0 did not re-score it. The in-repo 20-skill synthetic bench is unchanged: review recall 1.000, block recall 0.300, 0 false flags.

## MaliciousSkillBench results (0.29.0)

Run on 2 Nov 2026 against MaliciousSkillBench (Hugging Face revision `d4b42ce5`): 516 malicious and 456 clean skills, plus 19 Anthropic skills as an extra clean set. Static rules only.

| Setting             | Detection       | False positives | Anthropic skills flagged |
| ------------------- | --------------- | --------------- | ------------------------ |
| `block` only        | 102/516 = 19.8% | 11/456 = 2.4%   | 0/19                     |
| `review` or `block` | 174/516 = 33.7% | 30/456 = 6.6%   | 0/19                     |

- Held-out half (rules were tuned on the other half only): 20.3% detection, 3.3% false positives at `block`.
- Prose-only (plain-language) attacks are the weak spot: 2/98 caught at `block`, 17/98 at `review` or `block`.
- For comparison, 0.27.0 scored 20.2% detection with 9.9% false positives at `block`.

Most malicious skills in this corpus are not caught at `block`. Treat a clean result as "no known patterns found", not as proof of safety.

## One command

`npm run bench` builds the CLI, downloads the pinned MaliciousSkillBench and Anthropic inputs, checks every file's SHA-256, scans them, and writes `bench/results/public/`. That folder has `results.csv` (one row per public skill), `benchmark-summary.json`, `rules.json` (rule ids for the public set only), and `blind-aggregate.json` (counts and a digest, no skill ids). The `llm` field in the summary is `not-run`: the command does not call a model, and a model opinion never changes those verdicts. See [LABELING.md](LABELING.md) for where each label comes from.

## Automatic README badge

The README's MaliciousSkillBench badge reads `badges/benchmark.json` from the `badges` branch through a shields.io endpoint. The `benchmark badge` workflow rebuilds that file on every release tag (or manual run): it downloads the skill text from the pinned upstream sources listed in `bench/msb/manifest.json` (MaliciousSkillBench at a fixed Hugging Face revision, CC BY 4.0, and `anthropics/skills` at a fixed commit), checks each file against its SHA-256, scans it with the built CLI (nothing is executed), and counts block verdicts. The repository stores only IDs and hashes, never the skill text. Downloads are pinned and hash-checked, and only transient network errors (timeouts, 429, 5xx) are retried, with backoff. If anything else fails, nothing is published, the workflow run fails, and an issue titled "Benchmark badge run failed" is opened so the cause gets fixed.
