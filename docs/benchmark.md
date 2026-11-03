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

## Automatic README badge

The README's MaliciousSkillBench badge reads `badges/benchmark.json` from the `badges` branch through a shields.io endpoint. The `benchmark badge` workflow rebuilds that file on every release tag (or manual run): it downloads the skill text from the pinned upstream sources listed in `bench/msb/manifest.json` (MaliciousSkillBench at a fixed Hugging Face revision, CC BY 4.0, and `anthropics/skills` at a fixed commit), checks each file against its SHA-256, scans it with the built CLI (nothing is executed), and counts block verdicts. The repository stores only IDs and hashes, never the skill text. Downloads are pinned and hash-checked, and only transient network errors (timeouts, 429, 5xx) are retried, with backoff. If anything else fails, nothing is published, the workflow run fails, and an issue titled "Benchmark badge run failed" is opened so the cause gets fixed.
