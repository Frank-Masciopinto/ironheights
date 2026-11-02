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
