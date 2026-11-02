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
