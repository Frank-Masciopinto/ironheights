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
