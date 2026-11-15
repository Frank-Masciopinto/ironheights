# Shipped-script skills benchmark set

A scored set of **multi-file** skills where the malice (or the honest twin's
lack of it) lives in a shipped script (`scripts/*.{py,sh,js,ps1}`) that
`SKILL.md` tells the agent to run. It is separate from the headline
MaliciousSkillBench numbers (those corpora are SKILL.md-only).

- 1028 malicious + 1026 benign (2054 total).
- 2048 generated from a pinned seed (`script-skills-20261115`): 16 attack
  families × 16 disguises × 4 languages, each with an honest twin.
- 6 real-derived fixtures copied from `benchmark-candidates/missed-attacks`
  (2026-11-03 serpent env-dump, 2026-11-03 spider decode-then-exec, 2026-11-13
  reverse-shell helpers).
- Held-out split is hash-based and **must not be read when writing or tuning
  rules**. Score it once.

Hosts are reserved `.invalid` or well-known data-relay names. There are no
real keys. **Nothing in this set is executed.**

## Layout

- `generate.py` — deterministic builder. Writes `samples/`, `labels.json`,
  and `manifest.json` (per-file SHA-256 and a tree hash).
- `real-src/` — the six real-derived fixtures, copied into `samples/` as-is.
- `samples/<id>/` — generated on demand (gitignored); recreate with
  `python3 bench/script-skills/generate.py`. `--check` compares against the
  pinned manifest.
- `labels.json` — per-sample `path`, `label`, `family`, `split`, `source`, `notes`.
- `score.py` — one-command scorer for Ironheights (PR and optional main),
  Cisco skill-scanner 2.3.2, and NVIDIA SkillSpector v2.12.0.
- `results/` — `baseline.md`, `summary.json`, and per-split CSVs.

## Families

secret-exfil, staged-loader, persist-rc, persist-cron, trust-hosts,
auto-approve, reverse-shell, miner-loader, obfuscated-exfil,
credential-harvest, destructive, env-dump, authorized-keys, tls-off,
webhook-settings, clipboard-harvest.

## Split

```
split = "dev" if int(sha256(f"{seed}:{id}").hexdigest()[:8], 16) % 2 == 0 else "heldout"
seed = "script-skills-20261115"
```

If any held-out sample is read for tuning, the held-out part is burned and
must be re-split with a new seed. This set never touches `bench/blind`.

## Reproduce

From the repo root, after `npm run build`:

```
python3 bench/script-skills/score.py \
  --pr dist/cli/index.js \
  --main /path/to/ironheights-0.36.0/dist/cli/index.js \
  --cisco .venv/bin/skill-scanner \
  --nvidia .venv/bin/skillspector
```

Omit `--main` to score only the current CLI. Verdict mappings are the same as
`scripts/benchmark-msb.py` (see `docs/benchmark-proof.md`).
