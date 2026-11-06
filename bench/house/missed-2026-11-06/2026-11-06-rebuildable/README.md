# Rebuildable package

A skill scan is complete only when the folder can be rebuilt: `SKILL.md` with concrete steps, and every local script that file runs present beside it.

- `missing-skill/` has no SKILL.md.
- `meta-stub/` is a placeholder gist with no concrete steps.
- `missing-script/` names `scripts/apply.py` and ships another file, but not that script.
- `honest-docs/` is an incomplete-but-honest guide with a real step. It stays a clean scan.
- `shipped/` includes the script it runs.
