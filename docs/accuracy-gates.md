# Accuracy gates

Every pull request runs the `accuracy gates (real-world FP + blind holdout)` job in `ci.yml`
(`scripts/realworld-gate.py`). It is deterministic: every input is pinned to a revision and
SHA-256 checked, nothing is executed, and only transient download errors are retried.

## 1. Real-world clean set (false positives)

`bench/realworld/manifest.json` lists **5,655 real, published skills** (IDs and SHA-256 only, no text
is committed):

| Source                                                                                                                                | Skills | How they are picked                                                                                                                                                                                                                                                                                                                                                                      | License                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| [GokuScraper/clawhub-skills](https://huggingface.co/datasets/GokuScraper/clawhub-skills) @ `240122b9` (72,788 ClawHub SKILL.md files) | 4,500  | Joined with [OpenClaw/clawhub-security-signals](https://huggingface.co/datasets/OpenClaw/clawhub-security-signals) @ `69dcbd32` (MIT, 67,453 skills); kept only when ClawScan (high confidence), static analysis, VirusTotal **and** NVIDIA SkillSpector all say clean and the scanned version is the text version. Top 3,000 by downloads plus the top 300 of each look-alike category. | CC BY 4.0 compilation; each skill keeps its ClawHub license   |
| [FayeZC/SkillMD-138K](https://huggingface.co/datasets/FayeZC/SkillMD-138K) @ `0d73048a` (138,133 GitHub SKILL.md files)               | 1,155  | Repositories with at least 5,000 stars, at most 20 files per repository.                                                                                                                                                                                                                                                                                                                 | CC BY 4.0 compilation; each file keeps its repository license |

Look-alike categories (a skill can be in several): monitoring/daemon/background 1,330, API key 1,267,
scheduler 914, installer 860, backup 642.

`bench/realworld/baseline.json` lists the skills `main` blocks or sends to review today. **The job fails if a PR blocks,
or sends to review, any skill not on that list.** Removing entries (fixing false positives) is always fine; adding one
needs a written reason in the PR and the maintainer's approval.

## 2. Blind held-out attack set

`bench/blind/manifest.json` is a fixed slice of MaliciousSkillBench (600 malicious, 300 benign) that
is disjoint from `bench/msb/manifest.json` and shares no structural family with it, chosen by
SHA-256 of a fixed salt and the benchmark ID.

**Never open, print, grep or read these skills when writing or tuning rules.** The gate script
prints aggregate counts only. The job fails if blind detection falls below, or blind false
positives rise above, the numbers in `baseline.json`.

## 3. Shadow mode for new checks

A new check tags its findings with `shadowCheck: '<name>'` and adds the name to `SHADOW_CHECKS` in
`src/rules/shadow.ts`. While listed, its findings are logged at `info` with `wouldSeverity` and a
"would block" note and never change the verdict. The gate rescans the real-world set with
`IRONHEIGHTS_SHADOW=enforce` and reports how many skills each shadow check would block. A check is
promoted (removed from `SHADOW_CHECKS`) only when that number is zero; after that the normal gate
protects it.

## Refreshing

`scripts/realworld-build-manifest.py <download dir>` rebuilds both manifests from the pinned
files; then run `scripts/realworld-gate.py dist/cli/index.js out --write-baseline` on `main`.
