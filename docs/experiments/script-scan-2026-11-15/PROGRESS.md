# Script-scan experiment — progress

Updated: 2026-11-15 19:15 Europe/Warsaw

Branch: `exp/script-scan` (PR https://github.com/Frank-Masciopinto/ironheights/pull/150, draft).
Rebased onto `590ac5f` (0.36.0). Do NOT merge.

## Status: building the ≥1000 shipped-script benchmark set for PR #150 (Kaleb t441u).

### Next up
- Inventory showed almost no public multi-file malicious skills with shipped scripts (official MSB/look-alikes/real-world are SKILL.md-only; missed-attacks has a handful of script-bearing fixtures; monthly ClawHub crawl is unlabeled).
- Build a pinned `bench/script-skills` set: ≥1024 malicious + ≥1024 honest twins, mostly generated variants across 16 families × 16 disguises × 4 languages, plus the real-derived script fixtures we do have.
- Held-out split is hash-based; do not tune IH-SCR rules on this set.
- Score Ironheights main (590ac5f), PR #150, Cisco 2.3.2, SkillSpector v2.12.0. Add the table to README/docs so it appears on merge. One-command scorer + CI manifest check.
