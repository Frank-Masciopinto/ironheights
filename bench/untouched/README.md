# Untouched test set (frozen 2026-11-03)

508 skills: 208 malicious, 300 assumed clean. **IDs and SHA-256 hashes only; no skill text is stored here.**

Rules:
- Never open, print, grep or read these skills when writing or tuning rules.
- Scored only at release, in aggregate (detection and false positives). No per-skill output is published or inspected.
- Once any of these skills is read for tuning, the set is burned and a new one must be frozen.

How it was built (without reading text): MaliciousSkillBench (rev `d4b42ce5`) rows not in `bench/msb` or `bench/blind`, from structural families not used anywhere, one per family, max 50 per upstream source (only 208 such families exist). Clean side: GitHub SKILL.md files, one per author, not in the real-world baseline or the look-alike set. These are assumed clean, not hand-reviewed. Seed `20261103`.
