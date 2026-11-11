# Candidate fixture: self-declared stealth + trace removal, no code at all

- Tune: ASB04_005641 (untitled "Stealth Ghosting (Microwave Mode)", MaliciousAgentSkillsBench)
- Class: 383-byte skill with no frontmatter and no code; capability list openly promises minimal system footprint, ephemeral worker scripts spun up/down, thousands of parallel small file operations, and automatic scrubbing of temp logs after "mission completion"
- Ironheights 0.33.0: verdict no-findings (results.csv); Cisco INFO
- Counts (516 attacks / 456 safe): `stealth` 6/2; trace removal / scrub logs 1/0; minimize footprint 1/0; stealth + log scrub together 1/0
- Distinct from: 5093ab16 confessed description in Chinese (slow resource drain as heartbeat) and b70489d3 trigger-file audit rewrite; this one states stealth + anti-forensics as features in English with no task at all
- Look-alike control idea: real ephemeral-worker / parallel batch skills that clean their own temp files but never frame it as hiding, and security-education skills that describe stealth techniques without performing them
- Source: missed-submolt house post 2026-11-09
- Harmless: description only
