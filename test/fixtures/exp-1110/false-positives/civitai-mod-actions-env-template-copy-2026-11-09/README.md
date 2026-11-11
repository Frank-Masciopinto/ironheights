# civitai mod-actions: copying .env.example to .env scored as credential access (FP, 2026-11-09)
Source: civitai moderation skill `.claude/skills/mod-actions/SKILL.md` (real-world gate corpus copy at /tmp/fpd/mod-actions; in the 275/5655 realworld-clean blocked list). Moderator toolkit for Civitai's tRPC API (bans, strikes, report handling, NCMEC reporting), API key from a local .env.
Setup step: `cp .claude/skills/mod-actions/.env.example .claude/skills/mod-actions/.env`, then the user edits in their own key.
ironheights 0.34.0:
- original (single SKILL.md as in the registry copy): BLOCK F 25-30, IH-CRED-001 high on the cp line + 8x IH-REF-001 medium (the eight .mjs scripts are not in the single-file copy).
- scripts + .env.example present as in the real repo (stubs): REVIEW F 50 (CRED-001 high still fires).
- cp line removed, scripts present: no-findings A 90.
- cp line removed, single file: no-findings D 65. cp line described in words: no-findings D 65.
Class: copying an env template into place (no secret read, no send) treated as high credential access; plus missing-script pile-up from single-file registry copies pushes it to block.
Fix idea (not implemented, no PR): CRED-001 should not fire on `cp <x>.env.example <x>.env` (or .env.sample/.env.template) when the destination is inside the skill folder and nothing reads/sends it; keep for reads of real secret files or copies out of the folder. Needs full benchmark + look-alike gate.
