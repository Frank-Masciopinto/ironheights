# Script-scan experiment — progress

Updated: 2026-11-15 19:07 Europe/Warsaw

Branch: `exp/script-scan` (worktree `/workspace/ih-scriptscan`).
Base was `e871705` (PR #148). `origin/main` is now `590ac5f` (Release 0.36.0, includes #148). Rebase onto it after the pending WIP commit. Do NOT merge. Do not touch release / version / npm / site files.

## Status: tightens + official gates done; look-alike GH "flips" look like an incomplete la-main index — verifying against the 590ac5f CLI.

### Done
- Read DISCARDED-RULES.md. Implemented IH-SCR-001/002/003/005 + extract/join infrastructure.
- Dropped IH-SCR-004 (real-world FPs: npmmirror, pytorch CPU index, ClawHub registry).
- Stopped feeding virtual fences to the general rule set (had caused 4,729 look-alike flips).
- Tightened: named fences only; no raw-IP sinks; official installer hosts; persist skips comments.
- Further tightens: fence closers must match opener indent and have no info string; namedFencePath previous-line names only from "save as / write to / filename:"; IH-SCR-003 carries must be on the write statement (or a bound secret/URL), not a nearby curl; bare `crontab` is not a write.
- Full tests: 874 passed. Official MSB: 260/516 block, 314 bor, 6/456 FP (same as post-#148 main). Official gate: 232/452 real-world, blind 335/600 and 13/300 (same as main). Per-rule official hits: 0 (SKILL.md-only corpora + named-fence-only).
- Full 173,071 look-alike rescan (`/tmp/ih-scr-la4`) with the tightened CLI: 0 IH-SCR hits. ClawHub 34,938: 0 verdict flips vs la-main (6,252 flagged, exact match). GitHub: 4,636 skills flagged that are absent from la-main.txt (main index has only 5,949 of 138,133 GH skills). None of those 4,636 are IH-SCR findings (NET/PRIV/CRED/EXEC etc.). Next: rescan them with the 590ac5f CLI to confirm they are not new.

### In flight
- Commit remaining WIP, rebase onto 590ac5f, confirm the 4,636 GH skills against main, fill RESULTS, push, open draft PR.

### Constraints honored
- Blind/held-out scored only, not tuned.
- Zero new official FPs. Zero IH-SCR look-alike hits after tightens.
- No merge. No release-file edits.
