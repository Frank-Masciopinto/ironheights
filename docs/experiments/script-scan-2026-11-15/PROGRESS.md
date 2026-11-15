# Script-scan experiment — progress

Updated: 2026-11-15 19:10 Europe/Warsaw

Branch: `exp/script-scan` (worktree `/workspace/ih-scriptscan`), rebased onto `590ac5f` (Release 0.36.0).
Do NOT merge. Release / version / npm / site files were not edited in this experiment.

## Status: complete except draft PR open + push. Official counts unchanged vs main; 0 new FPs.

### Done
- Read DISCARDED-RULES.md. Implemented IH-SCR-001/002/003/005 + extract/join infrastructure.
- Dropped IH-SCR-004 and the other branches logged in DISCARDED-RULES.md.
- Tightens: named fences only; no raw-IP sinks; official installer hosts; persist skips comments; fence closers match indent / no info string; save-as cues only; persist carries on the write statement.
- Rebased onto 590ac5f (0.36.0). Full tests: 874 passed.
- Official MSB: 260/516 block, 314 bor, 6/456 FP (same as main). Official gate: 232/452 real-world, blind 335/600 and 13/300 (same as main). Per-rule official and look-alike IH-SCR hits: 0.
- Full 173,071 look-alike rescan: 0 IH-SCR hits. ClawHub 34,938: 0 flips vs la-main. The 4,636 GitHub skills flagged by this PR but missing from la-main were rescanned with the 590ac5f CLI: 4,636/4,636 identical verdicts and rule sets (la-main's GH index was incomplete). 0 new FPs vs live main.
- RESULTS.md filled.

### Next
- Commit RESULTS, push (force-with-lease after rebase), open a DRAFT PR. Do not merge.
