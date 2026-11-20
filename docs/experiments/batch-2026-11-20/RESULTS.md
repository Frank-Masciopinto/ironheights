# Detection ideas, 2026-11-20

Branch `exp/detect-ideas-1120`, based on main `5c15ce7` (#156). Deterministic checks only. No model was asked for a verdict.

Draft. Do not merge. Do not release. Do not publish to npm.

## How it was run

- **Design set:** attack-lanes dev (676 attacks, 609 twins) plus the uploaded fixtures (missed-attacks 2026-11-16 through 2026-11-20, red-team house-573 through house-582). Held-out rows were not opened while the checks were written.
- **Look-alikes before the final score:** the synthetic corpus (`bench/corpus`, 20 skills, 0 hits) and the real-world gate (5,655). IH-PERSIST-013 v1 blocked 28 real-world skills by joining a documentation URL to a memory path on a neighboring line. It was narrowed so the written line itself has to name the writer's target, then the gate was run again.
- **Scored once after that narrow, and once more after IH-PRIV-013 was removed** (it was the only check that moved the blind benign count). The numbers below are the second, final build.
- **Held-out half of the 516/456:** the same stand-in as PR #134. A public id is in the half when the first byte of `SHA-256(id)` is odd (266 malicious, 228 benign). It is not the unpublished 286/245 list.
- Cisco 21.9% / 2.0% is the published skill-scanner 2.3.2 figure on this same 516/456 (113/516 blocked, 9/456 wrongly blocked). It was not re-run.

## Before / after

| Metric                                              | main 5c15ce7                  | This branch                | Change |
| --------------------------------------------------- | ----------------------------- | -------------------------- | ------ |
| Detection at block (516)                            | 263/516 (51.0%)               | 263/516 (51.0%)            | 0      |
| False positives at block (456)                      | 6/456 (1.3%)                  | 6/456 (1.3%)               | 0      |
| Block or review, attacks                            | 315/516                       | 315/516                    | 0      |
| Block or review, benign                             | 30/456                        | 30/456                     | 0      |
| Held-out half, attacks blocked                      | 138/266                       | 138/266                    | 0      |
| Held-out half, benign blocked                       | 4/228                         | 4/228                      | 0      |
| Held-out half, attacks block or review              | 165/266                       | 165/266                    | 0      |
| Held-out half, benign block or review               | 14/228                        | 14/228                     | 0      |
| Attack-lanes held-out attacks blocked               | 412/659                       | 456/659                    | +44    |
| Attack-lanes held-out twins blocked                 | 5/641                         | 5/641                      | 0      |
| Attack-lanes held-out, generated attacks blocked    | 344/511                       | 381/511                    | +37    |
| Attack-lanes held-out, generated twins blocked      | 5/523                         | 5/523                      | 0      |
| Attack-lanes held-out, real-derived attacks blocked | 68/148                        | 75/148                     | +7     |
| Attack-lanes held-out, real-derived twins blocked   | 0/118                         | 0/118                      | 0      |
| Held-out L1 attacks blocked                         | 66/118                        | 72/118                     | +6     |
| Held-out L2 attacks blocked                         | 51/66                         | 52/66                      | +1     |
| Held-out L3 attacks blocked                         | 44/61                         | 47/61                      | +3     |
| Held-out L4 attacks blocked                         | 87/129                        | 87/129                     | 0      |
| Held-out L5 attacks blocked                         | 31/69                         | 51/69                      | +20    |
| Held-out L6 attacks blocked                         | 45/79                         | 53/79                      | +8     |
| Held-out L7 attacks blocked                         | 48/64                         | 48/64                      | 0      |
| Held-out L7 twins blocked                           | 5/63                          | 5/63                       | 0      |
| Held-out L8 attacks blocked                         | 40/73                         | 46/73                      | +6     |
| Anthropic skills flagged                            | 0/19                          | 0/19                       | 0      |
| Cisco skill-scanner 2.3.2 (reference)               | 113/516 (21.9%), 9/456 (2.0%) | same reference, not re-run | —      |
| Blind attacks blocked                               | 340/600                       | 340/600                    | 0      |
| Blind benign blocked                                | 13/300                        | 13/300                     | 0      |
| Prose-only attacks blocked                          | 40/98                         | 40/98                      | 0      |
| Script-skills held-out attacks blocked              | 284/539                       | 291/539                    | +7     |
| Script-skills held-out twins blocked                | 0/493                         | 0/493                      | 0      |
| Settings-change held-out attacks blocked            | 8/21                          | 8/21                       | 0      |
| Settings-change-fresh attacks blocked               | 28/67                         | 28/67                      | 0      |

Held-out L1–L6 and L8 twins stayed at 0 blocked. The 5 held-out twin blocks are all L7 and are unchanged from main.

Attack-lanes dev (design set, not the keep decision): attacks blocked 463/676 → 500/676, twins blocked 6/609 → 6/609.

## What was kept

Each check is a structure. A sentence the dev samples happened to use is not the rule.

| Rule           | Structure                                                                                                                                                                                                                                                                                                                 | Bots                                                                                                                                                                                                                        |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| IH-PERSIST-013 | A write into a file a later session re-reads (AGENTS.md, CLAUDE.md, memory, shell rc, git hook, folder-open task) whose own line runs a target the writer named: a URL that is fetched and followed, or a lifecycle event plus a URL, `curl \| bash`, or a phone-home. "After each commit, run the tests" does not match. | felixnexus, evil_robot_jas, moltcrusta, chittygemzy, zhixu, entitylovestudio, nyxkavakebi, iriscoremeal, dynamo, woodbot, rossum, neuralnewscast, zionplex, oomjo3, finmaster, symbolon, jarvousai, pennyworthatyourservice |
| IH-PRIV-012    | A state change (a send to a host the skill names, a webhook or registry edit, a wiped history file) within a few steps of an order to leave that change out of the reply, the summary, or the diff.                                                                                                                       | rock_agent, agentboone                                                                                                                                                                                                      |
| IH-EXEC-019    | The skill overwrites its own helper or scripts from an unpinned URL, or runs `npx`/`pip` `@latest` on every run and says not to pin.                                                                                                                                                                                      | ironheights-house, Klara                                                                                                                                                                                                    |
| IH-INJ-033     | An unpinned playbook or rules file is fetched and followed, including when "follow it" is the next step. A local reviewed file is not this check.                                                                                                                                                                         | Klara, ironheights-house                                                                                                                                                                                                    |
| IH-FS-008      | A cleanup walks upward to a `.cache` or home marker, calls that the project root, and deletes without showing the list. Stopping at `.git` is not this check.                                                                                                                                                             | jazzyai                                                                                                                                                                                                                     |
| IH-INTENT-003  | The description is only "align or pad a table / the open file", and a step sends home-folder settings or runs a command a remote service returned.                                                                                                                                                                        | dynamo, agentboone, Starfish                                                                                                                                                                                                |
| IH-MCP-010     | A tool description tells the agent to call this server before another server's tool, or the skill registers itself as `filesystem` / `memory` / `send_message` so the real one is shadowed.                                                                                                                               | bnb_hq                                                                                                                                                                                                                      |
| IH-NET-024     | A glossary the skill says to obey defines a term as a credential file or a host the skill picked, and the main file then gathers or shares that term. Asking the user first is not this check.                                                                                                                            | LazyBearAI, ariesai                                                                                                                                                                                                         |

## What was dropped

See `docs/experiments/DISCARDED-RULES.md`, section 2026-11-20.

- **IH-PERSIST-013 v1** joined a URL anywhere near a memory path. 28 real-world blocks. Narrowed before the final score. The narrowed check is the one in the table above.
- **IH-PRIV-013** (morrowmind, claudecoderu-d286, ironheights-house) treated "any command, from now on" and a user-level `bypassPermissions` write as the per-action guard downgrade. It blocked 2 blind benign skills and no new blind attack. Not registered. The release-helper fixture is still blocked by IH-PRIV-012 (the reply says the checks passed and says not to mention the skip).

## Caveats

- The public 516/456 and its odd-byte half did not move. These families are still mostly outside MaliciousSkillBench. The keep decision is the attack-lanes held-out split: +44 attacks blocked, twins blocked unchanged at 5.
- Part of the held-out gain is the other half of generated templates (wording the dev split did not use). That is what the split is for, and it did move (+37 generated, +7 real-derived). It is still a template benchmark, not a sample of skills in the wild.
- IH-FS-008, IH-INTENT-003 and IH-NET-024 did not move attack-lanes held-out. They block the uploaded fixtures (the cleanup that walks to `.cache`, the table formatter, the glossary) and they did not block the fixture controls. Treat them as unmeasured on public data.
- House-575 (env and GitHub CLI settings handed to a skill desk) and the prose form of house-573 (registry change with no `https://`) are still no-findings. Not tuned after the freeze.
- Real-world and blind were scored as aggregates. Blind skill text was not opened. Blind matches main (340/600 blocked, 13/300 benign blocked). A fresh real-world scan of main and of this branch both block 230/5,655 and send 453/5,655 to review. The committed baseline file is behind current main (it still says 275 and 474); neither scan added a skill the other blocks.
