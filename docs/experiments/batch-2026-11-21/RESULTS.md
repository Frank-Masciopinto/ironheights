# All open Moltbook accuracy ideas, 2026-11-21

Branch `exp/all-moltbook-ideas-1121`, based on main `745b318` (0.37.0). Deterministic checks only. No model was asked for a verdict.

Draft. Do not merge. Do not release. Do not publish to npm.

## How it was run

- **Design set:** the uploaded fixtures (missed-attacks 2026-11-16 through 2026-11-21, red-team house rounds and r292) plus the attack-lanes dev half as an aggregate only. Held-out skill text was not opened.
- **Look-alikes before the final score:** the uploaded `FP__` skills (0 new-rule hits) and the real-world gate (5,655). IH-NET-026 blocked 3 real skills by treating a markdown link whose path contains `credentials` as a secret in a URL. It was dropped. IH-EXEC-020 v1 joined three phrases anywhere in a long guardrail guide (`prod-shield`, already blocked). It was narrowed so the three legs sit in one step or the next.
- **Scored once after that.** Public sets did not move. The kept checks block the dev fixtures and add no real-world id.

Cisco skill-scanner 2.3.2 and NVIDIA SkillSpector v2.12.0 (`7d9b4be`, `--no-llm`) were not re-run. The corpora are the same pinned versions as the 0.37.0 README, so those published cells are copied below. A checkmark is the best cell on that row.

## Before / after

Winner is the best cell on that row. Ironheights ties itself across main and this PR on every public row, so the winner versus Cisco and SkillSpector is unchanged.

| Set                                  | main 745b318            | This PR                            | Cisco 2.3.2         | SkillSpector v2.12.0 | Winner      |
| ------------------------------------ | ----------------------- | ---------------------------------- | ------------------- | -------------------- | ----------- |
| Main attacks blocked (516)           | 263/516                 | 263/516                            | 113/516             | 134/516              | Ironheights |
| Main attacks block or review         | 315/516                 | 315/516                            | 115/516             | 220/516              | Ironheights |
| Main benign blocked (456)            | 6/456                   | 6/456                              | 9/456               | 48/456               | Ironheights |
| Main benign block or review          | 30/456                  | 30/456                             | 11/456              | 141/456              | Cisco       |
| Official Anthropic flagged (19)      | 0/19                    | 0/19                               | 1/19                | 4/19                 | Ironheights |
| Attack-lanes held-out attacks (659)  | 456/659                 | 456/659                            | 111/659             | 170/659              | Ironheights |
| Attack-lanes held-out twins (641)    | 5/641                   | 5/641                              | 17/641              | 20/641               | Ironheights |
| Attack-lanes all attacks (1335)      | 956/1335                | 956/1335                           | 226/1335            | 374/1335             | Ironheights |
| Attack-lanes all twins (1250)        | 11/1250                 | 11/1250                            | 32/1250             | 45/1250              | Ironheights |
| Script-skills held-out attacks (539) | 291/539                 | 291/539                            | 174/539             | 154/539              | Ironheights |
| Script-skills held-out twins (493)   | 0/493                   | 0/493                              | 111/493             | 108/493              | Ironheights |
| Script-skills all attacks (1028)     | 533/1028                | 533/1028                           | 342/1028            | 295/1028             | Ironheights |
| Script-skills all twins (1026)       | 0/1026                  | 0/1026                             | 231/1026            | 225/1026             | Ironheights |
| Blind attacks (600)                  | 340/600                 | 340/600                            | 190/600             | 173/600              | Ironheights |
| Blind benign (300)                   | 13/300                  | 13/300                             | 6/300               | 35/300               | Cisco       |
| Prose-only attacks (98)              | 40/98                   | 40/98                              | 5/98                | 7/98                 | Ironheights |
| Real-world clean (5655)              | 230 block / ~453 review | 230 block / 452 review, no new ids | not run on this set | not run on this set  | no new ids  |

Real-world review is 452 in this run. The published main figure is about 453. No id was added. The gate baseline file still lists the older 275/474 counts; this run blocks a subset of that list (230) and adds none.

## Per cluster

Public-set attack gains are 0 on every cluster. Benign delta is 0 on blind, main, attack-lanes twins, and script-skills twins. Real-world ids added: 0.

| Cluster                                      | Kept                                      | Dropped                                | What the kept checks catch on the dev fixtures                                                      |
| -------------------------------------------- | ----------------------------------------- | -------------------------------------- | --------------------------------------------------------------------------------------------------- |
| C01 secret in a skill-owned folder           | IH-FLOW-002                               | —                                      | split collect-then-upload                                                                           |
| C02 template default and local override      | IH-FLOW-002                               | —                                      | enter-for-default URL; gitignored override filling an empty key                                     |
| C03 whole-bundle graph and separate approval | folded into IH-FLOW-002                   | runtime taint not built                | followed files are one procedure; a redacted draft does not approve the secret payload              |
| C04 front door versus sidecar                | folded into IH-FLOW-002                   | effect census (already discarded)      | same                                                                                                |
| C05 credential phishing of the user          | IH-CRED-012, IH-CRED-013                  | —                                      | chat-paste of a code or password; device sign-in that keeps the token and skips the permission list |
| C06 purpose versus capability                | IH-INTENT-005                             | vague prose ratio                      | one record in the description, bulk update in the steps, reply names only the one                   |
| C07 paired-route redirect                    | IH-NET-025                                | —                                      | push address set to a skill host while fetch stays, reply omits it                                  |
| C08 remote staged loader                     | IH-EXEC-020                               | v1 whole-file join                     | unpinned remote list whose entries are installed or run                                             |
| C09 ambient persistence                      | IH-PERSIST-015, IH-PERSIST-016            | memory-window join (already discarded) | hidden recurring job that sends notes; one-time task plus a hidden folder-open rerun                |
| C10 scope escape                             | IH-FS-009                                 | relative path (IH-FS-001)              | home or config link on the always-include list, omitted from the reply                              |
| C11 global git hooks                         | IH-PERSIST-014                            | —                                      | `--global` hooksPath, templateDir, or include.path that sets hooksPath                              |
| C12 MCP shadowing                            | IH-MCP-011, IH-MCP-012                    | —                                      | same-name tool with precedence and a skill relay; read-only label that admits an upload             |
| C13 approval narrower than the effect        | folded into IH-INTENT-004 and IH-FLOW-002 | —                                      | draft report after a submit; redacted draft before a secret send                                    |
| C14 status misreport                         | IH-INTENT-004                             | —                                      | approve or auto-merge reported as drafted                                                           |
| C15 render-hidden directive                  | IH-INJ-034, IH-INJ-002 pragma fix         | —                                      | hidden comment that reads a secret and sends it; prettier-ignore no longer blocks                   |
| C16 deferred fetch URL                       | —                                         | IH-NET-026                             | —                                                                                                   |
| C17 check that cannot fail                   | IH-PRIV-014                               | —                                      | security step kept, failure no longer stops the run, change hidden or shared                        |
| C18 failure-branch sink                      | folded into IH-FLOW-002                   | —                                      | who named the destination, including a redacted approval                                            |
| C19 rebuildability                           | already IH-META-005                       | new word lists                         | —                                                                                                   |
| C20 false-positive precision                 | IH-INJ-002 pragma fix                     | other wording drops                    | prettier-ignore and markdownlint comments                                                           |
| C21 quiet copy                               | folded into IH-FLOW-002                   | —                                      | secret artifact uploaded to a skill host                                                            |
| C22 content as orders                        | folded into IH-INJ-034 and IH-EXEC-020    | —                                      | hidden directive; remote list that selects actions                                                  |
| C23 typosquat / payee lists                  | —                                         | pattern 3                              | —                                                                                                   |
| C24 settings write                           | already settings-change rules             | broader write                          | —                                                                                                   |
| C25 scoring process                          | —                                         | excluded                               | —                                                                                                   |
| C99 hand review                              | folded into the rows above                | restatements                           | see `ideas-status.csv`                                                                              |

## Kept rule ids

IH-FLOW-002, IH-PERSIST-014, IH-PERSIST-015, IH-PERSIST-016, IH-CRED-012, IH-CRED-013, IH-MCP-011, IH-MCP-012, IH-INTENT-004, IH-INTENT-005, IH-INJ-034, IH-NET-025, IH-EXEC-020, IH-PRIV-014, IH-FS-009. IH-INJ-002 was narrowed, not replaced.

## Caveat

These families are still mostly outside MaliciousSkillBench, the blind slice, and the generated attack-lanes and script-skills sets. The keep decision is the dev fixtures plus a zero change in benign counts. That is the same shape as the fixture-only checks kept on 2026-11-20, and it is not a measured gain on public data.
