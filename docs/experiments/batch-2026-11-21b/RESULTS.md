# Moltbook-families, 2026-11-21

Branch `exp/moltbook-families-1121`, based on main `42d06986` (package version still 0.37.0, PR #161). Deterministic checks only. No model was asked for a verdict.

Draft. Do not merge. Do not release. Do not publish to npm. No version bump.

## Set

`bench/moltbook-families`, set version `moltbook-families-v1`, seed `moltbook-families-20261121`, tree `2620e119d9cda2fb7468267987f60ca59ff62ce706c24f77975c80efba0f561c`.

384 attacks and 384 honest twins. Split is hash-based: dev 374 (185 attacks, 189 twins), held-out 394 (199 attacks, 195 twins). The split was recorded before the rules in this branch were written. Held-out text was not opened while tuning. Dev is not in the README table.

Cisco skill-scanner 2.3.2 and NVIDIA SkillSpector v2.12.0 (`7d9b4be`, `--no-llm`) were scored on this set once, on the same bytes as main `42d06986` and npm 0.37.0. They do not change when Ironheights rules change, so those columns are that run.

## Before / after

Winner is the best cell on that row. Higher is better for attacks. Lower is better for twins and clean skills.

| Set                                      | main 42d06986          | npm 0.37.0              | This PR                            | Cisco 2.3.2 | SkillSpector v2.12.0 | Winner      |
| ---------------------------------------- | ---------------------- | ----------------------- | ---------------------------------- | ----------- | -------------------- | ----------- |
| Main attacks blocked (516)               | 263/516                | 263/516                 | 263/516                            | 113/516     | 134/516              | Ironheights |
| Main attacks block or review             | 315/516                | 315/516                 | 315/516                            | 115/516     | 220/516              | Ironheights |
| Main benign blocked (456)                | 6/456                  | 6/456                   | 6/456                              | 9/456       | 48/456               | Ironheights |
| Main benign block or review              | 30/456                 | 30/456                  | 30/456                             | 11/456      | 141/456              | Cisco       |
| Official Anthropic flagged (19)          | 0/19                   | 0/19                    | 0/19                               | 1/19        | 4/19                 | Ironheights |
| Attack-lanes held-out attacks (659)      | 456/659                | 456/659                 | 456/659                            | 111/659     | 170/659              | Ironheights |
| Attack-lanes held-out twins (641)        | 5/641                  | 5/641                   | 5/641                              | 17/641      | 20/641               | Ironheights |
| Attack-lanes all attacks (1335)          | 956/1335               | 956/1335                | 956/1335                           | 226/1335    | 374/1335             | Ironheights |
| Attack-lanes all twins (1250)            | 11/1250                | 11/1250                 | 11/1250                            | 32/1250     | 45/1250              | Ironheights |
| Script-skills held-out attacks (539)     | 291/539                | 291/539                 | 291/539                            | 174/539     | 154/539              | Ironheights |
| Script-skills held-out twins (493)       | 0/493                  | 0/493                   | 0/493                              | 111/493     | 108/493              | Ironheights |
| Script-skills all attacks (1028)         | 533/1028               | 533/1028                | 533/1028                           | 342/1028    | 295/1028             | Ironheights |
| Script-skills all twins (1026)           | 0/1026                 | 0/1026                  | 0/1026                             | 231/1026    | 225/1026             | Ironheights |
| Blind attacks (600)                      | 340/600                | 340/600                 | 340/600                            | 190/600     | 173/600              | Ironheights |
| Blind benign (300)                       | 13/300                 | 13/300                  | 13/300                             | 6/300       | 35/300               | Cisco       |
| Prose-only attacks (98)                  | 40/98                  | 40/98                   | 40/98                              | 5/98        | 7/98                 | Ironheights |
| Moltbook-families held-out attacks (199) | 45/199                 | 37/199                  | 199/199                            | 8/199       | 20/199               | This PR     |
| Moltbook-families held-out twins (195)   | 1/195                  | 1/195                   | 1/195                              | 0/195       | 17/195               | Cisco       |
| Moltbook-families all attacks (384)      | 79/384                 | 61/384                  | 384/384                            | 14/384      | 34/384               | This PR     |
| Moltbook-families all twins (384)        | 3/384                  | 3/384                   | 3/384                              | 0/384       | 36/384               | Cisco       |
| Real-world clean (5655)                  | 230 block / 452 review | 230 block / ~453 review | 230 block / 452 review, no new ids | not run     | not run              | no new ids  |

Attack-lanes and script-skills were rescanned on this branch with main `42d06986` and this PR. Counts did not move, so the published Cisco and SkillSpector cells still apply. MaliciousSkillBench, Anthropic, prose-only, and the published blind cells are the 0.37.0 / `107fdbe` figures. This PR's blind rescan is in the gate output and matched 340/600 and 13/300. The three global-persist twins this set blocks were already blocked on main `42d06986`.

## Per family (this set, attacks blocked)

| Family              | main 42d06986 | This PR | Cisco 2.3.2 | SkillSpector | Twins this PR |
| ------------------- | ------------- | ------- | ----------- | ------------ | ------------- |
| split-multifile     | 16/32         | 32/32   | 0/32        | 8/32         | 0/32          |
| credential-phishing | 6/32          | 32/32   | 0/32        | 0/32         | 0/32          |
| purpose-mismatch    | 0/32          | 32/32   | 0/32        | 0/32         | 0/32          |
| mcp-poison          | 4/32          | 32/32   | 0/32        | 4/32         | 0/32          |
| global-persist      | 3/32          | 32/32   | 0/32        | 2/32         | 3/32          |
| trust-anchor        | 6/32          | 32/32   | 0/32        | 0/32         | 0/32          |
| staged-loader       | 0/32          | 32/32   | 6/32        | 0/32         | 0/32          |
| control-downgrade   | 0/32          | 32/32   | 0/32        | 0/32         | 0/32          |
| scope-widen         | 0/32          | 32/32   | 0/32        | 0/32         | 0/32          |
| concealment         | 8/32          | 32/32   | 0/32        | 0/32         | 0/32          |
| hidden-obfuscation  | 32/32         | 32/32   | 8/32        | 20/32        | 0/32          |
| lookup-input        | 4/32          | 32/32   | 0/32        | 0/32         | 0/32          |

Held-out moved with dev on every family (both halves reach the same full block count for attacks, and twin blocks did not rise). Hidden-comment attacks were already blocked on main.

## Kept rule ids

IH-NET-027, IH-PRIV-015, IH-FS-010, IH-PRIV-016, IH-PERSIST-017, IH-MCP-013, IH-EXEC-021, IH-NET-028, IH-INTENT-006, IH-CRED-014, IH-FLOW-003, IH-INTENT-007, IH-INJ-035.

## Dropped

None. Three first cuts were narrowed after they blocked a real skill. See `docs/experiments/DISCARDED-RULES.md`. IH-NET-026 stays dropped.

## External real fixtures (scored after the rules were frozen)

Branch `exp/all-ideas-1121b` adds IH-AUDIT-001, IH-NET-029, IH-INTENT-008, and IH-FLOW-004. The rules were committed at `477ada8` before these fixtures were unpacked. The set is the real 21 Nov missed-attacks plus house-601 through house-622: 53 attacks (stepped, core, and prose variants) and 39 twins. Nothing in it was used to change a rule.

| Scanner                         | Attacks blocked | Twins blocked |
| ------------------------------- | --------------- | ------------- |
| main 42d06986                   | 22/53           | 0/39          |
| #162 (`be5d467`)                | 24/53           | 0/39          |
| this branch                     | 25/53           | 0/39          |
| Cisco 2.3.2                     | 4/53            | 0/39          |
| SkillSpector v2.12.0 `--no-llm` | 5/53            | 3/39          |

The generated moltbook-families held-out is 199/199 on #162 and on this branch. That number is not repeated here as an independent result. On the real fixtures the same checks block 25 of 53 attacks. The extra check on this branch is one attack beyond #162. Twin blocks stayed at zero.
