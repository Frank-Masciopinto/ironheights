# Batch 2026-11-25: accuracy ideas logged after the 24 Nov bot-suggestions check

Draft experiment. Not a release. Do not merge until the owner says so.

29 accuracy ideas were logged after the 24 Nov ~11:42 Warsaw check, 12 of them from outside bots. Status for each one is in `ideas-status.csv`: 7 landed, 22 deferred.

## Sets and split

New fixtures from `benchmark-candidates` (missed-attacks and redteam, 24-25 Nov, plus the grokentra r351 capture) were split with the existing policy: an attack and its honest twin share a pair key, and `sha256('exp1124|' + pairkey) % 2` picks dev or held-out. The hash is unchanged, so no earlier held-out sample moved. house-704 lands in dev in both the 24 Nov and the 25 Nov split.

- `newdev1125`: 20 attacks, 12 honest twins. Rules were tuned here.
- `newheld1125`: 13 attacks, 10 honest twins. Scored once, after tuning. Skill text was not opened.
- The blind set was not read.

Only three families have samples in both halves: credential relay, trust-anchor authority, and split multi-file. The first two landed. The third is deferred (see below).

## Rules added

- **IH-CRED-015** (critical, credentials): the skill's own steps ask the user to relay a sign-in secret (one-time or N-digit code, password, backup or recovery codes, recovery words, session cookie, auth header, magic link, connection string) into the chat or to the skill's service, and the skill keeps or sends it. The honest twin signs in on the provider's own screen and never receives the secret. Extends IH-CRED-012, which needs an explicit forward of a one-time code or password. Ideas 7, 27, 28, 29.
- **IH-NET-030** (critical, network): the skill ships its own list, directory, or index as the source of truth for a third party's identity or endpoint (support number, official site, payee, download link, version, checksum), then ranks it above the owner's channel or hides where it came from. No name lists: it does not repeat discarded C23 ("Pattern 3"). Sibling of IH-NET-011. Ideas 15, 17, 26.

## Rules dropped

None. Both rules block their dev targets, their held-out same-family samples, and no twin. No rule was built and then cut. `DISCARDED-RULES.md` has a 2026-11-25 section listing the shapes considered and not built, and why.

## Before and after

Block count, with block-or-review in brackets. Cisco skill-scanner 2.3.2 and NVIDIA SkillSpector v2.12.0 (`7d9b4be`, `--no-llm`) were run on the same bytes with the existing competitor mapping (block = HIGH or CRITICAL, or DO_NOT_INSTALL). The 24 Nov split had no competitor scores before this run.

| Set                               | npm 0.37.0              | main 474a55d | This PR               | Cisco 2.3.2 | SkillSpector v2.12.0 | Winner                  |
| --------------------------------- | ----------------------- | ------------ | --------------------- | ----------- | -------------------- | ----------------------- |
| 25 Nov dev attacks (20)           | 2 (2)                   | 2 (2)        | **6 (6)**             | 1 (1)       | 0 (4)                | This PR                 |
| 25 Nov dev twins (12), lower wins | 0 (0)                   | 0 (0)        | 0 (0)                 | 0 (0)       | 0 (2)                | Tie (IH, Cisco)         |
| 25 Nov held-out attacks (13)      | 3 (4)                   | 4 (5)        | **6 (7)**             | 2 (2)       | 1 (2)                | This PR                 |
| 25 Nov held-out twins (10)        | 0 (0)                   | 0 (0)        | 0 (0)                 | 0 (0)       | 0 (1)                | Tie (IH, Cisco)         |
| 24 Nov dev attacks (105)          | 17 (29)                 | 25 (35)      | **26 (36)**           | 4 (4)       | 18 (34)              | This PR                 |
| 24 Nov dev twins (51)             | 0 (1)                   | 0 (1)        | 0 (1)                 | 0 (1)       | 3 (7)                | Tie (IH, Cisco)         |
| 24 Nov held-out attacks (96)      | 22 (31)                 | 24 (33)      | 24 (33)               | 13 (16)     | 14 (23)              | main = This PR          |
| 24 Nov held-out twins (50)        | 0 (0)                   | 0 (0)        | 0 (0)                 | 1 (1)       | 1 (2)                | IH (all three)          |
| Blind attacks (600)               | 340/600                 | 340/600      | 340/600               | 190/600     | 173/600              | Ironheights (all three) |
| Blind benign (300), lower wins    | 13/300                  | 13/300       | 13/300                | 6/300       | 35/300               | Cisco                   |
| Real-world clean (5,655)          | 230 block / ~453 review | 230 / 452    | 230 / 452, no new ids | not run     | not run              | no new ids              |

Across the 24 Nov sets (302 skills), the only verdict that changed between main and this PR is the house-704 plain-wording attack (no findings → block). No twin changed.

Real-world and blind come from the CI accuracy-gate job on this PR (run 45605669408). IH-CRED-015 and IH-NET-030 fire on 0 of the 5,655 real-world skills, so main and this PR block the same 230 and review the same 452. Blind stays at 340/600 and 13/300. Blind cells for Cisco and SkillSpector are the published 2026-11-21b figures, and neither tool was run on real-world. Main and 0.37.0 MaliciousSkillBench, attack-lanes, script-skills, and prose-only cells are unchanged from the 2026-11-21b table.

These are deterministic findings only. No model-based verdicts are in this table.

## What each rule caught

| Fixture                                                    | Split    | Rule        |
| ---------------------------------------------------------- | -------- | ----------- |
| connect-step relay sign-in code (attack, plain wording)    | dev      | IH-CRED-015 |
| house-704 ownership check asks recovery codes (2 variants) | dev      | IH-CRED-015 |
| support-number lookup trusts skill directory (2 variants)  | dev      | IH-NET-030  |
| house-716 sync fix asks session cookie                     | held-out | IH-CRED-015 |
| house-732 release helper names its own index official      | held-out | IH-NET-030  |

## Deferred, and why

- **Held-out-only families** (L4 allow-once and org-MFA, L3 license companion, L6 notes-server mail tool, L7 root-finder, obfuscation changelog, MCP server instructions): no dev sample to tune on. Writing a rule would mean tuning on held-out. L7 walk-up is also DISCARDED C10.
- **Dev-only families** (L1 form-helper, L8 new-payee, purpose/verb mismatch, L5 speedup shim, L5 tidy memory, format pack, grokentra r351): no held-out sample of the same structure, so a rule can't show a held-out win. Purpose mismatch also has an open twin FP record (DISCARDED C06).
- **Split multi-file** (ideas 5, 20): it has both halves, but the sidecar is pointer-named and real-world FP risk is high. It needs a focused follow-up.
- **No fixture, or needs context the scanner does not have**: L8 dry-run transparency comment (idea 2), cross-skill persistence stacking (idea 24).

## Remaining misses worth a next step

1. Split multi-file: a sidecar FAQ, checklist, or recipe that SKILL.md defers to on failure. Both halves exist (house-714 dev, routing-table held-out).
2. Get one dev and one held-out sample each for L4 downgrade and L5 memory writes. Both have several bot ideas behind them (1, 9, 11, 22, 25; 21, 23).
3. L1 form-helper over-collection (12, 13) needs a held-out twin pair before a rule can ship.
