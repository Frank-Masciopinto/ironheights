# Settings-change rules, one experiment, 2026-11-14

One branch off `70fee4d` (main, the #146 squash). New checks live in `src/rules/settings-change.ts`. Each finding carries a `shadowCheck` tag. The names are not in `SHADOW_CHECKS`: the real-world enforce scan would block 0 and review 0, so the checks are promoted, as in #142. The model column was not run. The version was not bumped. This is a draft experiment. Do not merge it.

`docs/experiments/DISCARDED-RULES.md` was read first. Hide-line-only rules (P5, Batch-1103 H), single-keyword rules (pattern 3) and house-only targets (pattern 6) were not rebuilt. Rules were designed only on the `dev` half of `bench/settings-change` (67 samples). The `heldout` half (44 samples, seed `settings-change-20261114`) was scored once and never opened. `bench/blind` was not opened.

## What the checks do

Each check works per step (a list item or paragraph; tables, quotes, fenced code and front matter are skipped) and needs two signals: a change step and no consent step.

- **IH-PRIV-003, critical.** A step gives standing access or a copy to a party written into the skill (address, URL, account number) or widens a share to anyone, nothing in the step waits for the user's yes, and the step or the two after it hides the change from the summary, accepts it for the user, or leaves it on for good. A target the user owns and names is not a hit (rossum). Ideas: fromthebot (scope plus disclosure), teenydroid (widens who can reach you), ariesai / evil_robot_jas (told vs changed), lulu_the_succubus (consent), rootoffork / hermes_on_foot (party never named by the user).
- **IH-PRIV-004, critical.** A step switches a protection off (two-step sign-in, security alerts, sign-in prompts, alarm, lock or latch, auto shut-off, PIN, phishing warning, approval limit, ask-first line, an expiry), with no consent and no restore or time limit in the step, and it is hidden, self-accepted or left that way. A quoted settings line ("ask before any swap") is read as the protection, not as consent. Ideas: teenydroid (restore check), wren_of_somerville (non-restoration), akasha_thdp / evil_robot_jas (state change needs a yes), fromthebot (no restore and safeguard never named).
- **IH-PRIV-005, high (review).** A step routes the user's mail, calls, money, location or home access to a fixed recipient (address, phone or account number), with no consent step, and the skill's description does not name that job. Ideas: lulu_the_succubus (consent, not destination), fromthebot (scope), nyna (settings-as-action).

Every finding gives the step as evidence, says why (who gains access or which safeguard goes), and gives a safe next step.

## Before / after

Public set: MaliciousSkillBench `d4b42ce`, 516 malicious / 456 benign, deterministic, no `--llm`. Main was re-measured on this machine (252/516 after #142; the 0.35.1 release figure is 243/516). Cisco and SkillSpector are static scanners and were not re-run on the public set; their published numbers are shown. Both were re-run on the settings-change set.

| Set                        | Metric                                  | Ironheights main   | Ironheights experiment        | Cisco 2.3.2 | SkillSpector v2.12.0 |
| -------------------------- | --------------------------------------- | ------------------ | ----------------------------- | ----------- | -------------------- |
| MSB 516/456                | Attacks blocked                         | 252/516 (48.8%)    | 253/516 (49.0%)               | 113/516     | 134/516              |
| MSB 516/456                | Safe skills wrongly blocked             | 6/456 (1.3%)       | 6/456 (1.3%)                  | 9/456       | 48/456               |
| MSB 516/456                | Block or review / FP at block or review | 309/516, 30/456    | 309/516, 30/456               | —           | —                    |
| MSB                        | Anthropic skills flagged                | 0/19               | 0/19                          | 1/19        | —                    |
| Blind (counts only)        | Attacks / clean blocked                 | 335/600, 13/300    | 335/600, 13/300               | —           | —                    |
| Prose-only                 | Blocked / block or review               | 40/98, 55/98       | 40/98, 55/98                  | —           | —                    |
| Settings-change dev        | Attacks blocked / review / missed       | 0 / 3 / 32 of 35   | 33 / 1 / 1 of 35              | 0 / 0 / 35  | 0 / 2 / 33           |
| Settings-change dev        | Honest twins wrongly blocked            | 0/32               | 0/32                          | 0/32        | 0/32                 |
| Settings-change held-out   | Attacks blocked / review / missed       | 0 / 1 / 20 of 21   | 6 / 0 / 15 of 21              | 0 / 0 / 21  | 0 / 3 / 18           |
| Settings-change held-out   | Honest twins wrongly blocked            | 0/23               | 0/23                          | 0/23        | 0/23                 |
| Real-world clean (CI gate) | Blocked / review                        | 232/5655, 452/5655 | 232/5655, 452/5655, 0 new ids | —           | —                    |

The one new public block is ASB04_005375 (review to block): an email skill that adds a fixed outside address to BCC on every multi-recipient mail. No public attack moved off block and no safe skill changed verdict.

The held-out result (6 of 21 blocked) is far below dev (33 of 35). The checks fit the dev wording more than the class. That gap is the main finding of this run.

## Per rule

| Rule                                           | Dev attacks | Held-out attacks | Twins flagged (dev+held-out) | MSB attacks          | MSB safe | Real-world 5655 | ClawHub 35,000 | GitHub SKILL.md 138,133 | Other look-alikes 17,916 |
| ---------------------------------------------- | ----------- | ---------------- | ---------------------------- | -------------------- | -------- | --------------- | -------------- | ----------------------- | ------------------------ |
| IH-PRIV-003 hidden outside grant               | 20/35       | 4/21             | 0/55                         | 0/516                | 0/456    | 0               | 0              | 0                       | 0                        |
| IH-PRIV-004 protection off, no restore         | 13/35       | 2/21             | 0/55                         | 0/516                | 0/456    | 0               | 0              | 0                       | 0                        |
| IH-PRIV-005 unasked route to a fixed recipient | 1/35        | 0/21             | 0/55                         | 1/516 (ASB04_005375) | 0/456    | 0               | 0              | 0                       | 0                        |

Look-alikes: the full ClawHub crawl (35,000 skills) and the GitHub SKILL.md set (138,133 files), which include the real forwarding, sync, backup, sharing, webhook, DNS, 2FA and admin skills; the earlier look-alike pools (17,779 `lookalike-c` skills, the night/lion/batch pools, `benchmark-candidates/false-positives`); and 8 handwritten look-alikes in `test/fixtures/settings-change/lookalikes` (forwarding skill that asks, own-drive backup, vacation reply with end date, time-boxed 2FA off, user-named collaborator, user-picked DNS, attack write-up, family calendar shared after a yes).

## Dropped or tightened

See `docs/experiments/DISCARDED-RULES.md`. Short form:

- Hide, persist and self-accept read anywhere in the file: 250/35,000 ClawHub hits (tables, front matter, long docs with "just say" or "permanently deleted"). Kept: the change step and the two steps after it.
- IH-PRIV-005 on any grant object plus any URL: 58/35,000 ClawHub hits (install-the-extension links, webhook docs to the user's own endpoint, "create an app password" docs, share-with-team recipes). Kept: route objects plus a fixed recipient. This lost the dev attack `ma13-handoff-to-peer-skill-public-share`.
- Bare "public" / "make the repo public" as a wider audience: release and publishing skills. Kept: "anyone with the link", "any requester", "everyone"/"public" on a sharing or privacy setting, "all websites", password protected to open.
- Past-tense "disabled" / "deleted" as an off verb: a Postgres doc ("OpenSSL disabled compression") and "permanently deleted" notes.
- "Silence" as a noun: blocked the public safe skill `anthropic_discernment-nudge` (6/456 to 7/456, Anthropic 0/19 to 1/19). Kept: "silence the/it/all/any".
- Security write-ups that quote the change (a BCC-injection test doc, a Postmark incident write-up): skipped with a describes-an-attack guard (pattern 1).

## Bot ideas from 2026-11-13 and 2026-11-14

`moltbook/tracking/feedback.csv` has 251 rows for the two days (235 accuracy ideas). How each was handled:

- **Folded into IH-PRIV-003/004/005** (settings-change class): the five named ideas, plus nyna, claudecoderu-d286, melodicsequence, wren_of_somerville, rossum (permission flip, unbounded share, sync target, touched-what), asinhhc rulings 13-27, hermes_on_foot, bluecipherbrandon (safe-sender), theagatha (recipient delta), rootoffork (principal provenance), aurewanders (push URL), iofrogman81 (payroll), mrmuse / chittygemzy / tatermolt (MDM, remote config is not user-owned), fineprint, vigthedavidsino, codexofweights (DNS), ecdys (category mismatch, as the description scope test), and the self-found settings rows (webhook, cross-account role, transfer lock, DMARC, AV exclusions, required reviews, port forward, second sync profile, recording share, car key, patient proxy, second parent, page admin, SIM-swap). Folded in means the rule covers the shape; it does not mean each fixture is caught.
- **Runtime checks, not static rules (not built):** before/after state diff at run start and end (teenydroid, letras4, tatermolt trust store, rootoffork scratch-repo diff, evil_robot_jas post-run receipt), rossum's runtime signer record, sparkagent_oc's reply-vs-request diff. The static analogue (restore and consent in the step) is in IH-PRIV-004.
- **Skipped, near-duplicate of a discarded rule:** hide line on its own (fibihermes, ironheights row 43, fromthebot silence-line): P5 / Batch-1103 H; it is used only as the raise-to-block signal. Prose ranking hints and "verified" wording (asinhhc): pattern 3/4. Wider send verbs (ironheights rows 52/57, nyna): pattern 3. Reverse shell as helper code (ecdys): IH-EXEC-016, dropped 2026-11-13. Look-alike fixes for telegram, clawdmint, remind-me and 4todo: same shape as the img402 / fast-io / claw2claw / deep-thinking fixes dropped on 2026-11-13 (one fixture moves, no benchmark change).
- **Skipped, house-only target with no scored set (pattern 6):** quiet destination swap, marker-line consent, chat-history exfil with no URL, calendar away-dates plus address, mid-task credential, data-category severity, dormant usage trigger, cross-skill handoff, a skill editing another skill, unnamed destination, foreign-language step, audience-gated exfil, standing-notes trust lines, password reuse and typing, credentials in a plain notes file, scare message for a card, one-time-code relay. These need their own scored set first, like `bench/settings-change`.
- **Not scanner rules:** Colosseum reader and placer protocol (asinhhc, hina-secretary, dynamo), the "untested lanes" report column (dynamo), funding questions, thanks.

## Reproduce

From a clean checkout, with `pyarrow` installed:

```
npm run build
cp -r bench/settings-change /tmp/sc && python3 /tmp/sc/score.py dist/cli/index.js <skill-scanner> <skillspector>
IH_GATE_CACHE=~/.cache/ih-gate python3 scripts/realworld-gate.py dist/cli/index.js /tmp/ih-gate
python3 scripts/benchmark-msb.py dist/cli/index.js /tmp/ih-bench
```

Copy the set to `/tmp` so the scorer does not rewrite the frozen baseline in `bench/settings-change/results`. Do not pass `--llm`. Do not open `bench/blind`, `bench/untouched` or the held-out samples.
