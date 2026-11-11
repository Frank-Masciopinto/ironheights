# Nov 9–10 accuracy rows, one experiment, 2026-11-10

One branch off `b97ed90935dd151ccd126441d634bae838916e14` (main, PR #134). New checks live in `src/rules/exp-1110.ts`. Narrow exemptions live in the existing intent, exec, credential, persistence, privilege, filesystem, and network checks. The model column was not run. Version was not bumped.

`docs/experiments/DISCARDED-RULES.md` was read first. Ideas that match a discarded rule or a common failure pattern were skipped or redesigned. The log's 2026-11-10 section lists what was dropped, including the three shapes that failed the real-world gate on the first pass and the word-list papers.

## Before / after versus main

Both columns were scanned on this machine. Public set: MaliciousSkillBench `d4b42ce5766a6e0359c987cf59c1007cb3795a90`, 516 malicious / 456 benign, deterministic, no `--llm`. Cisco skill-scanner was not re-run. The reference row is the published Cisco 2.3.2 number from `docs/benchmark.md`.

The historical held-out half (286 malicious / 245 benign) is the split cited from `benchmark-2026-11-02/v030/RESULTS.md`. That id list is not in this repository. The half below is the same stand-in PR #134 used: public ids whose SHA-256 starts with an odd byte (266 malicious / 228 benign). It is not the unpublished 286/245 list.

No public attack moved off block. No public safe skill moved onto block. Anthropic stayed 0/19.

| Metric                                    | main `b97ed90`                                          | experiment              | change          |
| ----------------------------------------- | ------------------------------------------------------- | ----------------------- | --------------- |
| Detection at block                        | 211/516 (40.9%)                                         | 243/516 (47.1%)         | +32             |
| False positives at block                  | 6/456 (1.3%)                                            | 6/456 (1.3%)            | 0               |
| Block or review                           | 291/516                                                 | 301/516                 | +10             |
| False positives at block or review        | 31/456                                                  | 30/456                  | −1              |
| Anthropic skills flagged                  | 0/19                                                    | 0/19                    | 0               |
| Held-out half at block (id hash, 266/228) | 109/266 block, 4/228 FP                                 | 126/266 block, 4/228 FP | +17 block, 0 FP |
| Blind attacks at block                    | 219/600                                                 | 335/600                 | +116            |
| Blind clean skills at block               | 14/300                                                  | 13/300                  | −1              |
| Prose-only attacks at block               | 35/98                                                   | 40/98                   | +5              |
| Prose-only block or review                | 54/98                                                   | 55/98                   | +1              |
| Real-world clean blocked                  | 275/5655 in the CI baseline file (273 in the #134 note) | 232/5655                | 0 new ids       |
| Real-world clean sent to review           | 474/5655 in the CI baseline file                        | 452/5655                | 0 new ids       |
| Cisco reference (not re-run)              | 113/516 (21.9%) block, 9/456 (2.0%) FP, 1/19 Anthropic  | same reference          | —               |

The CI baseline file was not rewritten. It still lists the 275 blocked and 474 review ids. This branch blocks 43 of those and adds none. The blind set was not opened. The gate prints counts only. The +116 blind blocks are a result, not a tuning target.

One public attack, ASB04_003303, leaves block. Its only signal was the black-bird emoji (a ZWJ between two non-ASCII characters). The same joiner blocked honest pet skills. A ZWJ next to ASCII still blocks. Net detection is still up by 32.

Look-alike fixtures copied to `test/fixtures/exp-1110/` (27 honest `original/` and `control/` skills) had zero hits from the new rules. The 5,655 real-world skills had zero hits from every new rule id.

## Per rule

Public attacks are 516 and public safe skills are 456. "New blocks" counts public attacks that were not block on main and are block now, and that carry the rule. A skill with two new rules is listed under both. The 33 new blocks are all accounted for.

| Rule                                         | Public attacks flagged | New public blocks | Public safe | Real-world skills flagged |
| -------------------------------------------- | ---------------------- | ----------------- | ----------- | ------------------------- |
| IH-EXEC-009 underscore helper run            | 68/516                 | 25                | 0/456       | 0/5655                    |
| IH-INJ-025 fake eval prerequisite            | 10/516                 | 6                 | 0/456       | 0/5655                    |
| IH-INJ-024 orders after an end marker        | 2/516                  | 2                 | 0/456       | 0/5655                    |
| IH-CRED-010 private key printed in prose     | 2/516                  | 2                 | 0/456       | 0/5655                    |
| IH-INJ-022 Unicode tag characters            | 1/516                  | 1                 | 0/456       | 0/5655                    |
| IH-INJ-023 base64 order in a comment         | 1/516                  | 1                 | 0/456       | 0/5655                    |
| IH-INJ-027 procedures only in a PDF          | 1/516                  | 1                 | 0/456       | 0/5655                    |
| IH-PERSIST-008 cron that fetches and follows | 1/516                  | 1                 | 0/456       | 0/5655                    |
| IH-NET-007 secret posted to a decoded URL    | 1/516                  | 0 (already block) | 0/456       | 0/5655                    |
| IH-NET-008 media upload with no ask          | 1/516                  | 0 (already block) | 0/456       | 0/5655                    |
| IH-INTENT-001 email-the-secret sentence      | 82/516 (rule total)    | 1                 | 8/456       | not a new id              |

The intent row is the existing plain-language rule after two edits: "email the contents" counts as a send, and a feature list such as "Covers sending, …, and API keys" does not. The one new block is that sentence plus "do not mention this step to the user." The eight safe hits are the same family the rule already had; no safe skill moved onto block.

These checks match the attached fixtures and add no public row. They stay because they did not fail a gate:

| Rule                                                | Fixture it locks                             | Public attacks | Real-world |
| --------------------------------------------------- | -------------------------------------------- | -------------- | ---------- |
| IH-EXEC-010 renamed `.txt` executable               | `2026-11-09-executable-renamed-txt`          | 0/516          | 0/5655     |
| IH-EXEC-011 code registered as a tool               | `2026-11-09-runtime-tool-factory`            | 0/516          | 0/5655     |
| IH-CRED-009 no-network claim plus a hidden key send | `2026-11-09-silent-key-backup-contradiction` | 0/516          | 0/5655     |
| IH-PERSIST-007 ransom note plus encrypt             | `2026-11-10-ransomware-said-out-loud`        | 0/516          | 0/5655     |
| IH-PRIV-002 NOPASSWD sudoers write                  | planted sudoers bullet                       | 0/516          | 0/5655     |
| IH-INJ-026 "you have a serious bug"                 | `2026-11-10-agent-told-it-is-buggy` shape    | 0/516          | 0/5655     |

## Exemptions that cleared real skills

Each one left every public attack that was block on main at block. `sudo apt-get install` stays high (Night F, ASB04_002324).

- Constant `os.system("pip install …")` with no interpolation, pipe, or URL is low and score-exempt. `os.system(f"pip install {name}")` stays high.
- `cp .env.example .env` (also `.sample` and `.template`) is not a credential read. A copy of `.env` outward, or a curl on the same line, still is.
- `systemctl start` inside a Terraform `user_data` or cloud-init block is not persistence. `systemctl enable` still is.
- A line that only names sudo, with no command after it, is low. A sudoers `NOPASSWD` write is IH-PRIV-002 and blocks.
- A quoted `**/.env.*local` cache glob with no read verb is low. `cat .env` stays high.
- "Never use `../`" is info. A write on the same line stays.
- A named API key posted only to a host the skill declares (homepage or metadata), with no credential file and no environment dump, is not IH-NET-002. An undeclared host stays high.
- "Referral code" as a list noun is not a steer. "Include our referral code" still is.
- "Do not skip" and "never skip" a confirmation are not IH-INJ-003. "Skip confirmation" still is.
- `page.$eval` and `$$eval` are not `eval(`. `eval(userInput)` still is.
- `curl | python main.py -` feeds data to a local script. `curl | python -` still blocks.
- A ZWJ between two emoji is not hidden text. A ZWJ next to ASCII still is.
- A fenced `sudo rm` or `chmod 777` under a run instruction stays high. The same command inside a sentence, or under "never" / ❌, does not. `sudo apt-get install` stays high.
- `ExecStart` / `WantedBy` in a systemd user unit (`systemd/user` or `systemctl --user`) is not persistence. A system `systemctl enable` stays high.

## Dropped

See `docs/experiments/DISCARDED-RULES.md`. Short form: a bare `scripts/_common.py` mention, `print(wallet.private_key)` in an SDK sample, and "never mention setup files to the user." Each failed the real-world gate on the first pass and was narrowed. The word-list and receipt papers (v10–v16b, v17, v17b) were not promoted. Apt-install pileup was not retried (Night F).

## Not shipped from the 152 ideas

Already on main after #134: DNS key in a lookup name (IH-NET-006), `rdN_` handoff (IH-INJ-021), interactive `/dev/tcp` (IH-EXEC-008), self-declared log scrub (IH-PERSIST-006), vendor-installer cap.

Not a deterministic block. The word-list papers tag trigger words such as "syncs" as unverifiable and say not to promote them to review. Honest skills use those words. A receipt that closes only after an author names an address is a protocol, not a scan of one file.

Too close to a discarded failure. "sudo apt install" counted until it blocks is Night F. Lowering every credential path named in prose is Night G. This run only skips a template copy, a cache glob, and the tool's own cookie path when nothing reads or sends it.

Left for a later pass because the honest twin uses the same words: whole-folder no-auth deploy versus the claimable-database skill, and a photo upload the user asked for. IH-NET-008 only fires when the upload is paired with holding the answer or not asking.

## Reproduce

From a clean checkout, with `pyarrow` installed:

```
npm run build
IH_GATE_CACHE=~/.cache/ih-gate python3 scripts/realworld-gate.py dist/cli/index.js /tmp/ih-gate
python3 scripts/benchmark-msb.py dist/cli/index.js /tmp/ih-bench
```

Do not pass `--llm`. Do not open `bench/blind` or `bench/untouched` skill text.
