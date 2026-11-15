# Settings-change rules, redesign after #147 review, 2026-11-14

Draft experiment on `experiment/settings-change-rules` (base `70fee4d`). Do not merge.

Kaleb's review of the first version: the rules fit the dev wording (dev 33/35 blocked vs held-out 6/21). This version detects the attack idea instead. The first version is logged in `docs/experiments/DISCARDED-RULES.md`, along with every variant dropped during the redesign.

## The idea the checks read

A skill changes the user's authorisation surface without the user. The checks read it as a diff of who can reach the user's data, money, code, accounts or home, and what guards them (fineprint).

- **Widen (IH-PRIV-003).** One order has three parts close together: a grant verb (add, invite, share, forward, set, transfer, trust, link, expose, publish and similar, in five languages), an access surface (delegate, admin, owner, member, guardian, proxy, recovery, allowlist, safe senders, identity provider, role binding, authorised keys, deploy keys, OAuth redirect, payee, payout, forward, BCC, webhook, push URL, registry, resolver, MX, port, share, album, calendar, location, household, camera, digital key), and a party outside the user. That party is an address, account, key, wallet, phone or host written into the skill, or anyone/public. ariesai: an order that names a new person, address or account the user never gave is a finding even when no surface word is present.
- **Weaken (IH-PRIV-004).** One order puts an operator (turn off, disable, remove, bypass, exempt, skip, set to off/never/none/0, a permissive config value, approving a sign-in prompt for the user) next to a protection. Strong protections are sign-in gates (2FA, passkeys, sign-in verification, account PINs), AV, firewall, DMARC/SPF, TLS checks, audit logs, door and screen locks, latches, alarms, shut-offs, parental controls, and indicator lights. Soft safeguards are limits, notifications, confirmations, approval steps, ordinary logging and plain verification. theagatha: an indicator or watching light switched off blocks on its own.
- **What decides severity.** None: a consent step, a prohibition, an attack write-up, a target the user owns or names, a job the skill's description is about (including the vendor the skill is for), or a time-boxed or test-only weakening. Block: the change is hidden from what the skill tells the user, accepted for the user, left on with no restore, missing from a nearby report, or removes a sign-in gate. Review: any other strong change. Soft safeguards, outside roles and code examples need an explicit sign (hidden, accepted for the user, or left on for good).
- **Where it looks.** Prose orders (list items, paragraphs; tables, quotes and front matter skipped), plus code lines from fenced blocks and from files the skill names (`scripts/`, `references/`). Units under "Never", "Red flags" and similar headings are skipped.

The checks use shadow tags (`settings-outward-access`, `settings-protection-weakened`). They are promoted the #142 way: the real-world enforce scan would block 0 and review 0.

## Before / after

Main benchmark: MaliciousSkillBench `d4b42ce`, deterministic, no `--llm`. Cisco and SkillSpector main-benchmark figures are their published numbers. Both were re-run on every settings-change set.

| Set                                                         | Metric                          | Ironheights main   | #147 (v1)       | This redesign   | Cisco 2.3.2 | SkillSpector v2.12.0 |
| ----------------------------------------------------------- | ------------------------------- | ------------------ | --------------- | --------------- | ----------- | -------------------- |
| MSB 516/456                                                 | Attacks blocked                 | 252/516            | 253/516         | 252/516         | 113/516     | 134/516              |
| MSB 516/456                                                 | Safe wrongly blocked            | 6/456              | 6/456           | 6/456           | 9/456       | 48/456               |
| MSB                                                         | Block-or-review, attacks / safe | 309/516, 30/456    | 309/516, 30/456 | 309/516, 30/456 | —           | —                    |
| MSB                                                         | Anthropic skills flagged        | 0/19               | 0/19            | 0/19            | 1/19        | —                    |
| Blind (counts only)                                         | Attacks / clean blocked         | 335/600, 13/300    | 335/600, 13/300 | 335/600, 13/300 | —           | —                    |
| Settings-change dev (design set)                            | Blocked / review / missed of 35 | 0 / 3 / 32         | 33 / 1 / 1      | 33 / 2 / 0      | 0 / 0 / 35  | 0 / 2 / 33           |
| Settings-change dev                                         | Twins wrongly flagged           | 0/32               | 0/32            | 0/32            | 0/32        | 0/32                 |
| Old held-out (**already seen**, used for the #147 decision) | Blocked / review / missed of 21 | 0 / 1 / 20         | 6 / 0 / 15      | 8 / 1 / 12      | 0 / 0 / 21  | 0 / 3 / 18           |
| Old held-out                                                | Twins wrongly blocked           | 0/23               | 0/23            | 0/23            | 0/23        | 0/23                 |
| **Fresh held-out** (scored once)                            | Blocked / review / missed of 67 | 0 / 4 / 63         | 13 / 3 / 51     | **26 / 3 / 38** | 0 / 0 / 67  | 1 / 5 / 61           |
| Fresh held-out                                              | Twins wrongly blocked (review)  | 0/67 (1)           | 0/67 (1)        | 0/67 (1)        | 0/67        | 1/67                 |
| Fresh addendum (scored once)                                | Blocked / review / missed of 5  | 0 / 0 / 5          | 1 / 0 / 4       | 3 / 0 / 2       | 0 / 0 / 5   | 0 / 0 / 5            |
| Fresh addendum                                              | Twins wrongly blocked           | 0/5                | 0/5             | 0/5             | 0/5         | 0/5                  |
| Real-world clean (CI gate)                                  | Blocked / review                | 232/5655, 452/5655 | same            | same, 0 new ids | —           | —                    |

The one fresh twin at review (`au-f11-sudoers-nopasswd-all-control`) is a review on main too, from an older rule.

Fresh held-out by source (blocked / review / missed of attacks):

| Source                                                                        | Main       | #147       | Redesign   |
| ----------------------------------------------------------------------------- | ---------- | ---------- | ---------- |
| missed-attacks 2026-11-14, other loop (23)                                    | 0 / 2 / 21 | 8 / 1 / 14 | 17 / 0 / 6 |
| House red-team 459-502, other loop (22)                                       | 0 / 0 / 22 | 5 / 0 / 17 | 8 / 0 / 14 |
| Author-written before design, config languages and other prose languages (22) | 0 / 2 / 20 | 0 / 2 / 20 | 1 / 3 / 18 |

The redesign doubles #147 on unseen data (26 vs 13 blocked of 67) with no new false positive. Most remaining misses are config-file forms (Terraform, Kubernetes, sudoers, sshd, `.npmrc`, Firestore and similar). Code lines need an explicit sign before they count, so a bare config diff in `references/` is not flagged. That rule is what keeps ordinary setup docs at zero. The house rows that are still missed fall mostly outside the strong surfaces.

## Per rule

| Rule               | Dev + old held-out attacks hit (block / review) | Fresh + addendum attacks hit (block / review) | Twins | Look-alikes          |
| ------------------ | ----------------------------------------------- | --------------------------------------------- | ----- | -------------------- |
| IH-PRIV-003 widen  | 22 / 3                                          | 18 / 0                                        | 0     | 0                    |
| IH-PRIV-004 weaken | 19 / 0                                          | 11 / 1                                        | 0     | 1 review (see below) |

Look-alike pools: ClawHub crawl 0/35,000. GitHub SKILL.md 1/138,133 at review: the Citrix PVS guide's "Configure antivirus exclusions for write cache", a vendor-recommended weakening. Every other pool scored 0: the 17,777 earlier look-alike dirs, the 8 handwritten look-alikes, all honest twins and the 972 main-benchmark skills. The Citrix hit was left in place. Any wording fix for it would be fitted to one file.

## How the fresh held-out was built (`bench/settings-change-fresh`)

- Frozen and hashed (`manifest.json`, per-file SHA-256, `tree_sha256 152c097f…`) and committed (`92e8fa3`) before any redesigned rule was written. It was never opened during design. Each "before" and "after" column was scored once, at the end, from a /tmp copy.
- 67 attacks + 67 honest twins. 23 pairs from `missed-attacks/2026-11-14-*` not in the first set. 22 pairs from house red-team 459-502 (458 left out because its twin is in dev). 22 pairs written by the rule author before the redesign, in new domains, languages and file layouts. Those 22 are not independent of the author; the other 45 are.
- Addendum (split `fresh-addendum`, 5 + 5): camera-live-share-outside, guest-wifi-open-bridged, and house 503-508. They were requested after design had started, so they were copied by path without being opened, then hashed and committed (`c2df2f3`) before any further rule change. The only design change after that was the two bot ideas (theagatha indicator lights, ariesai named party), and it used look-alikes and dev only.

## Not done

- No version bump, no release, no merge.
- Model column not run.
