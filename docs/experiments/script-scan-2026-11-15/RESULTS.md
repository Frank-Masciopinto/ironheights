# Script-scan experiment (2026-11-15)

**Draft PR: https://github.com/Frank-Masciopinto/ironheights/pull/150 — do not merge without Kaleb's approval.** One experiment branch, rebased
onto `main` at `590ac5f` (Release 0.36.0, which includes PR #148: 260/516 block,
6/456 FP, block-or-review 314). Deterministic static analysis only — no model
verdicts are mixed into any count here. Release files for 0.36.0 were not edited
in this PR.

## What this adds

The scanner already walked on-disk script files. This PR adds a small data-flow
pass over those files and over **named** fenced script bodies in SKILL.md, plus a
join of SKILL.md with scripts the doc actually names.

- **IH-SCR-001 — a script sends a secret or credential to an exfil sink** (critical).
  The script reads a user secret (env var named like a key/token/password, or
  `.env` / `~/.ssh` / `~/.aws` / a credentials path) and writes it to a data-relay
  or exfil sink: a paste/request bin, `webhook.site`, an ngrok tunnel, a reserved
  `.invalid` host, or a host whose name/path says `exfil`/`steg`. A raw IP is
  **not** a sink by itself (dropped — see DISCARDED).
- **IH-SCR-002 — staged loader** (high). The script fetches a runnable file from a
  foreign, non-official host and then executes it (interpreter, `./file`,
  `chmod +x`, `exec`). Official registry/installer hosts (npm, PyPI, pypa.io,
  python.org, dot.net, Microsoft, Aliyun CDNs, GitHub, etc.) are not foreign.
- **IH-SCR-003 — persist remote or secret content into a persistence sink** (high).
  The script appends downloaded or secret material into shell rc, cron, or agent
  config files. Comment-only lines are ignored. Carries must be on the write
  statement itself (or a name bound as a secret/URL), not a curl a few lines
  above.
- **IH-SCR-005 — a script turns off the host agent's approval or sandbox guard**
  (high). The script writes an auto-approve-all / sandbox-off key into an agent
  config file.
- **Infrastructure.** `extractNamedScripts` turns a named fence (info-string path,
  an explicit "save as / write to / filename:" line, or a first-line comment path)
  into a virtual script file, but only `joinsScripts` rules see those virtual
  files. On-disk files still win when the same path exists. `joinSkillAndScripts`
  only joins scripts SKILL.md actually names. Fence closers must match the opener
  indent and have no info string, so nested example fences stay content.

IH-SCR-004 (persist a package-index / registry override) was implemented, failed
the real-world gate, and was dropped. Treating every unnamed fence as shipped
code, feeding virtual files to the general rule set, counting raw IPs as exfil
sinks, and treating a nearby curl or the bare word `crontab` as a persist write
were also dropped. See `docs/experiments/DISCARDED-RULES.md`.

Official MSB, the 5,655 real-world skills, and the 173k look-alikes are
SKILL.md-only. After the unnamed-fence path was closed, these published counts
do not move. The rules are covered by unit fixtures that ship real script files
and named fences. That is the intended lever for multi-file skills; it is not a
text-only gain on the official corpora.

## Before / after (same sets; Cisco and SkillSpector columns are scanner-constant)

Main benchmark: MaliciousSkillBench `d4b42ce`, deterministic, no `--llm`. Cisco
skill-scanner 2.3.2 and NVIDIA SkillSpector v2.12.0 (`7d9b4be`) are static-only
(no LLM); this PR changes only Ironheights, so their columns are unchanged from
the published figures. Ironheights "main" is `590ac5f` (0.36.0, post-#148).

| Set / metric | Ironheights main (590ac5f) | This PR | Cisco 2.3.2 | SkillSpector v2.12.0 |
|---|---|---|---|---|
| MSB attacks blocked | 260/516 (50.4%) | **260/516 (50.4%)** | 113/516 | 134/516 |
| MSB safe wrongly blocked | 6/456 (1.3%) | **6/456 (1.3%)** | 9/456 | 48/456 |
| MSB block-or-review (attacks) | 314/516 (60.9%) | **314/516 (60.9%)** | 115/516 | 220/516 |
| MSB safe block-or-review | 30/456 | **30/456** | 11/456 | 141/456 |
| Official Anthropic skills flagged | 0/19 | **0/19** | 1/19 | 4/19 |
| Blind attacks blocked | 335/600 | **335/600** | 190/600 | 173/600 |
| Blind benign blocked | 13/300 | **13/300** | 6/300 | 35/300 |
| Real-world clean blocked (CI gate) | 232/5655 | **232/5655, 0 new** | — | — |
| Real-world clean sent to review | 452/5655 | **452/5655, 0 new** | — | — |
| Look-alike pools (34,938 ClawHub + 138,133 GitHub) | baseline | **0 new block, 0 new review, 0 IH-SCR hits** | — | — |

Blind and held-out were scored once and not used for tuning. A mid-experiment
blind reading of 339/600 came from the leaky unnamed-fence CLI and went back to
335/600 after that path was closed.

The checked-in `la-main.txt` index lists only 5,949 of the 10,585 GitHub
look-alikes that 0.36.0 already flags. The 4,636 missing rows were rescanned
with the `590ac5f` CLI: every verdict and every non-META rule set matches this
PR exactly (2,671 review, 1,965 block, 0 IH-SCR). ClawHub (34,938) already
matched `la-main` exactly (6,252 flagged). So the 173,071-skill pool has **0
new false positives** against live main.

## Per-rule counts on the official sets

All four live rules scored **0** on the official 516/456 MSB skills, **0** on the
5,655 real-world skills, and **0** on the 173,071 look-alikes. Official
materializations have no sidecar scripts, and unnamed fences are not treated as
shipped code.

| Rule | Attacks (516) | Safe (456) | Real-world (5655) | Look-alikes flagged (173,071) |
|---|---|---|---|---|
| IH-SCR-001 | 0 | 0 | 0 | 0 |
| IH-SCR-002 | 0 | 0 | 0 | 0 |
| IH-SCR-003 | 0 | 0 | 0 | 0 |
| IH-SCR-005 | 0 | 0 | 0 | 0 |
| IH-SCR-004 (dropped) | — | — | 2 new reviews + 2 review→block score pushes | — |

Unit fixtures (3 positive / 3 near-miss per live rule, plus extract/join/fence
tests) confirm each rule catches the generic structure on shipped scripts and
named fences, and misses the honest twins.

## Dropped rules / branches

Logged in DISCARDED-RULES.md:

- IH-SCR-004 (registry / package-index persist) — real-world FPs on npmmirror, PyTorch CPU index, ClawHub `--registry`.
- Feeding extracted fences to every existing content rule — 4,729 look-alike verdict flips.
- Treating every unnamed markdown fence as a shipped script — 50 look-alike flips (raw IPs, official installers, rc/cron comments).
- Raw IP as an automatic IH-SCR-001 sink.
- Joining every script in the tree rather than only paths SKILL.md names.
- IH-SCR-003 carries from a nearby curl, or the bare word `crontab` as a write — honest installer PATH-to-bashrc and prose crontab mentions. Fence-closer desync and naming a fence from a nearby command path were tightened at the same time.

## Tests

874 tests passed (full vitest suite) after the rebase onto 0.36.0. `docs:rules`
regenerated (IH-SCR-004 removed from the published rule list). Real-world +
blind official gate: PASS vs live main (232/452 and 335/600, 13/300). In-repo
`baseline.json` is still the older 0.33.0 snapshot (275/474, 217/15); the gate
compares against that file and still passes, but the numbers to read are the
live main column above.
