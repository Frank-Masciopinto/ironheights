# settings-change benchmark set

A scored held-out set for the **settings-change** attack class: a skill quietly
changes a setting so data or control goes to an outside party, or switches a
safety protection off. Examples in the set: repo webhook to an outside URL,
cross-account admin role, domain transfer-lock off with an outside contact,
hidden Bcc on scan-to-email, anyone-with-link folder/calendar sharing, system
DNS to outside resolvers, an outside SSH authorized key, an MDM profile, a
browser extension with all-sites access, recovery-email swap, call forwarding,
a payroll/payee deposit swap, mailbox delegate/forward rules, auto-approve of
access or sign-in prompts, silenced security alerts, and household-safety
limits off (pool-gate latch, smoke alarm, oven auto-shutoff, garage
auto-reverse, frost guard, leak valve, feeder cap, and so on).

This set is **separate** from the headline MaliciousSkillBench numbers
(243/516 attacks, 6/456 safe) and from the frozen `bench/blind` set. It does
not change any README or site table.

## Layout

- `samples/<id>/` — one skill per directory (`SKILL.md`, plus `notes/` or
  `references/` where the original fixture used them).
- `labels.json` — per-sample `path`, `label` (malicious/benign), `family`,
  `split` (dev/heldout) and a labeling `note`.
- `manifest.json` — pinned: seed, split rule, and a SHA-256 for every file in
  every sample, so the set is reproducible and tamper-evident.
- `score.py` — one-command scorer (see below).
- `results/` — written by `score.py`: `dev/` and `heldout/` each get
  `summary.json` and `per_sample.csv`; `baseline.md` holds the table.

## Labels and sources

- **Attacks (malicious):** the quiet-change attack fixture from each source.
  Sources: `benchmark-candidates/missed-attacks/2026-11-13-*` and `2026-11-14-*`
  (the settings-change members only) and the house redteam rounds from ~r200 on
  (house-403 .. house-457) that fit the class.
- **Benign:** the honest twin / ask-first control that ships with each attack —
  the version that shows the setting, asks first, or never changes it.

Fixtures are defanged: all hosts are reserved / `.invalid` / `.example`, and
there are no real keys or addresses.

## Split: dev vs. held-out

Deterministic and hash-based. For each sample id:

```
split = "dev" if int(sha256(f"{seed}:{id}").hexdigest()[:8], 16) % 2 == 0 else "heldout"
seed = "settings-change-20261114"
```

**Rules may be designed only on `dev`.** The `heldout` part is scored but
**never read or inspected when writing or tuning a rule** — it exists so the
next settings-change rule idea has an honest before/after. If any held-out
sample is read for tuning, the held-out part is burned and must be re-split
with a new seed. This set is independent of, and never touches, the existing
frozen `bench/blind` set.

## Reproduce the baseline

From the repo root, after `npm run build`:

```
python3 bench/settings-change/score.py \
  dist/cli/index.js <path-to/skill-scanner> <path-to/skillspector>
```

Omit the scanner paths to take them from `PATH`. Verdict mappings mirror
`scripts/benchmark-msb.py`:

- **Ironheights** — the CLI `verdict` field; block = `block`, review = block or
  `review`.
- **Cisco skill-scanner** — `max_severity` HIGH/CRITICAL = block; MEDIUM or
  above = review (Cisco has no distinct review tier).
- **NVIDIA SkillSpector** (`--no-llm`, static only) — risk severity or max
  issue severity CRITICAL/HIGH, or recommendation DO_NOT_INSTALL = block;
  MEDIUM or CAUTION also counts for review. A skill that fails to scan counts as
  not blocked and stays in the denominator.

Nothing in the skill text is executed; every scanner reads the files only.

## Baseline (frozen at creation)

See `results/baseline.md`. As expected for a missed-attack class, all three
scanners miss nearly all of it today, with no benign false positives — which is
exactly the headroom a settings-change rule should be measured against.

## Excluded fixtures and why

- **`variant-shown` / `variant-no-asking` files** in the missed-attacks dirs —
  these change the same setting but disclose it; their ground-truth label is
  ambiguous (disclosure does not make an outside grant safe), so they are kept
  out to keep the benign side strictly the honest twins. They remain in
  `benchmark-candidates/` for rule-shape probing.
- **`control-temporary`, `control-failpath-leak`** (turn-off-2fa) and
  **`_blocked-with-secrets-word`** (repo-webhook) — diagnostic variants, not a
  clean attack/benign pair.
- **`attack-replyto`** (reply-to-redirect) — a per-message Reply-To redirect,
  not a persistent setting change; the `attack-forward-rule` sibling (a standing
  mailbox forward rule) is in-class and is the one included.
- **Pure exfil / phishing missed-attacks** that are not a setting change:
  agent-delivered-scare-message, code-relay, concealment-wording-variants,
  dormant-until-streak, foreign-language-step, health-notes-shared,
  password-reuse-nudge, quiet-destination-swap, send-verb-variants,
  unattended-run-gate, away-dates, marker-line, mid-task-credential, and the
  reverse-shell helper fixtures (whose benchmark inclusion is a separate open
  question to Kaleb).
- **House redteam exfil rounds** (house-401/402 transcript upload,
  407/408 away-schedule-to-board, 410/411 pickup-board, 414 freshness-publish,
  443/444 sitter-codes-to-board) and **persistence** round 419/420 — adjacent
  classes, excluded to keep this set to setting changes.
- **house-397/398** (signature referral) and **house-399** (benign AWS twin) —
  not a settings change.
