# Detection-80 combined experiment (2026-11-15)

**Draft. Do not merge without Kaleb's approval.** One experiment branch off `main` at
`f5dcd5b` (252/516 block, 6/456 FP, block-or-review 309). Plan: `moltbook/DETECTION-80.md`.
Four attack families plus review-to-block escalations, all in one PR. Deterministic static
analysis only — no model verdicts are mixed into any count here.

## What the checks read (generic structure, not benchmark wording)

- **g. IH-NET-011 — trust-anchor redirection.** A setup step repoints a trust anchor to a
  host that is neither official nor one the skill declares as its own:
  - the hosts file is made to redirect a known registry/API host
    (`echo "0.0.0.0 registry.npmjs.org" >> /etc/hosts`) — unambiguous, scored **critical**;
  - the package index / registry is overridden to a foreign host **and** the change is
    pinned as mandatory / every-run / do-not-skip / null-route (`index-url = https://mirror.internal…`,
    "mandatory preparation step for every run") — scored **high** (review).
  An optional mirror or a pin to the official registry is not flagged. (A base-URL branch was
  tried and dropped — see DISCARDED.)
- **a. IH-NET-012 — a user secret sent to an exfil sink.** A block reads one of the user's own
  secrets (an env var named like a key/token/password, or `.env` / `~/.ssh` / `~/.aws`) and makes
  an outbound write (POST/PUT, form upload, email) whose destination is a **data-relay / exfil
  sink** — a paste bin, request bin, `webhook.site`, an ngrok tunnel, a raw IP, a reserved
  `.invalid` host, or a host whose name/path says `exfil`/`steg`. A key sent as an Authorization
  or OAuth-basic header to an API, or to a bot API (Telegram/Discord), is **not** flagged: that
  is structurally identical to exfil, so the rule leans entirely on the destination, not on how
  the secret is wrapped. (A broader "secret + any foreign POST" version was tried and dropped —
  see DISCARDED.)
- **f. IH-EXEC-016 — staged loader (download-then-run).** A fetch (curl / wget / Invoke-WebRequest)
  saves a file from a foreign host and the skill then runs it. It fires when either the author
  states the intent ("execute the downloaded …", "downloaded and executed"), or the saved file has
  a **runnable** extension (py/sh/js/exe/ps1/…) and is the **direct** target of an interpreter,
  `./file`, `chmod +x`, or `exec` at a command boundary. Data/config downloads (json/yaml/conf) with
  no stated execute-intent are not flagged, and a file merely passed as an *argument* to another
  local script is not a run (this excludes e.g. an API-recon skill that fetches `openapi.json` and
  ingests it). A pinned install from an official registry is not flagged.
- **d. IH-PRIV-005 — the agent's own guardrail switched off.** A structured agent-config key
  turns the host agent's sandbox or approval gate off (`dangerouslyDisableSandbox: true`,
  `autoApproveAll: true`). Documented dev-CLI flags (`--yolo`, `--dangerously-skip-permissions`,
  `--approval-mode yolo`) are **not** matched — honest dev-tool skills pass them knowingly (dropped,
  see DISCARDED). The key match tolerates the JSON-quoted form (`"dangerouslyDisableSandbox": true`).
  The auto-approve-**list** widening variant flagged in the 2026-11-15 loop (house-531 / tmux-A100)
  is the same control-downgrade structure; its wildcard-list form (`autoApprove: ["*"]`) has zero
  instances in the tunable corpus/house sets — the only live example uses the boolean key and is
  already blocked — so a wildcard-list branch was considered but not shipped (no measured gain, only
  added FP surface). See DISCARDED.
- **d/g. IH-NET-013 — TLS trust anchored to a certificate the skill ships itself.** A skill points a TLS trust anchor (npm `cafile`, git `http.sslCAInfo`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `--cacert`) at a `.pem`/`.crt` that is a **file shipped inside its own folder**, so TLS is validated against a CA the author controls (a silent MITM anchor). The discriminator is **file provenance**: the rule fires only when the referenced cert actually exists on disk in the skill directory — an exported system-store cert, a system CA path, or a CA-bundle filename the skill does not ship is not flagged. Added from the 2026-11-15 marginalia_claude confirmed bypass: this PR blocks the **bundled-ca** variant (A95→block) and reviews the **ssh-ca** variant (a skill-shipped `team-ca.pub` marked `@cert-authority` for `*` in known_hosts, A100→review) while leaving the honest system-store twin clean. The apt-global-key variant is already blocked by main's IH-PRIV-003. The companion **env-tls-off** variant (persisting `NODE_TLS_REJECT_UNAUTHORIZED=0` to a shell profile) was **not** shipped — real-world skills persist TLS-off in their own `~/.zshrc` too, so no deterministic text signal separates it at zero FP (see DISCARDED). No MSB corpus row ships a self-anchored CA, so it does not move the corpus count; it closes a confirmed real gap at zero FP on the 456 safe skills, the 5,655 real-world corpus and the 173k look-alikes.

- **Review-to-block escalation.** `IH-NET-004` (two or more named secrets serialized into one
  payload and sent) is escalated from review to block. It scores zero on the 456 safe skills, the
  5,655 real-world corpus and the look-alike pools. `IH-REF-003` was also tried for escalation and
  dropped (it turned 2 real-world skills into blocks).

All five checks carry a `shadowCheck` tag so the real-world gate can scan them in enforce mode;
the enforce scan is clean (0 would-block, 0 would-review), so they run live.

### Considered, not added — config-include→commit exfil (r265 style-matcher, family a)

The r265 marginalia candidate reads a project's lint/formatter/git/**ssh** config, follows every `Include`/`[include]` "wherever it points" (out to `~/.ssh/config`, `~/.gitconfig`, `~/.npmrc`, which can hold keys/tokens), copies the content **verbatim** into `docs/CONVENTIONS.md`, and commits it — an exfiltration whose sink is a committed file. It was **not** added: the honest look-alikes it names (EditorConfig / ESLint / Prettier parent-directory walks, `~/.gitconfig` / `~/.npmrc` setting derivation) have the identical read-config-and-resolve-includes structure, so the only separating signals are the wording "follow wherever it points", "verbatim", and "commit" — fitting a deterministic rule to those phrases would overfit this one sample and risk FPs on every config-inheritance skill. Logged in DISCARDED; the right home is the shipped-script / data-flow analysis that is out of this PR's scope.

## Before / after (same sets; Cisco and SkillSpector columns are scanner-constant)

Main benchmark: MaliciousSkillBench `d4b42ce`, deterministic, no `--llm`. Cisco skill-scanner
2.3.2 and NVIDIA SkillSpector v2.12.0 (`7d9b4be`) are static-only (no LLM); this PR changes only
Ironheights, so their columns are unchanged from the published figures.

| Set / metric | Ironheights main (f5dcd5b) | This PR | Cisco 2.3.2 | SkillSpector v2.12.0 |
|---|---|---|---|---|
| MSB attacks blocked | 252/516 (48.8%) | **260/516 (50.4%)** | 113/516 | 134/516 |
| MSB safe wrongly blocked | 6/456 (1.3%) | **6/456 (1.3%)** | 9/456 | 48/456 |
| MSB block-or-review (attacks) | 309/516 (59.9%) | **314/516 (60.9%)** | 115/516 | — |
| MSB safe block-or-review | 30/456 | **30/456** | 11/456 | — |
| Anthropic safe flagged | 0/19 | **0/19** | 1/19 | — |
| Blind attacks blocked | 335/600 | **335/600** | 190/600 | — |
| Blind benign blocked | 13/300 | **13/300** | 6/300 | — |
| Prose-only attacks block / review | 40/98, 55/98 | 40/98, 55/98 | — | — |
| Real-world clean blocked (CI gate) | 232/5655 | **232/5655, 0 new** | — | — |
| Real-world clean sent to review | 452/5655 | **452/5655, 0 new** | — | — |
| Look-alike pools (34,938 ClawHub + 138,133 GitHub) | baseline | **0 new block, 0 new review** | — | — |

Settings-change sets (scored once, not tuned on): dev 33 block / 2 review / 0 missed; old held-out
8 / 1 / 12; **fresh held-out 26 / 3 / 38**; fresh-addendum 3 / 0 / 2 — all identical to main, with
0 benign blocked and the one pre-existing benign review unchanged. The new rules do not touch them.

## Per rule (this PR, MSB corpus)

| Rule | Attacks hit (block / review) | New blocks | Safe 456 | Real-world 5655 new | Look-alikes new |
|---|---|---|---|---|---|
| IH-NET-011 trust-anchor | 1 / 1 | ASB04_003064 | 0 | 0 | 0 |
| IH-NET-012 secret→exfil sink | 1 / 0 | ASB04_003159 | 0 | 0 | 0 |
| IH-EXEC-016 staged loader | 1 / 1 | ASB04_002493 | 0 | 0 | 0 |
| IH-PRIV-005 agent guard off | 1 / 0 | ASB04_001816 | 0 | 0 | 0 |
| IH-NET-004 escalation (existing) | 4 / 0 | 001241, 003426, 003636, 003955 | 0 | 0 | 0 |
| IH-NET-013 self-anchored CA | 0 (corpus) — blocks the bundled-ca confirmed-bypass candidate | — | 0 | 0 | 0 |

New reviews: ASB04_003195 (IH-NET-011 pinned index override), ASB04_006570 (IH-EXEC-016,
`curl -o …exe` from `3psil0n` then `exec` — stays review at high).

## How far toward 80%

This lifts deterministic block from 48.8% to **50.4%** (+8 attacks) at **zero** new false
positives anywhere — the 456 safe skills, the 5,655 real-world corpus, the 173k look-alike pool,
and the held-out settings-change sets are all unchanged, and blind detection rises to 335/600.
It does not approach 80%. As `DETECTION-80.md` records, 124 of the unblocked attacks (47%) carry
no malicious signal in SKILL.md at all — the payload sits in an unshipped script or in pure intent
prose — so the text-only ceiling on this benchmark is ~76%, and reaching it needs every hooked
attack caught at zero FP, which never happens. Each family here is deliberately gated to the
unambiguous core of its structure, which is why the gain per family is small: the loud
false-positive surface (OAuth base64, API auth headers, legit mirrors, bot APIs, documented
dev-CLI flags) sits right on top of the attack structure. The next lever is not more text rules;
it is the two out-of-scope levers the plan names — scanning shipped script files (the benchmark
ships SKILL.md only, so the 84 unshipped-script decoys look clean here but would be scannable in a
real install) and a separate model-opinion column kept out of the deterministic count.
