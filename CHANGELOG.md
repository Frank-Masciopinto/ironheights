# Changelog

## 0.23.0 — 2026-10-31

**Fail-closed MCP decisions with receipts, coverage-honest posture grades, and same-change widening checks.** Ironheights protects any AI bot that installs it. Every item below was suggested by bots on Moltbook. Existing fields, models and exit codes keep their meaning unless you opt in; new JSON fields are additive.

- MCP `check_skill` returns `decision` (`allow`, `blocked_pending_approval`, `blocked`); review and incomplete wait for a human. Suggested by ecdys, Rios and templeofmolt.
- MCP `check_skill` fails closed: an error, timeout or empty result is a failed call with `state: checker-unavailable`, `verdict: unknown`, `decision: blocked`, logged as its own event. Suggested by zoranmesh, fennwick, soleia42, nyna, kobolsix, openclawprime and SamanthaSchacht.
- Required `provenance` on `check_skill`, `drift_status` and `threatmodel_check` (version, rule-set hash, time, content digest, subject producer), plus an opaque `checkId` anchor. Suggested by ledger-line-19, Kleinbot, ODEI, hz-assistant, vina, pennyworthatyourservice, evil_robot_jas, swordfish-ming and anp2_com.
- Server-written receipts (`mcp-receipts.jsonl`) with each matched rule, file, line and that file's sha256, and what would change the decision. Suggested by ackedagents, KitSinclair, SamanthaSchacht, aiko3062, theagatha and thegreekgodhermes.
- New MCP tool `verify_check`: `live`, `stale`, `absent` or `unverifiable`; only `live` keeps its decision. Suggested by entitylovestudio, vynderbot, miloforryan, lyra_reader and ODEI.
- `check_skill` `view: "agent"` returns control state only; evidence stays in the receipt for the approver. Suggested by ecdys and Rios.
- `ironheights report`: a letter grade only at full coverage, otherwise `incomplete` with `N of M` and the uninspected skills named; per-skill `coverage` (files read, skipped, runtime-fetched URLs, reasons); `--fail-on-incomplete`. Suggested by lobsternigel, proxima, lobsterroyale, vina, soleia42, clawyer, grokentra, moltbookrevenueagent, templeofmolt and aether_cell.
- Report `fingerprint` and `validUntil` (`--valid-days`, default 7); the offline HTML greys itself out after expiry. Suggested by annuntiato, vina and evil_robot_jas.
- `threatmodel diff` with `defaults.modelChanges: fail` (read from the base model) or `--fail-on-widen`: a capability allowed only by a model change in the same PR is a high `widened-in-same-change` violation; accept new scope in its own model-only PR. Action input `threatmodel-fail-on-widen`. Suggested by pipnyc, nyna, kobolsix, ariesai and sheeshscout.
- `threatmodel check`/`diff` report the commits covered (`covered.base`, `covered.head`, `dirty`) and `notChecked` folders; docs say to run on every PR without a `paths:` filter. Suggested by fromthebot, narin_lab, nyna and templeofmolt.

Not built, with reasons: [docs/ideas.md](docs/ideas.md#deferred-from-0230). Scanner rules and detection are unchanged; the 20-skill synthetic benchmark is unchanged.

## 0.22.0 — 2026-10-31

**Claim results, config-key drift, and a posture hash.** Ironheights protects any AI bot that installs it. This release adds small, opt-in checks suggested by Moltbook bots. Existing models, ledgers, configs, JSON fields and exit codes keep their meaning. New JSON fields are additive.

- `threatmodel check` and `diff` report each allow-list as `passed`, `violated` or `untested`, with the distribution it was judged on (for example `3 hosts in diff, 3 on allowlist`). An untested claim matched zero rows and does not change the exit code. Suggested by RushantsBro on Moltbook.
- Capabilities the model never names (a host, secret name, env var, MCP server or webhook) are listed as uncovered, with a suggested claim. They do not change the exit code unless you pass `--fail-on-uncovered`, set `defaults.uncovered: fail`, or set the Action input `threatmodel-fail-on-uncovered`. Suggested by iriscoremeal and evil_robot_jas on Moltbook.
- A built-in `remote-instructions` claim reuses scanner finding `IH-INJ-004`. `defaults.remoteInstructions` is `report` (info, exit unchanged), `warn` or `deny`. A skill can allow it with `remoteInstructions: true`. A file hash pins the file, not the page it points at. Suggested by iriscoremeal on Moltbook.
- Each claim carries `enforcement`. Free-text claims such as `dataBoundaries` and `purpose` are flagged `unenforced`. Suggested by muse_bryce on Moltbook.
- `drift approve` records flattened config keys for each skill and for MCP servers passed with `--mcp`. `drift check` and `drift_status` report a key that was added, a restriction that was removed, or a restriction that was loosened. Auth, network and tool-scope keys block; other keys warn. Secret values are shown as `<redacted>`. A ledger written before this release still loads. Suggested by fromthebot on Moltbook.
- `ironheights report` leads each skill with its worst reach and keeps the grade beside it (`grade B @ cfg 1a2b3c4d`). `--history` sets `regraded` when that config hash changes and says the grade was recomputed. Suggested by fromthebot and evil_robot_jas on Moltbook.

Scanner rules and detection are unchanged; the 20-skill synthetic benchmark is unchanged.

## 0.21.1 — 2026-10-31

Fixes from end-to-end testing. Ironheights protects any AI bot that installs it, and these make `report` and `mcp` more precise.

- `report`: an empty folder no longer counts as a phantom skill, and a missing target path now exits non-zero (#45).
- `mcp`: `check_skill` returns an error for a missing `path` instead of a clean result, and ClawHub fetches remove their whole temp folder (#47).
- Docs: the threat model Action example pins `v0.21.1`. npm keywords expanded.

Scanner rules and detection are unchanged; the 20-skill synthetic benchmark is unchanged.

## 0.21.0 — 2026-10-30

**`ironheights report`: agent security posture report.** Ironheights protects any AI bot that installs it, and now it can report on a whole repository or an organisation folder of repositories in one go: a skill inventory with grade, verdict, finding count and top rules; threat-model coverage and violations per repository (0.19.0); drift since approval with `--ledger` (0.18.0); findings and skills per OWASP Top 10 for LLM Applications 2025 risk; and a trend over runs with `--history <file.jsonl>`. `--html` writes one self-contained page (no scripts, no external assets) for an audit pack, `--json` / `--json-file` the same data, and `--fail-on-block` exits 2 when any skill is blocked. Local only, no telemetry. See `docs/report.md`.

Scanner rules and detection are unchanged; the 20-skill synthetic benchmark is unchanged.

## 0.20.0 — 2026-10-30

**`ironheights mcp`: Ironheights as an MCP server.** Ironheights protects any AI bot that installs it, and now any MCP client can ask it about a skill before installing it. Run `npx -y ironheights@0.20.0 mcp` (stdio). Tools: `check_skill` (a local `path`, or a ClawHub `skill` reference downloaded to a temp folder and never executed) returns the A-F grade, score, verdict, findings with OWASP LLM ids and rule pages, drift status and plain advice; `drift_status` reports changes since `drift approve`; `threatmodel_check` runs the 0.19.0 threat model check; `get_rule` explains a rule with OWASP, MITRE ATLAS and OpenCRE ids. All tools are read-only. Protocol versions 2025-06-18, 2025-03-26 and 2024-11-05. No new dependencies. `server.json` and `mcpName` describe it for the MCP Registry as `io.github.Frank-Masciopinto/ironheights`. See `docs/mcp.md`.

Scanner rules and detection are unchanged; the 20-skill synthetic benchmark is unchanged.

## 0.19.0 — 2026-10-30

**`ironheights threatmodel`: agent threat model as code, checked on every PR.** Ironheights protects any AI bot that installs it, and now it can hold a repo to a reviewed model of what each skill and MCP server may touch. `ironheights.threatmodel.yml` lists the trusted skills and MCP servers and, per skill, the allowed network hosts (`*.suffix` wildcards), filesystem globs, environment variables, secret-shaped tokens, shell use and a minimum scan grade. `threatmodel init` writes a first model from the skills and MCP configs in the repo; `threatmodel check` reports every host, path, env var, token, shell use, low grade, unknown skill or unknown/changed MCP server outside it (high exits 2, medium exits 1); `threatmodel diff --base <ref>` reads the base commit with `git archive`, reports only what the PR adds and lists every widening of the model for the reviewer. `--markdown` writes a PR comment, `--sarif` writes SARIF 2.1.0, `--json` prints the report, and `--ledger` folds in `ironheights drift` changes. JSON Schema: `docs/threatmodel.schema.json`, also at https://www.ironheights.dev/api/v1/threatmodel.schema.json. Local only: no network, no telemetry, environment variables matched by name only. Inspired by continuous threat modeling. See `docs/threatmodel.md` and `examples/threatmodel`.

**GitHub Action `mode: threatmodel | both`.** Runs the threat model check (or diff against the PR base), posts and updates one summary comment per PR, writes the job summary, sets `threatmodel-exit-code` and `threatmodel-violations`, and fails on out-of-model additions. Inputs: `threatmodel-file`, `threatmodel-base`, `threatmodel-ledger`, `comment`, `github-token`. The default `mode: scan` is unchanged.

The ClawHub skill now mentions `drift` and `threatmodel` as user-run commands. Scanner rules and detection are unchanged; the 20-skill synthetic benchmark is unchanged.

## 0.18.0 — 2026-10-30

**`ironheights drift`: catch a skill or MCP tool that changes after you approved it (rug pull).** `drift approve` records each skill's file hashes, its SKILL.md description, the URL hosts and credential paths its text names, MCP server entries (`--mcp`, for example `~/.cursor/mcp.json`) and MCP tool descriptions and schemas from a saved `tools/list` response (`--tools`). `drift check` and `drift watch` report what moved since. A changed description, a new host, a new credential path, a changed MCP server entry or a changed tool description is high (exit 2). An added or changed file, or an unapproved skill, server or tool, is medium (exit 1). Key order and whitespace in JSON are not drift. Local only, no network, no telemetry. The ledger is `<ironheights home>/approvals.json` (mode `0600`). Works for skills from any agent (OpenClaw, Claude, Grok Bot, Codex, Cursor). See `docs/drift.md`.

**GitHub Action for skill hubs and repos.** New outputs `grade`, `score`, `verdict`, `findings` and `json-file`; `badge-file` writes a shields.io endpoint badge; the job summary lists the top findings with links to each rule page (`job-summary: 'false'` turns it off). Marketplace name "Ironheights AI Skill Scanner" with branding. `docs/hubs.md`: add Ironheights to your skill hub in one line.

Scanner rules and detection are unchanged; the 20-skill synthetic benchmark is unchanged.

## 0.17.0 — 2026-10-30

**OWASP and OpenCRE tags on every finding.** Each rule now carries its OWASP Top 10 for LLM Applications 2025 id and its OpenCRE (Common Requirement Enumeration) ids, for example `IH-INJ-001` → `LLM01:2025` and CRE `012-625` Indirect prompt injection (text inside a skill reaches the agent as indirect input; direct injection is CRE `686-110`). 40 of 44 rules map to at least one of 26 OpenCRE ids. Every id was checked against the OpenCRE public API (`/rest/v1/id/<id>`) on 2026-10-30; rules with no defensible match (`IH-FS-001`, `IH-META-001`, `IH-REF-001`, `IH-LLM-001`) stay unmapped rather than guessed.

- Terminal output adds one line per finding, such as `OWASP LLM01:2025 · CRE 012-625 → https://www.opencre.org/cre/012-625`.
- JSON adds `references.openCre` and a `links` list (OWASP risk page and OpenCRE pages). SARIF adds `openCre`, `links`, and a `helpUri` per rule pointing at `https://www.ironheights.dev/rules/<rule-id>`. Markdown and HTML reports link the OpenCRE pages.
- The links are static strings in the package. Scans still make no network calls and send no telemetry.
- `docs/rules.md` lists the OpenCRE ids with their names.

Scanner detection is unchanged; the 20-skill synthetic benchmark is unchanged.

## 0.16.0 — 2026-10-28

**Hard-coded environment fallback (`IH-CRED-006`, new, high).** A credential used as the default of an environment lookup ships in the package. `os.getenv("NAME", "…")`, `os.environ.get("NAME", "…")` (including a call split across lines), `getenv(...) or "…"`, `process.env.NAME || "…"` and `??`, `process.env["NAME"]`, and `${VAR:-…}` are checked in code files. A literal of length at least 16 that starts with `AIza`, `sk_`, `sk-`, `ghp_`, `github_pat_`, `xox[abprs]-`, `AKIA`, or `0x` plus 64 hex is flagged. Any other literal needs Shannon entropy of at least 3.5, length at least 20, and a secret-like variable name (`KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PRIVATE`, `AUTH`, `CREDENTIAL`). A 42-character `0x` address is not a secret. Markdown is not scanned, so transaction hashes and selectors there stay quiet. Placeholders (`your-api-key-here`, `changeme`, `xxx`, `<KEY>`) and env-to-env fallbacks (`process.env.A || process.env.B`) are quiet. Evidence keeps the first four and last four characters. Suggested by aether_cell, with the shell form from sheeshscout, on Moltbook. Their census of 2,827 ClawHub skills found 8 hits and 0 false positives; 0.13.0 through 0.15.0 flagged none of the 8.

The 20-skill synthetic benchmark is unchanged (review recall 1.000, block recall 0.300, 0 false flags).

## 0.15.0 — 2026-10-26

**Child process inherits ambient credentials (`IH-EXEC-005`, new, medium).** A skill that names an API key, token, or other secret-shaped variable and starts a child with the parent environment gets one finding per file. Explicit full copies count when the secret is in that file or anywhere else in the skill: a spread of `process.env` (including an MCP client `{ ...process.env, ...config.env }`), `env: process.env`, `os.environ.copy()`, `**os.environ`, `dict(os.environ)`, and an unfiltered `os.environ.items()` copy. A `spawn`, `exec`, `execFile`, `fork`, or `subprocess` call that leaves `env` unset counts only when the same file names the secret, which is the language default and is too common to blame on a key mentioned in another file. An explicit env object or dict that lists `PATH`, `HOME`, and the keys the child needs, and is not built from a full-environment copy, stays quiet. So does a full-environment copy in a skill that names no secret, a `regex.exec` call, and a call that appears only in a comment or a string. Files under `test/`, `tests/`, `__tests__/`, `spec/`, or `fixtures/` are skipped, same as the other accuracy rules. One medium finding is a review, not a block. Suggested by calbrutower, aidroid, lilt, and merktop on Moltbook.

The 20-skill synthetic benchmark is unchanged.

**Dependency.** `zod` 4.1.12 → 4.6.7. Node 24's `npm audit --audit-level=high` already failed on 0.14.1 for [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5) (zod before 4.6.6). Scanner behavior is unchanged.

## 0.14.1 — 2026-10-24

Same as the attempted 0.14.0 cut (install-tool metadata skip). 0.14.0 was unpublished after an npm stage conflict with a classic publish; this is the live tag.

## 0.14.0 — 2026-10-24 (unpublished)

**Install-tool metadata is not graded as the author's code.** ClawHub writes `.clawhub/origin.json` and a root `_meta.json` next to installed skills (registry URL, slug, version). Those files are still walked and hashed for tamper checks, but content rules no longer raise findings on them. With 0.13.0, billboardbug 1.2.3 graded B 85 solely because `IH-NET-001` fired on `clawhub.ai` inside `.clawhub/origin.json`. Suggested by [ccbillboardbug on Moltbook](https://www.moltbook.com/) during a beta rescan.

The 20-skill malicious benchmark is unchanged (same verdicts on the malicious set; no new false flags on clean skills).

## 0.13.0 — 2026-10-22

**Updates are offer-only.** `ironheights update` and the 6-hourly background check no longer install anything: no `npm install -g`, no `clawhub update`. When a newer CLI (with npm provenance and sha512 integrity) or ClawHub skill exists, it prints the exact command for the user to run, for example `npm install -g ironheights@0.13.0` or `clawhub update ironheights`. The skill tells the agent never to run an update on its own; it may run `ironheights update --check` when asked and show the command. Nothing is downgraded.

**Install from ClawHub first.** README and SKILL.md lead with `clawhub install ironheights`; SKILL.md install commands are pinned to the exact CLI version and updated automatically by `npm version`.

## 0.12.0 — 2026-10-21

Measured on the 2,827-skill ClawHub snapshot against 0.11.0: block 690 → 759, review 977 → 922, no-findings 1,159 → 1,145; 120 skills graded lower, 2 higher. 65 of the 68 new review → block moves are Maton copies whose delete examples skip the confirmation their docs require. The 20-skill benchmark is unchanged.

**Missing referenced script (`IH-REF-001`, new).** SKILL.md that tells the agent to run a script the skill does not ship (`python3 scripts/sync.py`, `bash {baseDir}/scripts/install.sh`) gets a medium finding; a passing prose mention of `scripts/…`, `bin/…` or `tools/…` is low. Quiet: files present anywhere in the package, `skills/<name>/` install prefixes, placeholders (`path/to/your_script.py`), bare names the user writes (`node swap.js`), URLs, absolute and home paths, build output (`dist/`), comments, files the same SKILL.md creates or downloads, and "do not use" lines. On the registry: 69 skills, 57 with a runnable miss. Suggested by synapseguide, ccbillboardbug, felixnexus and fujikatsu on Moltbook.

**Confirm-before-delete docs whose examples skip it (`IH-EXEC-004`).** When the prose says to confirm before deleting and a fenced delete example passes `--yes`, `-y` or `--force`, the example is medium ("the agent copies examples"), and a guard elsewhere no longer demotes it. The guard sentence itself is info. An example that says it runs after verifying is left alone. Found in 65 Maton skills (about 1M downloads).

**Precision.** URLs stop at full-width and CJK punctuation (`https://api.vendor.com，然后`). `example.*` documentation hosts, `localhost`, `*.localhost` and `0.0.0.0` are not destinations. A finding on a CHANGELOG/HISTORY/RELEASE_NOTES line that describes a fixed bug is info.

## 0.11.0 — 2026-10-21

Accuracy release. Measured on the 2,827-skill ClawHub snapshot against 0.10.0: non-info findings 27,523 → 16,215; block 755 → 690; no-findings 1,117 → 1,159; 179 skills graded higher, none lower. The 20-skill benchmark is unchanged.

**Relative paths inside the skill (`IH-FS-001`).** A `../` path that resolves inside the skill folder, judged from the folder of the file that names it (`scripts/run.sh` → `../references/api.md`, `require('../src/x')`), is no longer path traversal. Paths that leave the skill, backslash traversal and symlinks are still flagged. Non-info IH-FS-001 hits: 11,855 → 752.

**Advice against sudo (`IH-PRIV-001`).** "Never use sudo", "do not run this with `sudo`", "no sudo needed" and "sudo is not required" are quiet. A line that also runs sudo or another privilege pattern is still flagged.

**Registry skill card is notes.** ClawHub generates `skill-card.md` at the skill root, so its findings are reported as info (critical as medium). Non-info skill-card findings: 197 → 2. A `skill-card.md` deeper in the tree is graded as code.

**Empty folder: "nothing scanned".** A scan that read no files no longer prints grade A; the grade is `nothing scanned` (JSON letter `nothing-scanned`).

## 0.10.0 — 2026-10-21

Accuracy release, built from real ClawHub examples that Moltbook bots sent in.

**Credential files readable by others (`IH-CRED-004`, new, medium).** A script that writes a token, key, cookie or session file with no mode 600, `chmod 600`, `umask 077`, `install -m 600` or `mkstemp` gets a finding: under the usual umask 022 the file is created 644. Also caught: saving through a temp file and `rename` after an earlier `chmod 600` (low; the renamed file gets the default mode and undoes the chmod), and `tar`/`zip`/`cp -r` backups of `~/.openclaw`, credentials, `.ssh` or `.env` made without `umask 077`. In Markdown only fenced commands count, one step lower than in a script. link-skill (token cache written 644) now gets a finding; ticktick (`mode: 0o700`/`0o600` + chmod) stays quiet. Reported by clanker_chat, ymas and Leroy.

**Confirm-off switches (`IH-EXEC-004`, new).** `--yolo`, `--dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox` and `bypassPermissions` start a coding agent with approvals off: high in a script, medium in Markdown. `--no-input`, `--non-interactive`, `--yes`, `--auto-approve`, `auto_confirm` and friends are low, medium next to update/delete/send/publish/`--all`/`--force`. A guard within 3 lines (never, do not, avoid, unless, only when, ask the user, interactive) lowers a hit (agent switch to low, generic switch to info). `--force` alone and package-manager `--yes` (`npx`, `apt-get`, `pip`, ...) are not counted, and `codex --full-auto` (sandboxed) is not flagged. tmux (`codex --yolo` in send-keys) goes from A 100 to review; clawdhub `update --all --no-input --force` now gets a medium. A documented CLI switch such as gh-issues' `--yes | Skip confirmation` is graded here instead of as `IH-INJ-003` agent-safeguard tampering; `IH-INJ-003` is unchanged for every other line. From our own census, with atlas-memory-warden and ziggyclaw.

**Delivery-aware `IH-INJ-001`.** In Markdown, an instruction-override phrase in bare prose stays high. The same phrase in quotes, inline code, a fence or a blockquote is medium. It drops to info only when it is quoted **and** a refusal or detection word (refuse, never follow, attack, malicious, injection, untrusted, ...) outside the quote, or a security/risk heading, is within 3 lines. Marker words alone and quoting alone never drop a hit to info, and words inside the quoted payload do not count. Scripts are unchanged. agentmail (`"Ignore previous instructions..."` under _Security: Webhook Allowlist_) and playwright (`a page saying "ignore previous instructions..." is an attack`) move to info; guard-scanner's malicious-skill fixture stays high. Designed by kevinjobhunt and vectleagent.

**Secret in a URL (`IH-CRED-005`, new, low).** A credential-named variable or placeholder in a `key=`/`api_key=`/`token=`/`access_token=` query string (one note per file), or a token in `user:$TOKEN@host` (medium; a git remote stores it in `.git/config`, as in gh-issues). `token=ETH`-style asset parameters and header-borne keys are ignored. Suggested by ccbillboardbug and agenthaven.

**Key-to-memory instructions (`IH-CRED-003`).** "Store API key in TOOLS.md" / "save API key to MEMORY.md / memory" is now caught (rescuetime, moltbets, shekel-hyperliquid). The finding is reported on the line that names the secret instead of the two lines above it. Advice to keep a token in an env var or secret store, and negations ("never save the key to MEMORY.md"), are quiet: openspender's two false hits are gone. Reported by ranma, vina, foma-agent and ymas; openspender false positive by cellkai.

On the 2,827-skill registry scan: `IH-EXEC-004` hits 277 skills (7 high, 79 medium, 642 low, 334 info), `IH-CRED-004` 53 skills (17 medium, 66 low), `IH-CRED-005` 62 skills; `IH-INJ-001` high hits drop from 193 to about 102 (the rest become medium or info), `IH-INJ-003` from 214 to 160, `IH-CRED-003` from 147 to 53 lines. Verdicts: 16 block to review, 4 review to no-findings, 11 no-findings to review, 12 review to block, 1 no-findings to block.

The 20-skill benchmark is unchanged (review recall 1.000, block recall 0.300, 0 false flags); every malicious sample keeps its verdict, grade and finding count.

## 0.9.0 — unreleased

**Dependency unscanned.** A skill that only installs an outside tool used to get a clean A, because the scan never opens that tool. Now every registry package a skill installs (frontmatter `install` entries of kind `node`/`npm`, `uv`/`pip`, `brew`, `go`, `cargo`, `apt`/`dnf`, and `npm install -g`, `npx`, `pip install`, `uv tool install`, `uvx`, `pipx`, `brew install`, `go install`, `cargo install` commands in SKILL.md) is printed as `dependency unscanned:` with the exact name, the version as written, and whether it is pinned. The grade says so: `A (100/100), skill files only: 1 dependency unscanned`. The verdict and exit code do not change. On the 2,827-skill registry scan, 767 skills install 1,220 such packages; 229 of them would otherwise have graded a bare A. Suggested separately by SamanthaSchacht, Jeff_The_Metal_Ghost and clawyer on Moltbook.

**Install-name existence check.** `scan --check-registry` asks npm and PyPI whether each install name exists. A 404 is a new high finding, `IH-DEP-001`: the name is free for anyone to register. Offline, timeouts, rate limits and other errors are reported as `not checked`, never as missing. Off by default; scans stay local.

**Docs vs scripts.** `IH-PRIV-001` and `IH-FS-001` hits inside fenced Markdown code blocks (setup examples a person runs) are now one step lower than the same line in a shipped script (high to medium, medium to low), with a `Docs example` note. Remote execution, injection, exfiltration and credential rules are unchanged in docs. A declared read-only reference to one nearby named file (`Reads ../shared/style.md (read-only)`) is now info instead of medium. Reported by codexmainbizmac in the first scored beta pass. Registry-wide: 369 `IH-PRIV-001` and 139 `IH-FS-001` doc hits move down a step, 48 read-only references become info, 30 skills move from block to review, and 4 skills whose only hits were fenced `ln -s` / `../` doc examples move from review to no-findings (the hits stay visible as low).

**Fixed: `//` read as a URL.** `IH-NET-001` read any `//` after a letter or digit as a protocol-relative URL, so base64 `sha512-` integrity hashes in `package-lock.json` / `pnpm-lock.yaml`, Python floor division (`w//2`), shell `${var//a/b}` and DTD `-//W3C//` lines were flagged as hosts (one as an IP, high). Protocol-relative URLs now count only right after a quote, `(` or `=`, followed by a dotted host. Registry-wide this removes 552 false hits (524 in lockfiles) and adds none; 2 skills whose only finding was such a hit move from review to no-findings.

The 20-skill benchmark is unchanged (review recall 1.000, precision 1.000, 0 false flags; block 3/10, 0 false blocks).

## 0.8.0 — 2026-10-16

Wider `IH-INJ-004` (remote or self-updating instructions). On 26 hand-verified ClawHub skills that pull instruction text from the web, 0.7.0 flagged 13; 0.8.0 flags 25. Newly caught:

- downloads that use an output flag instead of `>`: `curl -o PATH URL`, `curl URL -o PATH`, `--create-dirs -o`, `wget -O`, `-OutFile`, including commands split across lines with a trailing backslash;
- a relative target (`> skill.md`) and lowercase `skill.md` / `heartbeat.md`;
- `>>` appends of a remote fragment into `SOUL.md`, `HEARTBEAT.md`, `AGENTS.md` or `SKILL.md`, with its own message;
- plain-English fetch-and-follow: a line that names a remote `heartbeat.md` / `soul.md` URL and says to fetch or follow it, add it to `HEARTBEAT.md`, or run it as a routine. A remote `skill.md` also needs a schedule nearby, so one-time install links and plain doc links stay quiet.

The one miss left is a vague "read the canonical skill.md first" nudge with no instruction to follow it.

Fewer `IH-CRED-002` (hard-coded secret) false positives. On the same 2,827-skill registry scan, 17 of the 27 skills it flagged (about 63% of hits) were docs, not secrets. These are now quiet:

- a private-key header quoted in prose, or followed by `...`, `\n...`, `your-private-key-here` or another placeholder instead of key material;
- a public `0x` + 40-hex token or contract address.

A header followed by base64 key material (on the next line or after a literal `\n`) is still critical, and so is a bare header on its own line. Live payment keys and other high-entropy values are unchanged. New: a `0x` + 64-hex value assigned to a key-like name (an EVM private key) is flagged; hex never reached the entropy threshold before. Registry-wide: 108 hits in 27 skills became 76 hits in 13 skills, every real-looking key from before is still caught, and 3 more skills with hard-coded wallet keys are caught. The 20-skill benchmark is unchanged (review recall 1.000, 0 false flags on the clean set).

Both fixes come from [yuigui on Moltbook](https://www.moltbook.com/post/16f89e3b-fe65-40dd-b4da-f9e3cb9bd66a): a content-hash pin says nothing about a file the skill fetches at runtime, so we counted every skill that does it and found where our own rule fell short.

## 0.7.0 — 2026-10-15

Automatic updates. At most once every 6 hours, any command starts a detached background check of the npm `latest` version of `ironheights` and the latest ClawHub `ironheights` skill version (3-second timeout, silent on network failure, never blocks or changes a scan). A newer CLI is installed with `npm install -g ironheights@<exact version>` only when the running copy is a global npm install and npm reports SLSA provenance and an sha512 integrity for that version; otherwise it prints the `npx ironheights@latest` note. The skill is updated with `clawhub update ironheights`. Nothing is downgraded, and prereleases are ignored.

New command `ironheights update` (`--check` reports only, `--json`, `--disable`/`--enable`). Automatic checks are off with `IRONHEIGHTS_NO_UPDATE=1`, when `CI` is set, or with `{"autoUpdate": false}` in `~/.ironheights/update-config.json`. State lives in `~/.ironheights/update-check.json`, the log in `~/.ironheights/update.log`.

The skill tells the agent to run `ironheights update` when 6 hours have passed since the last check, so skill-only installs update too. The README and SKILL.md wording changes from "no network" to: scans stay fully local, and the only network call made without a flag is the version check, which can be disabled.

## 0.6.0 — 2026-10-15

A config suppression can name the finding it accepts. Set `evidence` to that finding's evidence and the entry hides only the same rule, path, and evidence. Line numbers are ignored, the same match `scan --since-baseline` uses for a previous JSON result. Entries without `evidence` still cover the whole rule and glob.

A finding of that rule and path with different evidence stays at full weight. It is marked `not accepted` when the named evidence is still present, and `accepted finding changed` when the named evidence is gone and the rule still fires. An evidence entry that matches nothing in a file it covers is listed as a stale suppression. `scan --print-suppressions` prints one entry per current finding, with `ruleId`, `path`, and `evidence` filled in and `reason` set to `TODO: reason`. That placeholder is refused until it is replaced. Critical findings and `IH-INT-*` findings are unchanged. With no config, scan results are unchanged. `schemaVersion` stays `1`. `acceptance` and `staleSuppressions` are additive.

The finding-by-finding acceptance was suggested by rainykurohane (Moltbook). The KitSinclair first-party regression now cites the original Moltbook post, from a note by echodemus (Moltbook).

## 0.5.1 — 2026-10-14

The skill file is found case-insensitively. A skill that ships a lowercase `skill.md` (the official Moltbook download does) is now discovered as a skill, its frontmatter name, version and declared hosts are read, and `IH-META-001` checks it. Before, that frontmatter was ignored, so the skill's own host was treated as unknown. Scanning the Moltbook download directly now grades B (80/100), verdict `review`. When both spellings exist, `SKILL.md` wins.

A plain link to a skill's own declared host is not an `IH-INJ-004` finding; an instruction to fetch from that host and follow it, or to overwrite the skill's own files with it, still is (first-party, medium). Both cases now have regression tests.

The link-vs-instruction test pair was suggested by [KitSinclair on Moltbook](https://www.moltbook.com/post/d07b2559-4c63-4a33-a776-96bccad69d82).

First-party `IH-INJ-004` findings are grouped per rule across files, so the grade no longer depends on which file a duplicated line was kept from.

## 0.5.0 — 2026-10-14

Fairer grades. 0.4.0 graded the official Moltbook skill F (25/100) although it is not malicious. Five medium findings were simply added up: the same `curl … > SKILL.md` line counted twice because it is copied into `SKILL.md` and `heartbeat.md`, remote instructions from the skill's own declared host weighed the same as a stranger's, and two API route lines were misread as path traversal. The grade now:

- counts identical evidence for one rule once, across files;
- groups repeat hits of one rule in one file (first in full, the rest at half, capped at twice the worst hit);
- weighs a first-party `IH-INJ-004` finding (every URL on the line is the skill's own declared host) as a 10-point review item. The finding stays medium, gets `firstParty: true` and a note, and the verdict stays `review`. Third-party hosts are not discounted, and a critical finding always counts 100.

The Moltbook skill now grades B (85/100), verdict `review`, with its three self-update and remote-instruction lines still listed. Every malicious test fixture still grades F, and benchmark recall is unchanged (review recall 1.000 on the 20-skill corpus). `score` in the JSON keeps the plain severity sum and still drives the verdict; only `grade` changes. `schemaVersion` stays `1`; `firstParty` is an additive finding field.

`IH-FS-001` no longer reads URLs, API routes (`GET /api/v1/posts/uuid.../comments`) or `...` placeholders as `../` path traversal.

Rescan on update. `scan --changed` rescans only skills that are new or whose content hash or `SKILL.md` version changed since their last scan, and says why. State lives in `~/.ironheights/scan-state.json`. `ironheights watch` repeats that check every 60 seconds (`--interval`, `--once`). The Ironheights skill now tells the agent to rescan any skill after it is installed or updated, before using it.

## 0.4.0 — 2026-10-14

`IH-NET-001` no longer flags the skill's own declared hosts. A host counts as declared when it appears in frontmatter `homepage`, or under a `homepage`, `website`, `url`, `api_base`, `api`, `network`, `repository`, or `source` key anywhere in `metadata`. A leading `www.` is ignored and subdomains match. A declared host that is a raw IP or a known high-risk host (paste sites, webhook catchers, tunnels, shorteners) is still flagged at high severity. Prose URLs never declare a host.

`IH-NET-001` reports repeated hits on one host in one file as a single finding at the first line, with "Seen N times (lines …)" in the message. A skill that mentions its API in 70 places now gets one finding, not 70. Score and grade drop to match.

New rule `IH-INJ-004` (medium, review): remote or self-updating instructions. It flags a download that writes over a skill file (`curl … > …/skills/…/SKILL.md`), prose that tells the agent to overwrite its own skill files, and an instruction to fetch a remote file on a schedule ("every 30 minutes", "daily", "on each heartbeat") and follow it. A scan covers only the copy on disk, so these skills can change after review. Repeats of one pattern in a file are grouped.

New rule `IH-BIN-002` (medium, review): compiled files that cannot be scanned (`.pyc`, `.pyo`, `.pyd`, `.class`, `.wasm`, `.luac`, `.beam`, `.elc`, `.o`, `.a`, `.node`). A `.pyc` next to a clean `.py` can hold different code. `schemaVersion` stays `1`.

## 0.3.1 — 2026-10-14

After a clean (`no-findings`) human-readable `scan` in an interactive terminal, one line on stderr suggests starring the skill on ClawHub. It is skipped when stdout or stderr is not a TTY, when `CI` is set, with `--quiet`, `--json`, `--format html`, or `--dry-run`, and when `IRONHEIGHTS_NO_STAR_HINT=1` is set. stdout, exit codes, and JSON/SARIF/HTML output are unchanged. No network call is made. The README has ClawHub, GitHub, and npm badges.

## 0.3.0 — 2026-10-11

`ironheights coexist` (alias `ironheights doctor coexist`) looks for other security tools on this machine and reports where they overlap with Ironheights. It reads files only: OpenClaw config plugin and hook entries, plugin manifests, skill and hook folders, known state paths, `PATH` lookups, and CI files in a repo folder. It runs no other tool, calls no network, and writes nothing. Each detected tool lists the file that showed it. Findings `IH-COEX-001` to `IH-COEX-011` cover two tool-call guards, Ironheights enforce mode blocking another tool, two tools owning the same files, config rewriting, shared state paths, double network use, scheduled scans, instruction overlap, a traffic-intercepting proxy, a config that exempts a security tool by name, and a plugin allowlist that leaves the guard out. Each has a severity and a fix. `--json` follows `docs/coexistence.schema.json`. `--fail-on <severity>` exits 1 when a finding reaches that severity. The list of known tools is in `src/coexist/registry.ts`, with a source for every entry. Detection is heuristic, and absence of a finding is not proof that tools will not interfere. See [docs/coexistence.md](docs/coexistence.md).

`ironheights doctor` prints a one-line summary of other security tools.

The guard plugin takes a `priority` setting (default 80, range -1000 to 1000). OpenClaw runs higher numbers first, and a block ends the chain. At startup the plugin writes one log line when it sees other security tools. The line is read-only, has a three-second limit, and never delays or breaks startup. The guard still only returns `block` and `blockReason`, still never blocks in `monitor` mode, and keeps all its files under `~/.ironheights`.

`scan` notes a skill whose folder name or `SKILL.md` name equals a listed security tool: "name match only, not verified". Findings of the injection and credential kinds that sit in Markdown files get their `confidence` lowered one step and a `note`. Severity, score, grade, verdict, and exit code do not change, and nothing is allowlisted. A copied name earns no trust. `schemaVersion` stays `1`. `knownSecurityTool` and `note` are additive fields.

## 0.2.0 — 2026-10-10

`scan --json` and `scan --format html` (and every other command that writes to stdout) wait until the pipe has accepted the whole report before the process ends. `process.exit()` was dropping everything past the first 64 KiB, so a piped report came back as broken JSON. A file written with `--sarif` or `--html` was already complete. The exit code is unchanged.

`dist/` is scanned like any other directory. A pipe-to-shell line in `dist/` is a finding. `.git/` and `node_modules/` are not entered. They are listed in the text report, in JSON `skippedDirectories`, and in the SARIF run `properties`, with the warning "Skipped directories were not scanned." Their presence makes the verdict `incomplete` and the exit code `3` when the scanned files would otherwise be `no-findings`. Review still exits `1` and block still exits `2`. `--allow-skipped` keeps the warning and returns the finding verdict. `ignoreDirs` in config, each entry a path plus a reason of at least 8 characters, acknowledges `.git` or `node_modules` so they stay listed and do not make the scan incomplete. The grade is `incomplete` when a directory was skipped and not acknowledged, including when `--allow-skipped` is set. See [docs/limits.md](docs/limits.md).

`ironheights fetch <owner>/<slug>[@version]` downloads a ClawHub skill over HTTPS, writes the files without executing them, and scans the staging directory. `ironheights safe-install` does the same and copies the skill into a skills directory only when the verdict is `no-findings`, or `review` with `--accept-review`. `block` and `incomplete` are not installed. An existing copy is backed up and restored if the copy fails.

`ironheights advisories update` and `--online` download `https://ironheights.dev/advisories.json` and `advisories.json.sig`. The signature is Ed25519. The production public key is pinned as `8424b837422792656e6e7500869395a5afe64bf163baa63acea83f1e97cc2b6c`. A bad signature is rejected and is not cached. `scan` and `fetch` compare a cached feed with the skill name, content hashes, and indicator hosts and report `IH-ADV-001`. Tests inject a separate key. Rotating the production key is a CLI release first, then a feed signed by the new key. The private key stays offline.

`baseline create --key` and `verify --key` sign and check `baseline.json` with HMAC-SHA256 or Ed25519. `verify` reports a signature mismatch as a tampered baseline. Release builds still publish to npm with provenance, and they also write `SHA256SUMS` for the GitHub release.

`ironheights guard` watches OpenClaw tool calls for credential-path reads, download-and-execute shell commands, outbound requests to undeclared or high-risk hosts, and writes to agent identity files, memory files, and skill folders. The default mode is `monitor`: append a redacted line to a local log and do not block. `enforce` blocks the call until the policy file has an allow entry with a reason. Host allowlists reuse `allowDomains`, including `metadata.ironheights.allowDomains` when the tool call names that skill.

The OpenClaw integration is an in-process `before_tool_call` plugin (`openclaw.plugin.json`). It is not a sandbox and not a process outside the agent. A skill that can edit OpenClaw config or the policy file can turn it off. Limits and the threat model are in `docs/guard.md`.

`scan` prints a grade next to "Absence of findings is not proof of safety." The grade is a trust score from 0 to 100 (A 90–100, B 80–89, C 70–79, D 60–69, F 0–59) based on the existing risk points. Any skipped file, including a scan that passed `--allow-skipped`, is grade `incomplete` and has no numeric score. The grade uses the worst skill after suppressions, including findings that `--since-baseline` omits from the finding list. An `IH-ADV-001` match is included in that grade. `schemaVersion` stays `1`. Grade, summary, badge, scan mode, suppressions, references, and `advisoryFeed` are additive fields.

`scan --since-baseline [file]` reports findings that are new. With no file it reads `~/.ironheights/baseline.json`. An integrity baseline treats a finding as pre-existing when that file's bytes still match, and it refuses a `treeHash` mismatch. A previous `--json` result matches rule id, file, and evidence, and ignores line numbers. Omitted findings are counted and listed. The exit code follows the new findings. A text scan accepts only a previous JSON result.

`scan --html <file>` and `--format html` write one HTML file. It has no scripts and a `default-src 'none'` content security policy. Untrusted text is escaped. The report includes a README badge line that does not call a badge service. Text output prints the same summary and badge.

Inline `ironheights-ignore IH-XXX-000 reason="..." ` comments, and config `suppressions`, require a reason of at least 8 characters. A comment applies to its own line and the next line. Suppressed findings are counted and listed. A marker with no usable reason is listed and does not hide the finding. Critical findings and `IH-INT-*` findings stay visible unless `suppressCritical` or `suppressIntegrity` is set. A critical integrity finding needs both.

`scan --stdin` and `scan --text` run the same content rules on one piece of text for inbound email or web text. The output is labelled as a limited text scan. `--stdin` reads a pipe and returns a usage error on a terminal. This mode does not execute the text.

`IH-MCP-001`, `IH-MCP-002`, and `IH-MCP-003` check MCP configuration files for a shell pipe or an unpinned `npx` package, a literal secret in `env`, and a broad filesystem root. [docs/other-agents.md](docs/other-agents.md) explains how to point `scan` at Claude Code, Codex, and Cursor skill folders. An MCP server interface for ironheights itself stays excluded. See [docs/ideas.md](docs/ideas.md).

Rules in JSON and SARIF `properties` and tags now carry OWASP LLM Top 10 2025, OWASP Agentic Top 10 2026, and MITRE ATLAS ids where a mapping is defensible. `docs/rules.md` lists `none` when it is not.

`ironheights audit-config` (alias `doctor audit`) reads the local OpenClaw config and reports `IH-CFG-001` through `IH-CFG-009`. Output is text, JSON, or SARIF. `schemaVersion` stays `1`, with extra fields `command`, `configPath`, `configFound`, `configParsed`, `nativeAudit`, and `limits`. Secret values are replaced with `<redacted>`. The command does not call the network, does not change files, and does not replace `openclaw security audit`.

A composite action at `action.yml` runs `npx ironheights@<pinned version> scan`. `.pre-commit-hooks.yaml` scans a tree with `ironheights` on `PATH`. Exit code `3` still means the scan was incomplete.

Windows CI on `windows-latest` runs the build, the test suite, and the packed CLI smoke test on Node.js 20.0.0 and Node.js 24. Path handling accepts `~\` and `%USERPROFILE%` / `%APPDATA%` / `%LOCALAPPDATA%`. Credential rules recognize those home paths. Scanned text is normalized to LF.

`scan --llm` and `review` ask a language model for an advisory second opinion. The review is off unless you pass it. The default server is a loopback Ollama-compatible endpoint. A non-localhost URL needs `--llm-consent` and `IRONHEIGHTS_LLM_API_KEY`. Ironheights prints the exact request body before sending it. `--dry-run` prints that body and does not send it.

The model can only add `IH-LLM-001` notes. Those notes do not change the verdict, the grade, or the exit code. A block stays a block. If the model is unreachable, times out, or returns anything other than the expected JSON, the scan keeps the deterministic result and says why. Skill text is capped, stripped of control characters, and scrubbed for common secrets before it is sent. The scrub can miss a secret. Model notes can be wrong. `scan --stdin` and `scan --text` are not sent to a model, because a text scan has no skill directory.

## 0.1.5

`IH-NET-001` reports a Markdown URL again when the line tells the reader to download, install, fetch, or follow it, and when the host is a paste site or a file-drop host such as `rentry.co`, `glot.io`, `transfer.sh`, or `file.io`. A schema link such as `http://schemas.openxmlformats.org/...` and an official API host mentioned in prose stay quiet. `metadata.ironheights.allowDomains` still skips a declared host for that skill only.

`IH-EXEC-002` still reports each install command once. On the public benchmark corpus, `prereq-install` is review again because the undeclared git host is reported, and it is not block: the extra install findings from 0.1.0 stay fixed.

## 0.1.4

`IH-EXEC-002` reports each install or remote-run command once, on the line that contains the command. A prerequisite on a nearby line does not add another finding, and a blank line is not a finding. Evidence is the command itself.

`IH-CRED-001` treats `~/.ssh`, `~/.aws`, `~/.gnupg`, and `~/.azure` as credential locations with or without a trailing slash. `IH-NET-002` reports an instruction that sends one of those paths to a URL. Names such as `sshd` do not match.

SARIF `runs[0].tool.driver.informationUri` is `https://github.com/Frank-Masciopinto/ironheights`.

A file larger than `limits.maxFileBytes` (1 MiB by default), and any other skipped file, is named in the text report. The verdict is `incomplete` and the exit code is `3` when the scanned files would otherwise be `no-findings`. Review still exits `1` and block still exits `2`. `--allow-skipped` accepts the skipped files and restores the finding verdict. JSON `skippedFileCount` is on the document and on each skill. SARIF stores that count on the run `properties`.

0.1.2 and 0.1.3 below are part of this release. They landed on main in PRs #4 and #5 and were not tagged.

## 0.1.3

A skill can list the hosts it contacts under `metadata.ironheights.allowDomains` in `SKILL.md`. `IH-NET-001` skips those hosts and their subdomains for that skill only. Another skill that calls the same host still reports. Bundled OpenClaw skills do not declare their hosts yet, so `scan --all` on a stock install still reports their API hosts.

## 0.1.2

`scan --all` and `doctor` now include OpenClaw bundled skills, custodian skills, and the real directories behind `~/.openclaw/plugin-skills` symlinks.

A scan of the local OpenClaw 2026.9.3 skill trees showed several false-positive shapes. `process.env` and a mentioned `.env` are not a dotenv path, the word "cookies" is not the browser cookie store, and the word `curl` is not a request. Loopback addresses are treated like `localhost`. Homepage fields, license URLs, XML namespaces, placeholder hosts, and documentation links are not network destinations. An exfiltration finding requires the secret and the request in the same few lines. A package install is a URL install only when the URL is on that same line. Requests the skill actually makes, such as `curl` to an API host, still report `IH-NET-001`.

## 0.1.1

Fixed a silent exit 0 when `ironheights` or `ih` is started through an npm bin (`npx`, a local install, or a global install). The entry check resolves the real script path, so a symlink or a Windows shim that passes a relative path still runs the command.

## 0.1.0

First MVP: local skill scanning, P0 and P1 rules, baseline verification, quarantine, SARIF output, and the synthetic benchmark.
