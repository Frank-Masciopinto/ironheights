# Changelog

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
