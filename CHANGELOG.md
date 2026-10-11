# Changelog

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
