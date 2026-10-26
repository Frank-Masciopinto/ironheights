# Ironheights

[![Star on ClawHub](https://img.shields.io/badge/ClawHub-star%20the%20skill-f59e0b?logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyIDE1LjEgOC4zIDIyIDkuMyAxNyAxNC4xIDE4LjIgMjEgMTIgMTcuOCA1LjggMjEgNyAxNC4xIDIgOS4zIDguOSA4LjN6Ii8+PC9zdmc+)](https://clawhub.ai/frank-masciopinto/skills/ironheights)
[![GitHub stars](https://img.shields.io/github/stars/Frank-Masciopinto/ironheights?style=flat&logo=github&label=Star%20on%20GitHub)](https://github.com/Frank-Masciopinto/ironheights)
[![npm](https://img.shields.io/npm/v/ironheights?logo=npm)](https://www.npmjs.com/package/ironheights)

If Ironheights is useful to you, a star on [ClawHub](https://clawhub.ai/frank-masciopinto/skills/ironheights) or GitHub helps other OpenClaw users find it.

**Ironheights is an open-source, local-first security scanner for OpenClaw agent skills.** Website: [www.ironheights.dev](https://www.ironheights.dev)

Ironheights is a local-first scanner and integrity monitor for [OpenClaw](https://docs.openclaw.ai) skills. It reads skill files as data, looks for risky patterns with fixed rules, and compares skill and agent files with a baseline you save on the same machine.

It does not send telemetry, and it does not run the files it scans. Scans are fully local. The only network call made without a flag is a version check against npm and ClawHub, at most once every 6 hours; it only reports new versions, never installs anything, and can be turned off (see [Updates](#updates)). Other network use happens only when you run `fetch`, `safe-install`, `advisories update`, `--online`, `scan --llm`, `scan --check-registry`, or `review`.

## Install

Install the OpenClaw skill from ClawHub (recommended):

```bash
clawhub install ironheights
```

The skill uses the `ironheights` CLI, which requires Node.js 20 or newer on macOS, Linux, and Windows.

OpenClaw 2026.9.3 requires Node.js `>=24.16.0 <25 || >=26.1.0`. `ironheights doctor` prints whether the current runtime is inside that range.

Then install the CLI, or run it once with npx:

```bash
npx ironheights scan ./path/to/skill
```

Or install the command:

```bash
npm install -g ironheights
ironheights scan ./path/to/skill
```

`ih` is the same command. From a git checkout:

```bash
npm install
npm run build
node dist/cli/index.js scan test/fixtures/benign
```

## 60-second quickstart

```bash
npx ironheights doctor
npx ironheights scan ~/.openclaw/workspace/skills/some-skill
npx ironheights baseline create
npx ironheights verify
```

`doctor` prints which OpenClaw directories it found and which it did not. `scan` prints findings grouped by skill. A run with nothing to report looks like this:

```text
benign
  No findings

Verdict: no-findings
Absence of findings is not proof of safety.
```

A review looks like this:

```text
demo
  [high] IH-CRED-001 SKILL.md:3
    cat ~/.ssh/id_rsa
    Do not read these paths from a skill. Use a scoped environment variable or the platform secret store.

Verdict: review
Absence of findings is not proof of safety.
```

| Exit | Meaning                                                                                                                 |
| ---- | ----------------------------------------------------------------------------------------------------------------------- |
| 0    | No findings                                                                                                             |
| 1    | Review                                                                                                                  |
| 2    | Block                                                                                                                   |
| 3    | Incomplete. A file was skipped, or `.git` / `node_modules` was not entered, and the rest did not reach review or block. |
| 64   | Usage or config error                                                                                                   |
| 70   | The command stopped: an internal error, a failed network request, or a rejected signature.                              |

`--fail-on low|medium|high|critical` returns `0` when every finding is below that severity and nothing was skipped. A skipped file, or a `.git` or `node_modules` directory that was not entered, still returns `3` unless you pass `--allow-skipped` or you list that directory under `ignoreDirs` with a reason. `--allow-skipped` keeps the warning and returns the finding verdict (`0`, `1`, or `2`). The grade stays `incomplete`. Limits and `ignoreDirs` are in [docs/limits.md](docs/limits.md).

A scan that skipped a file looks like this:

```text
padded
  warning: skipped payload.md (file exceeds 1048576 bytes)
  Scan incomplete: 1 file was not scanned.

Verdict: incomplete
Absence of findings is not proof of safety.
```

## Commands

```text
ironheights scan <path> [--all] [--json] [--sarif <file>] [--md <file>] [--html <file>] [--format text|json|html] [--since-baseline [file]] [--print-suppressions] [--stdin] [--text <text>] [--fail-on <severity>] [--config <file>] [--allow-skipped] [--no-color] [--quiet] [--llm] [--llm-url <url>] [--llm-model <name>] [--llm-api ollama|openai] [--llm-consent] [--dry-run] [--check-registry]
ironheights review <path> [the same flags as scan]
ironheights fetch <owner>/<slug>[@version] [--out <dir>] [--json] [--sarif <file>] [--md <file>] [--fail-on <severity>] [--config <file>] [--allow-skipped] [--no-color] [--quiet]
ironheights safe-install <owner>/<slug>[@version] [--dir <skills-dir>] [--accept-review] [--out <dir>] [--json] [--config <file>] [--no-color] [--quiet]
ironheights advisories update
ironheights advisories show
ironheights baseline create|update|show [--key <file>]
ironheights verify [--key <file>]
ironheights quarantine <skill>
ironheights quarantine restore <id>
ironheights rules list
ironheights rules show <id>
ironheights doctor
ironheights doctor audit
ironheights coexist [--json] [--fail-on <severity>] [--openclaw-config <file>] [--repo <dir>]
ironheights audit-config [--json] [--sarif <file>] [--md <file>] [--fail-on <severity>] [--openclaw-config <file>]
ironheights bench <corpusDir> [--external <file.json>]
ironheights guard status [--policy <file>] [--config <file>] [--json]
ironheights guard policy check [--policy <file>] [--config <file>] [--call <json>] [--call-file <file>] [--json]
ironheights guard log [--tail <n>] [--policy <file>] [--json]
ironheights update [--check] [--json] [--disable] [--enable]
ironheights --online <command>
```

`scan` reads a cached advisory feed when one is present and does not download it. `--online` prints the feed URLs, downloads `https://ironheights.dev/advisories.json` and `https://ironheights.dev/advisories.json.sig`, checks the signature, then runs the rest of the command. `--online` with no other command only updates the cache. `--all` scans the skill directories from config, or the OpenClaw locations below when config does not set `skillDirs`.

## Fetch and safe-install

`fetch <owner>/<slug>[@version]` downloads a ClawHub skill into a temp directory, or into `--out`, and scans it. It prints every URL before requesting it. The host is `https://clawhub.ai`. Redirects are refused. Files are written mode `0600` and are not executed. Zip and tar bytes are stored and not extracted. Absolute paths, `..`, and symlinks are refused. See [docs/fetch.md](docs/fetch.md).

```text
fetch ada/notes@1.0.0
This command contacts the network. Scans stay local. Besides fetch, safe-install, advisories update, --online, scan --llm, and review, the only network call is a version check every 6 hours (off with IRONHEIGHTS_NO_UPDATE=1).

Requesting:
  GET https://clawhub.ai/api/v1/skills/notes?owner=ada
  GET https://clawhub.ai/api/v1/skills/notes/versions/1.0.0?owner=ada

Requesting:
  GET https://clawhub.ai/api/v1/skills/notes/file?owner=ada&path=SKILL.md&version=1.0.0

notes
  No findings

Verdict: no-findings
Absence of findings is not proof of safety.
Staged 1 files at /tmp/ironheights-fetch-.../notes
```

`safe-install` uses the same download, then copies into the OpenClaw workspace skills directory, or into `--dir`. It copies only when the verdict is `no-findings`, or `review` if you pass `--accept-review`. `block` and `incomplete` are not installed. An existing copy is moved to `~/.ironheights/install-backup/` first and restored if the copy fails.

## Advisory feed

`advisories update` downloads the signed feed from `https://ironheights.dev/advisories.json` and the detached signature beside it, then stores both under `~/.ironheights`. A bad signature is not cached. `scan` and `fetch` compare the skill name, file sha256, and indicator hosts with that cache and report `IH-ADV-001` with the source links. The feed format, the pinned public key, and the signing steps are in [docs/advisories.md](docs/advisories.md).

```text
advisories update
This command contacts the network. Scans stay local. Besides fetch, safe-install, advisories update, --online, scan --llm, and review, the only network call is a version check every 6 hours (off with IRONHEIGHTS_NO_UPDATE=1).

Requesting:
  GET https://ironheights.dev/advisories.json
  GET https://ironheights.dev/advisories.json.sig

Advisory feed signature verified.
Cached 2 advisories generated at 2026-10-10T00:00:00.000Z
Wrote /home/ada/.ironheights/advisories.json
```

The production public key is pinned in this release: `8424b837422792656e6e7500869395a5afe64bf163baa63acea83f1e97cc2b6c`. A feed signed by another key is rejected. `scan` with no cache still runs offline. Rotating the key is a new CLI release first, then a feed signed by the new key. The private key is not in this repository.

`audit-config` reads the local OpenClaw config and reports high-risk settings as `IH-CFG-001` through `IH-CFG-009`. `doctor audit` is the same command. It does not replace [`openclaw security audit`](https://docs.openclaw.ai/cli/security). See [docs/audit-config.md](docs/audit-config.md).

## Grade

Every scan prints a grade on the line before "Absence of findings is not proof of safety." The number is a trust score: 100 minus the risk score, and never below 0. A is 90–100, B is 80–89, C is 70–79, D is 60–69, and F is 0–59. The grade uses the worst skill after suppressions. Findings omitted by `--since-baseline` still count toward the grade.

The risk score behind the grade starts from the finding severities (critical 100, high 40, medium 15, low 5) and then removes double counting. The same evidence line for one rule, copied into two files, counts once. Repeat hits of one rule in one file are grouped: the first counts in full, each further hit counts half, and the group is capped at twice its worst hit. A first-party finding (an `IH-INJ-004` remote-instruction or self-update line whose URLs all point at the skill's own declared host) counts as a review item, 10 points. It stays a medium finding with `firstParty: true` and a note, and the verdict is unchanged. A critical finding always counts 100, so anything critical is F. `score` in the JSON keeps the plain severity sum and drives the verdict.

A skipped file, or a `.git` or `node_modules` directory that was not acknowledged in `ignoreDirs`, makes the grade `incomplete` and hides the number, including when you pass `--allow-skipped`. The exit code can still be 0 in that case. The verdict line is unchanged.

```text
Verdict: review
Grade: D (60/100)
Absence of findings is not proof of safety.
ironheights 0.9.0 | demo | grade D (60/100) | verdict review | 1 finding
Badge: [ironheights 0.9.0: grade D (60/100), verdict review](https://github.com/Frank-Masciopinto/ironheights) — Absence of findings is not proof of safety.
```

The badge line is text you can paste into a README. It does not load an image from a badge service.

### Dependencies unscanned

The scan reads the skill's own files. When a skill installs a package from a registry (a `metadata.<agent>.install` entry in SKILL.md frontmatter of kind `node`, `npm`, `uv`, `pip`, `brew`, `go`, `cargo`, `apt`, or an install command in SKILL.md such as `npm install -g`, `npx`, `pip install`, `uvx`, `brew install`, `go install`), that package's code was not scanned. Each one is listed as `dependency unscanned:` with the exact package name, the version as written, and whether it is pinned to an exact version. The grade then reads, for example, `A (100/100), skill files only: 1 dependency unscanned`, so a wrapper skill no longer gets a bare clean A. The verdict and exit code are unchanged. JSON reports carry the list as `unscannedDependencies`.

`scan --check-registry` also asks registry.npmjs.org and pypi.org whether each npm and PyPI install name exists. A name the registry does not know (HTTP 404) is a high `IH-DEP-001` finding: anyone could register it. Only a 404 counts. Offline, a timeout, a rate limit or any other status is reported as `not checked`, never as missing. Nothing about the skill is sent beyond the package name in the URL.

### Docs examples

`IH-PRIV-001` (sudo, broad chmod, disabling OS protections) and `IH-FS-001` (path traversal) hits inside a fenced code block in a Markdown file are graded one step lower than the same line in a shipped script, with a `Docs example` note: the docs tell a person to run it, a script runs it. Remote-execution, injection, exfiltration and credential rules keep full severity in docs. A line that names one nearby file (at most two `../`) and says it is only read, with no write, delete, walk, wildcard, network verb or sensitive target, is an info `IH-FS-001` finding.

## Rescan on update

A scan covers the copy on disk. `ironheights scan --changed <skills folder>` (or `--all`) rescans only skills that are new or whose content hash or `SKILL.md` version changed since their last scan, and prints why ("version changed (1.12.0 -> 1.13.0)"). The hash and version of each scanned skill are kept in `~/.ironheights/scan-state.json`. When nothing changed, it prints "Nothing to rescan." and exits 0.

`ironheights watch [paths...]` (or `watch --all`) runs that check every 60 seconds (`--interval <seconds>`, minimum 5) until stopped. `watch --once` checks once and exits, which suits cron or a post-update hook. The exit code is the worst seen.

## Findings since a baseline

`scan --since-baseline` compares the scan with a saved result and lists only findings that are new. Omitted findings are counted under "Omitted as pre-existing" and are not removed from the grade. The exit code follows the new findings, so an update that adds nothing new exits 0 even when the grade is still D or F.

With no path, the flag reads `~/.ironheights/baseline.json` (or `$IRONHEIGHTS_HOME/baseline.json`). That file is the integrity baseline from `baseline create`. A finding is pre-existing when the file's bytes still match the saved hash. A changed or new file reports every finding in that file. If `treeHash` does not match the file hashes, the scan stops with exit 64 and hides nothing.

You can also pass a previous `--json` report. A finding is pre-existing when the skill name, rule id, file, and evidence match. Line numbers are ignored. Save that report from a scan that did not use `--since-baseline`.

```bash
ironheights scan ./skill --since-baseline
ironheights scan ./skill --json > previous.json
ironheights scan ./skill --since-baseline previous.json
```

Put the skill path before `--since-baseline` when you omit the file, so the flag does not take the path as its argument.

## HTML report

`--html report.html` writes one HTML file and still prints the text report. `--format html` prints the HTML to stdout. The file contains its CSS, no scripts, and a content security policy of `default-src 'none'`. Skill names, paths, and evidence are escaped. The page does not request anything from the network.

## Suppressions

A suppression needs a reason of at least 8 characters. The comment applies to the line it is on and the next line. Quote the reason when it contains spaces.

```text
# ironheights-ignore IH-CRED-001 reason="reviewed local demo"
cat ~/.ssh/id_rsa
```

`//` and `<!-- -->` comments work the same way because the marker is plain text. A marker with no rule id or no usable reason is listed under "Suppression ignored" and the finding stays.

Config entries do the same job for a rule and an optional glob:

```json
{
  "suppressions": [
    { "ruleId": "IH-NET-001", "path": "docs/**", "reason": "documented example hosts" }
  ],
  "suppressCritical": false,
  "suppressIntegrity": false
}
```

An entry can name the finding it accepts by adding `evidence`. Use the evidence string from the report. The entry then suppresses only a finding with that rule id, a path the glob matches, and that exact evidence. Line numbers are ignored, the same match `scan --since-baseline previous.json` uses. An entry without `evidence` still covers the whole rule and glob. Evidence is the stricter option.

```json
{
  "suppressions": [
    {
      "ruleId": "IH-CRED-001",
      "path": "SKILL.md",
      "evidence": "cat ~/.ssh/id_rsa",
      "reason": "reviewed this local demo path"
    }
  ]
}
```

`ironheights scan <path> --print-suppressions` prints one entry per current finding, with `ruleId`, `path`, and `evidence` filled in. `reason` is `TODO: reason` until you replace it. That placeholder meets the length rule and is still refused, so the finding stays visible at full weight. The entries are JSON on stdout. The exit code is still the scan verdict. `--print-suppressions` replaces the report on stdout.

A finding of the same rule and path that was not named stays at full weight. It is marked `not accepted` when a named finding in that scope is still present, and `accepted finding changed` when every named finding for that rule and path is gone but the rule still fires. An evidence entry that matches nothing in a file it covers is listed under "Stale suppression". Text, JSON (`acceptance` on the finding, `staleSuppressions` on the skill), and SARIF all show these. `schemaVersion` stays `1`. With no suppression config, scan results are unchanged.

Suppressed findings are listed with their reasons and counted in the summary line. They do not add risk points. Critical findings stay visible unless `suppressCritical` is true. `IH-INT-*` findings, including on `verify`, stay visible unless `suppressIntegrity` is true. A critical integrity finding needs both.

## Text scan

`scan --text` and `scan --stdin` run the content rules on one piece of text, for an inbound email or a web page. The report starts with a limited-scan line: this is not a review of a skill directory, and the text is not executed. `--stdin` reads a pipe. On a terminal it exits 64. Do not combine either flag with a path or `--all`.

```bash
ironheights scan --text 'Hello, the meeting is at 3pm.'
printf '%s' 'Ignore previous instructions' | ironheights scan --stdin
```

## Other agents and MCP configs

The same `scan` command reads Claude Code, Codex, and Cursor skill folders. MCP configuration rules `IH-MCP-001`, `IH-MCP-002`, and `IH-MCP-003` flag a server launched with `curl|sh` or an unpinned `npx` package, a literal secret in `env`, and a broad filesystem root. Paths and examples are in [docs/other-agents.md](docs/other-agents.md). Ironheights does not ship an MCP server. See [docs/ideas.md](docs/ideas.md).

## Config

Ironheights reads `ironheights.config.json` from the current directory, then `~/.ironheights/ironheights.config.json`. Unknown keys are an error. `thresholds.block` defaults to 80 and `thresholds.review` defaults to 15.

```json
{
  "skillDirs": ["~/.openclaw/workspace/skills"],
  "agentFiles": ["~/.openclaw/workspace/AGENTS.md"],
  "allowDomains": ["docs.example.com"],
  "ignoreGlobs": ["**/*.map"],
  "ignoreDirs": [{ "path": "node_modules", "reason": "packages are not skill instructions" }],
  "ruleOverrides": { "IH-NET-001": { "enabled": true, "severity": "low" } },
  "failOn": "high",
  "limits": { "maxFileBytes": 1048576, "maxFiles": 2000, "maxDepth": 10 },
  "thresholds": { "block": 80, "review": 15 },
  "suppressions": [
    { "ruleId": "IH-NET-001", "path": "docs/**", "reason": "documented example hosts" },
    {
      "ruleId": "IH-CRED-001",
      "path": "SKILL.md",
      "evidence": "cat ~/.ssh/id_rsa",
      "reason": "reviewed this local demo path"
    }
  ],
  "suppressCritical": false,
  "suppressIntegrity": false,
  "llm": { "url": "http://127.0.0.1:11434", "model": "llama3.2", "api": "ollama" }
}
```

`ignoreDirs` acknowledges `.git` or `node_modules` so those directories stay listed and do not make the scan incomplete. Each entry needs a reason of at least 8 characters. `dist` is scanned either way. `ignoreGlobs` drops matching paths with no finding. The default list is empty. See [docs/limits.md](docs/limits.md).

An allowlist entry matches that host and its subdomains. The built-in list includes `example.com`, `example.org`, `example.net`, `localhost`, the loopback addresses `127.0.0.1` and `::1`, GitHub, npm, PyPI, and `openclaw.ai`.

`llm` sets the model server used by `scan --llm` and `review`. It does not turn the review on, and it cannot grant consent to send skill text off the machine. Unknown keys are still an error, including a `consent` key under `llm`.

## JSON output

`--json` prints a document with `schemaVersion` `1`. New fields below are additive. Consumers that ignore unknown keys keep working, so `schemaVersion` stays `1`. Evidence-bound drift adds `acceptance` on a finding and `staleSuppressions` on a skill. Both are omitted when they do not apply.

```json
{
  "schemaVersion": 1,
  "tool": { "name": "ironheights", "version": "0.9.0" },
  "scannedAt": "2026-10-09T00:00:00.000Z",
  "verdict": "no-findings",
  "skippedFileCount": 0,
  "grade": {
    "letter": "A",
    "score": 100,
    "disclaimer": "Absence of findings is not proof of safety."
  },
  "scanMode": "directory",
  "summary": "ironheights 0.3.0 | no skills | grade A (100/100) | verdict no-findings | 0 findings",
  "badge": "[ironheights 0.3.0: grade A (100/100), verdict no-findings](https://github.com/Frank-Masciopinto/ironheights) — Absence of findings is not proof of safety.",
  "skills": []
}
```

`grade.score` is omitted when `grade.letter` is `incomplete`. A text scan sets `scanMode` to `text` and adds `scanLimit`. `--since-baseline` adds `sinceBaseline` on the document and on each skill, including `omitted`. Each skill also has `suppressed`, `suppressedCount`, `suppressionRefused`, and `suppressionRefusedCount`. When a cached advisory feed was checked, the document also has `advisoryFeed` with `entries` and `generatedAt`.

`llmReview` is present only after `scan --llm` or `review`. A normal scan does not include that key. `advisory` is always true there. The grade and `verdict` stay the deterministic result, including an `IH-ADV-001` match.

Each skill has `skillName`, `root`, `filesScanned`, `filesSkipped`, `skippedFileCount`, `findings`, `score`, and `verdict`. `skippedFileCount` is the number of files the scan did not read. `filesSkipped` lists each path and the reason. `skippedDirectories` lists `.git` and `node_modules` directories that were not entered. An `explicit` flag means `ignoreDirs` acknowledged that directory. A finding has `ruleId`, `severity`, `confidence`, `file`, optional `line` and `column`, `evidence`, `message`, `remediation`, and `references` (`owaspLlm`, `owaspAgentic`, `mitreAtlas`). With `--since-baseline`, `score` and `verdict` describe the new findings. The grade still describes the full scan, including an `IH-ADV-001` match. `--sarif` writes SARIF 2.1.0. The run `properties` include `skippedFileCount`, `gradeLetter`, `disclaimer`, and `gradeScore` when the scan is complete. Rule `properties` and `tags` include the same references. An `IH-LLM-001` result sets `properties.advisory` to true. `tool.driver.informationUri` is `https://github.com/Frank-Masciopinto/ironheights`.

Scoring is critical 100, high 40, medium 15, low 5, info 0. The verdict is `block` when any finding is critical or the score is at least 80. It is `review` when any finding is high or medium, or the score is at least 15. It is `incomplete` when files were skipped and the score would otherwise be `no-findings`. Otherwise it is `no-findings`.

## Rules

The full list is generated in [docs/rules.md](docs/rules.md), including OWASP LLM Top 10 2025, OWASP Agentic Top 10 2026, and MITRE ATLAS ids. `none` means no defensible mapping was recorded. P0 rules cover remote shells, prerequisite installs, undeclared hosts, credential paths, hard-coded secrets, instruction overrides, hidden text, bundled executables, persistence, and MCP launch and secret checks. P1 rules cover dynamic execution, exfiltration shape, secrets in chat, weakened approvals, ambient credential inheritance to a child process, obfuscation, privilege bypass, filesystem tricks, skill metadata, and broad MCP filesystem roots. Integrity rules `IH-INT-001` through `IH-INT-004` come from `verify`, not from a content scan. `IH-ADV-001` comes from the cached advisory feed, not from a content pattern. Config rules `IH-CFG-001` through `IH-CFG-009` come from `audit-config`, not from a skill scan. `IH-LLM-001` is an advisory model note. It is not a pattern rule, and it appears only after `scan --llm` or `review`.

`IH-CRED-002` uses Shannon entropy. A quoted value assigned to a key-like name is reported when it is at least 20 characters and at least 4 bits per character. Evidence keeps the first four characters and masks the rest.

## OpenClaw locations

Verified against the OpenClaw docs for the 2026.9.3 line:

| Source                | Path                                                   |
| --------------------- | ------------------------------------------------------ |
| Workspace skills      | `<workspace>/skills`                                   |
| Project agent skills  | `<workspace>/.agents/skills`                           |
| Personal agent skills | `~/.agents/skills`                                     |
| Managed skills        | `~/.openclaw/skills`                                   |
| Workshop skills       | `~/.openclaw/agents/<agent>/agent/workshop-skills`     |
| Bundled skills        | `<openclaw package>/skills`                            |
| Custodian skills      | `<openclaw package>/custodian-skills`                  |
| Plugin skills         | real paths linked from `~/.openclaw/plugin-skills`     |
| Extra directories     | `skills.load.extraDirs` in `~/.openclaw/openclaw.json` |

The default workspace is `~/.openclaw/workspace`. Config is `$OPENCLAW_CONFIG_PATH` or `~/.openclaw/openclaw.json`. State moves when `OPENCLAW_STATE_DIR` is set. On Windows, `~` is `%USERPROFILE%`, so the same defaults are `%USERPROFILE%\.openclaw\workspace` and `%USERPROFILE%\.openclaw\openclaw.json`. Paths in config may use `~`, `~/`, `~\`, `%USERPROFILE%`, `%APPDATA%`, or `%LOCALAPPDATA%`.

Bundled skills on Windows are also looked up under `%APPDATA%\npm\node_modules\openclaw\skills`, `%LOCALAPPDATA%\pnpm\global\node_modules\openclaw\skills`, `%LOCALAPPDATA%\OpenClaw\deps\portable-node\node_modules\openclaw\skills`, `%ProgramFiles%\nodejs\node_modules\openclaw\skills`, and the git-install wrapper `%USERPROFILE%\.local\bin\openclaw.cmd`. `npm_config_prefix` is checked on every platform.

Watched agent files default to `AGENTS.md`, `SOUL.md`, `IDENTITY.md`, `USER.md`, `TOOLS.md`, `BOOTSTRAP.md`, `MEMORY.md`, the `memory/` directory, `openclaw.json`, `credentials/`, and `.env` under the OpenClaw state directory. Change the list with `agentFiles`.

Bundled skills are the `skills/` directory in the OpenClaw package. Ironheights finds that package from `OPENCLAW_BUNDLED_SKILLS_DIR`, from the `~/.openclaw/bin/openclaw` wrapper, from `~/.openclaw/tools/node-v*/lib/node_modules/openclaw`, or from the usual global `node_modules/openclaw` locations. Custodian skills are the sibling `custodian-skills/` directory. Plugin skills are the directories linked from `~/.openclaw/plugin-skills`. `doctor` says when the bundled directory was not found.

`SKILL.md` needs YAML frontmatter with `name` and `description`. Optional fields include `metadata.openclaw`, `homepage`, `user-invocable`, `disable-model-invocation`, and the `command-dispatch` keys.

`metadata.ironheights.allowDomains` is a list of hosts that this skill is allowed to contact. `IH-NET-001` skips those hosts and their subdomains for that skill only. Another skill that calls the same host still reports. The bundled OpenClaw skills do not declare their hosts, so `scan --all` on a stock install still reports their API hosts.

A download, install, or fetch instruction is a contact, and so is a paste site or a file-drop host. A schema link, or an official API host mentioned in prose, is not.

## Integrity

`baseline create` writes `~/.ironheights/baseline.json` with mode `0600`. The file stores a sha256, size, and mode for each path, plus a `treeHash` of the sorted content hashes. `verify` reports added, modified, removed, and mode-changed files. Pass `--key` (or set `IRONHEIGHTS_BASELINE_KEY`) to sign `baseline.json` and to check `baseline.json.sig`. A bad signature is reported as a tampered baseline. See [docs/baseline-signing.md](docs/baseline-signing.md).

An attacker who can write your home directory and who has the key can still replace the baseline. Keeping a copy of the key off the machine is still worth doing.

`quarantine <skill>` moves a skill to `~/.ironheights/quarantine/<timestamp>-<name>`. That directory is mode `0700` where the operating system honors Unix modes. `quarantine restore <id>` moves it back. A symlink or junction inside the skill is moved with the skill and is not followed into a delete. Ironheights does not delete a skill on its own.

## Runtime guard

`ironheights guard` evaluates a tool call against a local policy. The OpenClaw plugin in this package registers `before_tool_call` and can block that call when the policy mode is `enforce`. The default mode is `monitor`: it appends a redacted line to `~/.ironheights/guard.log.jsonl` and does not block.

The hook runs inside the OpenClaw process. It is not a sandbox and not a process outside the agent. A skill that can edit OpenClaw config or the policy file can turn it off. Details, the threat model, and the policy file are in [docs/guard.md](docs/guard.md).

```bash
ironheights guard status
ironheights guard policy check --call '{"toolName":"read","params":{"path":"~/.ssh/id_rsa"}}'
```

`guard policy check` exits 0 when the call would be allowed, 1 when it would be blocked, and 64 when the policy file is invalid.

## Other security tools

Many OpenClaw setups already run another scanner or guard. `ironheights coexist` finds them and reports overlaps, read-only and offline. It never runs the other tool and never edits a file.

```bash
ironheights coexist                  # text report: tools found, with the file that showed each one
ironheights coexist --json           # JSON for CI and scripts
ironheights coexist --fail-on medium # exit 1 when a finding is medium or higher
```

It looks at OpenClaw config plugin and hook entries, plugin manifests, skill and hook folders, known state paths, `PATH`, and CI files in the folder you pass with `--repo`. Findings `IH-COEX-001` to `IH-COEX-011` cover two guards on `before_tool_call`, Ironheights enforce mode blocking another tool, two tools owning the same files, shared state paths, double network use, and a config that exempts a security tool by name. Each has a severity and a fix.

The guard plugin runs at priority 80 by default and takes a `priority` setting. When another guard already enforces, keep Ironheights in `monitor` and let one tool own blocking. `scan` notes a skill that carries the name of a known security tool and lowers confidence on its Markdown injection and credential findings. It does not allowlist anything and does not change the verdict.

Detection is heuristic. A renamed or unlisted tool is not found, and a name can be copied. Absence of a finding is not proof that tools will not interfere. Details and limits: [docs/coexistence.md](docs/coexistence.md).

## The advisory skill

`skill/ironheights/SKILL.md` tells an OpenClaw agent to run `ironheights scan <path> --json`, summarize the result, and stop on a `block` verdict until you confirm. The skill asks for no secrets. Updates are offer-only: the agent never runs `ironheights update`, `clawhub update` or a global npm install on its own. When asked, it runs `ironheights update --check` and shows you the update command to run yourself. Install the skill with `clawhub install ironheights`.

This skill is advisory. It runs inside the agent, and a hostile skill can try to bypass it. The CLI you run yourself, or a process outside the agent, is the trusted path.

## What Ironheights cannot detect

- Novel attacks and attacks that are heavily obfuscated in a way the current rules do not describe.
- Behavior that only appears at runtime and never shows up as one of the tool calls the guard knows how to read. The guard is described in [docs/guard.md](docs/guard.md). It does not see a process that is already running.
- A host that is already compromised, including a baseline an attacker can rewrite.
- Social engineering that never lands in a file the scanner reads.
- Whether a model review is right. `scan --llm` can miss an attack and it can invent one.

No findings means the rules did not match. It does not mean the skill is safe.

## Updates

Ironheights checks for a newer version at most once every 6 hours. Any command reads a local timestamp in `~/.ironheights/update-check.json`; when a check is due it starts a detached background process and the command continues at once. That process asks registry.npmjs.org for the `latest` version of `ironheights` and clawhub.ai for the latest `ironheights` skill version, with a 3-second timeout. A network failure is ignored and never affects a scan. Results go to `~/.ironheights/update.log`.

Updates are offer-only. Ironheights never installs, updates or replaces anything. When a newer version exists, `ironheights update` prints it and the command to run yourself:

- **CLI**: offered only for a strictly newer stable version, and only when npm reports SLSA provenance and an sha512 integrity for that exact version: `npm install -g ironheights@<exact version>` (or `npx ironheights@<exact version>`).
- **ClawHub skill**: `clawhub update ironheights`. Nothing is ever downgraded.

```bash
ironheights update           # check now and print any update commands (changes nothing)
ironheights update --check   # same; kept for compatibility
ironheights update --disable # turn automatic checks off (--enable to turn them back on)
```

Automatic checks are off when `IRONHEIGHTS_NO_UPDATE=1` is set, when `CI` is set, or after `ironheights update --disable` (writes `{"autoUpdate": false}` to `~/.ironheights/update-config.json`).

## Privacy

Scans stay on the machine. There is no telemetry. The 6-hourly version check reads two version numbers (registry.npmjs.org and clawhub.ai) and sends nothing about your skills; turn it off with `IRONHEIGHTS_NO_UPDATE=1` or `ironheights update --disable`. `fetch`, `safe-install`, `advisories update`, and `--online` open a connection, and each one prints the URLs first. `scan --llm` and `review` are the other network path. They are off unless you pass them, and a normal `scan` does not call the network. The scanner reads files up to the configured size and does not extract archives. Set `IRONHEIGHTS_HOME` to put the baseline, the advisory cache, and the quarantine directory somewhere else.

## Use in CI

After a clean scan in an interactive terminal, `scan` prints one line to stderr suggesting a star on ClawHub. It is never printed when `CI` is set, when output is not a terminal, with `--quiet`, `--json`, or `--format html`, or when `IRONHEIGHTS_NO_STAR_HINT=1` is set. It is a printed line only; nothing is sent anywhere.

The repository root `action.yml` is a composite action. After a release tag, call it as `Frank-Masciopinto/ironheights@v0.3.0` (pin the tag you trust). It runs `npx ironheights@<version> scan` and does not read secrets. Exit codes match the scanner, including `3` when a file or a `.git` / `node_modules` directory was skipped. See [docs/ci.md](docs/ci.md) for the pre-commit hook and a SARIF upload example.

```yaml
name: ironheights
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Frank-Masciopinto/ironheights@v0.3.0
        with:
          version: '0.3.0'
          path: skills
          fail-on: high
```

This repository's [action workflow](.github/workflows/action.yml) runs that action against a benign fixture (exit 0), a malicious fixture (exit 1 or 2), and an oversized file (exit 3). It installs npm package `0.15.0`, the current latest on the registry. The action file in this commit is what the workflow executes.

## Windows

GitHub Actions runs this repository on `windows-latest` for Node.js `20.0.0` and Node.js `24`. Each Windows job runs `npm run build`, `npm test`, and `npm run test:packed`. That is the tested surface: the build, the unit and fixture tests, and the packed CLI smoke test. It is not a manual test of the OpenClaw Windows Hub app or a running Gateway service.

Scanned text is normalized from CRLF to LF. Directory junctions are treated like symlinks. Baseline keys under the home directory use `~/` with forward slashes so a baseline written on Windows still points at the same files when it is read back.

Node on Windows applies only the read-only attribute when Ironheights asks for mode `0600` or `0700`. `audit-config` does not report world-readable config permissions on Windows, and it does not run `icacls`. A baseline key file is refused for group or world read on macOS and Linux only. OpenClaw's own `openclaw security audit` is the check that understands Windows ACLs. A skills directory is refused when a path component is a symlink or a junction. An 8.3 short name is the same directory, not a symlink.

## Optional model review

`scan --llm` and `review` ask a language model for a second opinion. They are off unless you pass them. A scan without those commands is unchanged, and the review is never required.

The model is a reviewer of evidence the rules already extracted. It is not an authority. It can only add advisory notes with rule id `IH-LLM-001`. Those notes are severity `info`, they can be wrong, and they do not change the verdict or the exit code. A block stays a block. An empty model reply is not a clearance. `--fail-on` ignores `IH-LLM-001`.

```bash
ironheights scan ./path/to/skill --llm
ironheights scan ./path/to/skill --llm --dry-run
ironheights review ./path/to/skill --llm-url http://127.0.0.1:1234/v1 --llm-model local-model
```

The default server is Ollama at `http://127.0.0.1:11434` (`/api/chat`, model `llama3.2`). A loopback URL (`localhost`, `127.0.0.0/8`, or `::1`) does not need an extra flag. An OpenAI-compatible base URL works with `--llm-api openai`, and a URL that already ends in `/v1` or `/chat/completions` uses that API. Pass `--llm-model` when the default name is wrong.

Any other host needs both `--llm-consent` and `IRONHEIGHTS_LLM_API_KEY`. The key is sent as a bearer token and is not printed. Putting the key in the URL is refused. Config cannot store consent.

Before a request is sent, Ironheights prints the exact request body to stderr. `--dry-run` prints that body to stdout and does not send it, and it does not write the findings report. Skill text is untrusted data: it is wrapped in delimiters, size-capped, stripped of control characters, and scrubbed for common secret shapes. The scrub can miss a secret. Do not point a remote model at a skill that contains a live one. Absolute paths on your machine are not included. Redirects are not followed.

The model must reply with one JSON object, `{"notes":[...]}`, and nothing else. Any other output is discarded. If the server is down, times out, or returns a bad reply, the command prints why and keeps the deterministic result and exit code. `--llm-api` must be `ollama` or `openai`; a different value is a usage error.

Details and the request limits are in [docs/llm.md](docs/llm.md).

## Benchmark

See [docs/benchmark.md](docs/benchmark.md). The corpus in this repository is synthetic. Keep real samples on an isolated machine, on a read-only mount, and do not run them.

## Releases

npm releases are published with provenance. The tag workflow also writes `SHA256SUMS` for the package tarball and attaches it to the GitHub release. See [docs/release-verification.md](docs/release-verification.md).

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Use a private GitHub security advisory.

## License

Apache-2.0. See [LICENSE](LICENSE).
