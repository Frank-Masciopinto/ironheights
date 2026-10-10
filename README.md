# Ironheights

Ironheights is a local-first scanner and integrity monitor for [OpenClaw](https://docs.openclaw.ai) skills. It reads skill files as data, looks for risky patterns with fixed rules, and compares skill and agent files with a baseline you save on the same machine.

It does not call the network, does not send telemetry, and does not run the files it scans.

## Install

Ironheights requires Node.js 20 or newer.

OpenClaw 2026.9.3 requires Node.js `>=24.16.0 <25 || >=26.1.0`. `ironheights doctor` prints whether the current runtime is inside that range.

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

| Exit | Meaning                                                                                        |
| ---- | ---------------------------------------------------------------------------------------------- |
| 0    | No findings                                                                                    |
| 1    | Review                                                                                         |
| 2    | Block                                                                                          |
| 3    | Incomplete. A file was skipped, and the files that were scanned did not reach review or block. |
| 64   | Usage or config error                                                                          |
| 70   | Internal error                                                                                 |

`--fail-on low|medium|high|critical` returns `0` when every finding is below that severity and no file was skipped. A skipped file still returns `3` unless you pass `--allow-skipped`. That flag keeps the skipped-file warning and returns the finding verdict (`0`, `1`, or `2`) instead.

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
ironheights scan <path> [--all] [--json] [--sarif <file>] [--md <file>] [--html <file>] [--format text|json|html] [--since-baseline [file]] [--stdin] [--text <text>] [--fail-on <severity>] [--config <file>] [--allow-skipped] [--no-color] [--quiet]
ironheights baseline create|update|show
ironheights verify
ironheights quarantine <skill>
ironheights quarantine restore <id>
ironheights rules list
ironheights rules show <id>
ironheights doctor
ironheights bench <corpusDir> [--external <file.json>]
ironheights guard status|log
ironheights guard policy check [--call <json>]
ironheights --online
```

`--online` prints `not implemented in MVP` and does nothing else. `--all` scans the skill directories from config, or the OpenClaw locations below when config does not set `skillDirs`.

## Grade

Every scan prints a grade on the line before "Absence of findings is not proof of safety." The number is a trust score: 100 minus the risk score, and never below 0. A is 90–100, B is 80–89, C is 70–79, D is 60–69, and F is 0–59. The grade uses the worst skill after suppressions. Findings omitted by `--since-baseline` still count toward the grade.

A skipped file makes the grade `incomplete` and hides the number, including when you pass `--allow-skipped`. The exit code can still be 0 in that case. The verdict line is unchanged.

```text
Verdict: review
Grade: D (60/100)
Absence of findings is not proof of safety.
ironheights 0.1.5 | demo | grade D (60/100) | verdict review | 1 finding
Badge: [ironheights 0.1.5: grade D (60/100), verdict review](https://github.com/Frank-Masciopinto/ironheights) — Absence of findings is not proof of safety.
```

The badge line is text you can paste into a README. It does not load an image from a badge service.

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
  "ignoreGlobs": ["**/.git/**"],
  "ruleOverrides": { "IH-NET-001": { "enabled": true, "severity": "low" } },
  "failOn": "high",
  "limits": { "maxFileBytes": 1048576, "maxFiles": 2000, "maxDepth": 10 },
  "thresholds": { "block": 80, "review": 15 },
  "suppressions": [
    { "ruleId": "IH-NET-001", "path": "docs/**", "reason": "documented example hosts" }
  ],
  "suppressCritical": false,
  "suppressIntegrity": false
}
```

An allowlist entry matches that host and its subdomains. The built-in list includes `example.com`, `example.org`, `example.net`, `localhost`, the loopback addresses `127.0.0.1` and `::1`, GitHub, npm, PyPI, and `openclaw.ai`.

## JSON output

`--json` prints a document with `schemaVersion` `1`. New fields below are additive. Consumers that ignore unknown keys keep working, so `schemaVersion` stays `1`.

```json
{
  "schemaVersion": 1,
  "tool": { "name": "ironheights", "version": "0.1.5" },
  "scannedAt": "2026-10-09T00:00:00.000Z",
  "verdict": "no-findings",
  "skippedFileCount": 0,
  "grade": {
    "letter": "A",
    "score": 100,
    "disclaimer": "Absence of findings is not proof of safety."
  },
  "scanMode": "directory",
  "summary": "ironheights 0.1.5 | no skills | grade A (100/100) | verdict no-findings | 0 findings",
  "badge": "[ironheights 0.1.5: grade A (100/100), verdict no-findings](https://github.com/Frank-Masciopinto/ironheights) — Absence of findings is not proof of safety.",
  "skills": []
}
```

`grade.score` is omitted when `grade.letter` is `incomplete`. A text scan sets `scanMode` to `text` and adds `scanLimit`. `--since-baseline` adds `sinceBaseline` on the document and on each skill, including `omitted`. Each skill also has `suppressed`, `suppressedCount`, `suppressionRefused`, and `suppressionRefusedCount`.

Each skill has `skillName`, `root`, `filesScanned`, `filesSkipped`, `skippedFileCount`, `findings`, `score`, and `verdict`. `skippedFileCount` is the number of files the scan did not read. `filesSkipped` lists each path and the reason. A finding has `ruleId`, `severity`, `confidence`, `file`, optional `line` and `column`, `evidence`, `message`, `remediation`, and `references` (`owaspLlm`, `owaspAgentic`, `mitreAtlas`). With `--since-baseline`, `score` and `verdict` describe the new findings. The grade still describes the full scan. `--sarif` writes SARIF 2.1.0. The run `properties` include `skippedFileCount`, `gradeLetter`, `disclaimer`, and `gradeScore` when the scan is complete. Rule `properties` and `tags` include the same references. `tool.driver.informationUri` is `https://github.com/Frank-Masciopinto/ironheights`.

Scoring is critical 100, high 40, medium 15, low 5, info 0. The verdict is `block` when any finding is critical or the score is at least 80. It is `review` when any finding is high or medium, or the score is at least 15. It is `incomplete` when files were skipped and the score would otherwise be `no-findings`. Otherwise it is `no-findings`.

## Rules

The full list is generated in [docs/rules.md](docs/rules.md), including OWASP LLM Top 10 2025, OWASP Agentic Top 10 2026, and MITRE ATLAS ids. `none` means no defensible mapping was recorded. P0 rules cover remote shells, prerequisite installs, undeclared hosts, credential paths, hard-coded secrets, instruction overrides, hidden text, bundled executables, persistence, and MCP launch and secret checks. P1 rules cover dynamic execution, exfiltration shape, secrets in chat, weakened approvals, obfuscation, privilege bypass, filesystem tricks, skill metadata, and broad MCP filesystem roots. Integrity rules `IH-INT-001` through `IH-INT-004` come from `verify`, not from a content scan.

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

The default workspace is `~/.openclaw/workspace`. Config is `$OPENCLAW_CONFIG_PATH` or `~/.openclaw/openclaw.json`. State moves when `OPENCLAW_STATE_DIR` is set.

Watched agent files default to `AGENTS.md`, `SOUL.md`, `IDENTITY.md`, `USER.md`, `TOOLS.md`, `BOOTSTRAP.md`, `MEMORY.md`, the `memory/` directory, `openclaw.json`, `credentials/`, and `.env` under the OpenClaw state directory. Change the list with `agentFiles`.

Bundled skills are the `skills/` directory in the OpenClaw package. Ironheights finds that package from `OPENCLAW_BUNDLED_SKILLS_DIR`, from the `~/.openclaw/bin/openclaw` wrapper, from `~/.openclaw/tools/node-v*/lib/node_modules/openclaw`, or from the usual global `node_modules/openclaw` locations. Custodian skills are the sibling `custodian-skills/` directory. Plugin skills are the directories linked from `~/.openclaw/plugin-skills`. `doctor` says when the bundled directory was not found.

`SKILL.md` needs YAML frontmatter with `name` and `description`. Optional fields include `metadata.openclaw`, `homepage`, `user-invocable`, `disable-model-invocation`, and the `command-dispatch` keys.

`metadata.ironheights.allowDomains` is a list of hosts that this skill is allowed to contact. `IH-NET-001` skips those hosts and their subdomains for that skill only. Another skill that calls the same host still reports. The bundled OpenClaw skills do not declare their hosts, so `scan --all` on a stock install still reports their API hosts.

A download, install, or fetch instruction is a contact, and so is a paste site or a file-drop host. A schema link, or an official API host mentioned in prose, is not.

## Integrity

`baseline create` writes `~/.ironheights/baseline.json` with mode `0600`. The file stores a sha256, size, and mode for each path, plus a `treeHash` of the sorted content hashes. `verify` reports added, modified, removed, and mode-changed files.

An attacker who can write your home directory can edit the baseline. Signing it, or keeping a copy off the machine, is future work. See [docs/ideas.md](docs/ideas.md).

`quarantine <skill>` moves a skill to `~/.ironheights/quarantine/<timestamp>-<name>`. That directory is mode `0700`. `quarantine restore <id>` moves it back. Ironheights does not delete a skill on its own.

## Runtime guard

`ironheights guard` evaluates a tool call against a local policy. The OpenClaw plugin in this package registers `before_tool_call` and can block that call when the policy mode is `enforce`. The default mode is `monitor`: it appends a redacted line to `~/.ironheights/guard.log.jsonl` and does not block.

The hook runs inside the OpenClaw process. It is not a sandbox and not a process outside the agent. A skill that can edit OpenClaw config or the policy file can turn it off. Details, the threat model, and the policy file are in [docs/guard.md](docs/guard.md).

```bash
ironheights guard status
ironheights guard policy check --call '{"toolName":"read","params":{"path":"~/.ssh/id_rsa"}}'
```

## The advisory skill

`skill/ironheights/SKILL.md` tells an OpenClaw agent to run `ironheights scan <path> --json`, summarize the result, and stop on a `block` verdict until you confirm. The skill asks for no network access and no secrets.

This skill is advisory. It runs inside the agent, and a hostile skill can try to bypass it. The CLI you run yourself, or a process outside the agent, is the trusted path.

## What Ironheights cannot detect

- Novel attacks and attacks that are heavily obfuscated in a way the current rules do not describe.
- Behavior that only appears at runtime and never shows up as one of the tool calls the guard knows how to read. The guard is described in [docs/guard.md](docs/guard.md). It does not see a process that is already running.
- A host that is already compromised, including a baseline an attacker can rewrite.
- Social engineering that never lands in a file the scanner reads.

No findings means the rules did not match. It does not mean the skill is safe.

## Privacy

Scans stay on the machine. There is no telemetry and no default network call. The scanner reads files up to the configured size and does not extract archives. Set `IRONHEIGHTS_HOME` to put the baseline and quarantine directory somewhere else.

## Benchmark

See [docs/benchmark.md](docs/benchmark.md). The corpus in this repository is synthetic. Keep real samples on an isolated machine, on a read-only mount, and do not run them.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Use a private GitHub security advisory.

## License

Apache-2.0. See [LICENSE](LICENSE).
