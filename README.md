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

Exit codes are `0` for no findings, `1` for review, `2` for block, `64` for a usage or config error, and `70` for an internal error. `--fail-on low|medium|high|critical` returns `0` when every finding is below that severity.

## Commands

```text
ironheights scan <path> [--all] [--json] [--sarif <file>] [--md <file>] [--fail-on <severity>] [--config <file>] [--no-color] [--quiet]
ironheights baseline create|update|show
ironheights verify
ironheights quarantine <skill>
ironheights quarantine restore <id>
ironheights rules list
ironheights rules show <id>
ironheights doctor
ironheights bench <corpusDir> [--external <file.json>]
ironheights --online
```

`--online` prints `not implemented in MVP` and does nothing else. `--all` scans the skill directories from config, or the OpenClaw locations below when config does not set `skillDirs`.

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
  "thresholds": { "block": 80, "review": 15 }
}
```

An allowlist entry matches that host and its subdomains. The built-in list includes `example.com`, `example.org`, `example.net`, `localhost`, the loopback addresses `127.0.0.1` and `::1`, GitHub, npm, PyPI, and `openclaw.ai`.

## JSON output

`--json` prints a document with `schemaVersion` `1`:

```json
{
  "schemaVersion": 1,
  "tool": { "name": "ironheights", "version": "0.1.3" },
  "scannedAt": "2026-10-09T00:00:00.000Z",
  "verdict": "no-findings",
  "skills": []
}
```

Each skill has `skillName`, `root`, `filesScanned`, `filesSkipped`, `findings`, `score`, and `verdict`. A finding has `ruleId`, `severity`, `confidence`, `file`, optional `line` and `column`, `evidence`, `message`, and `remediation`. `--sarif` writes SARIF 2.1.0.

Scoring is critical 100, high 40, medium 15, low 5, info 0. The verdict is `block` when any finding is critical or the score is at least 80. It is `review` when any finding is high or medium, or the score is at least 15. Otherwise it is `no-findings`.

## Rules

The full list is generated in [docs/rules.md](docs/rules.md). P0 rules cover remote shells, prerequisite installs, undeclared hosts, credential paths, hard-coded secrets, instruction overrides, hidden text, bundled executables, and persistence. P1 rules cover dynamic execution, exfiltration shape, secrets in chat, weakened approvals, obfuscation, privilege bypass, filesystem tricks, and skill metadata. Integrity rules `IH-INT-001` through `IH-INT-004` come from `verify`, not from a content scan.

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

## Integrity

`baseline create` writes `~/.ironheights/baseline.json` with mode `0600`. The file stores a sha256, size, and mode for each path, plus a `treeHash` of the sorted content hashes. `verify` reports added, modified, removed, and mode-changed files.

An attacker who can write your home directory can edit the baseline. Signing it, or keeping a copy off the machine, is future work. See [docs/ideas.md](docs/ideas.md).

`quarantine <skill>` moves a skill to `~/.ironheights/quarantine/<timestamp>-<name>`. That directory is mode `0700`. `quarantine restore <id>` moves it back. Ironheights does not delete a skill on its own.

## The advisory skill

`skill/ironheights/SKILL.md` tells an OpenClaw agent to run `ironheights scan <path> --json`, summarize the result, and stop on a `block` verdict until you confirm. The skill asks for no network access and no secrets.

This skill is advisory. It runs inside the agent, and a hostile skill can try to bypass it. The CLI you run yourself, or a process outside the agent, is the trusted path.

## What Ironheights cannot detect

- Novel attacks and attacks that are heavily obfuscated in a way the current rules do not describe.
- Behavior that only appears at runtime, after a script is executed.
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
