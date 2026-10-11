# Running Ironheights next to other security tools

Many OpenClaw setups already have other security tools: a ClawHub vetting skill, a runtime guard plugin, a scanner CLI such as Cisco's `skill-scanner`, a secret scanner in a pre-commit hook. Ironheights should run beside them without double-blocking, fighting over files, or quietly trusting them.

`ironheights coexist` (alias `ironheights doctor coexist`) answers two questions, read-only and offline:

1. Which other security tools does this machine appear to have?
2. Is there anything in how they overlap with Ironheights that you should fix?

Detection is heuristic. A tool we do not list, or one that was renamed, is not found. A tool we find may be installed but broken, disabled in a way we cannot see, or malicious under a familiar name. Absence of a finding is not proof that two tools are compatible.

## Design

### Options considered

| Approach                                                                          | Verdict                                                                                                                                                                                 |
| --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Probe by running other tools (`skill-scanner --version`, `openclaw plugins list`) | Rejected. It executes code we do not control, and Ironheights promises that nothing runs. Presence on `PATH` is read with a file lookup only.                                           |
| Ask OpenClaw for the live hook list over its API                                  | Rejected as the primary source. It needs a running Gateway and an API surface we do not control. Static files work with the Gateway stopped, and in CI.                                 |
| Static detection from files, with evidence per hit                                | **Chosen.** Skill folders, plugin manifests and `openclaw.json` entries, internal hook folders, state paths, `PATH`, and repo CI files. Every hit lists the file that caused it.        |
| A list of known tools in a data file, with a source URL per entry                 | **Chosen**, as the way to attach facts (hook type, state paths, hosts contacted) to a hit. See `src/coexist/registry.ts`. Only tools we read in the research files or on a public page. |
| Detect unknown hook plugins by reading their entry file for `before_tool_call`    | **Chosen**, low confidence. It finds guard plugins that are not in the list, and says so.                                                                                               |
| Auto-allowlist or lower the severity of anything that looks like a known scanner  | Rejected. See "False trust" below.                                                                                                                                                      |
| Change the other tool's config, or ours, to fix a conflict                        | Rejected. `coexist` never writes. It prints the exact change and why.                                                                                                                   |

### Where detection looks

| Source          | What is read                                                                                                                                                    | Confidence                          |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| OpenClaw config | `plugins.entries.<id>` (`enabled`, `config.mode`), `plugins.allow`, `plugins.deny`, `plugins.load.paths`, `hooks.internal.entries`, `mcp.servers`               | high                                |
| Plugin folders  | `<state>/extensions/*/openclaw.plugin.json` and `package.json`; the entry file named in `package.json` `openclaw.extensions` is searched for `before_tool_call` | high (manifest id), low (code hint) |
| Skill folders   | Folder names and the `name:` line of `SKILL.md` in every skill directory Ironheights already knows about                                                        | medium                              |
| Internal hooks  | `<state>/hooks/*/HOOK.md` and `<workspace>/hooks/*/HOOK.md`                                                                                                     | medium                              |
| State paths     | Known state files such as `~/.agentguard/` and `<state>/guard-scanner/`                                                                                         | low                                 |
| `PATH`          | A file named like a known scanner CLI. Nothing is run.                                                                                                          | medium                              |
| Repo files      | `.pre-commit-config.yaml`, `.github/workflows/*.yml`, `.git/hooks/pre-commit` in the folder you pass with `--repo` (default: the current directory)             | medium                              |

Every read is bounded in size and count. A folder name or a `name:` line can be copied by anyone, so name-based hits are medium at best.

### Conflict classes and what we check

Each check has an id, a severity, and a concrete fix. None of them changes a file.

| Id            | Class                             | What triggers it                                                                                                                                                                                                                    | Severity                                                                       |
| ------------- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `IH-COEX-001` | Two tool-call guards              | The Ironheights guard plugin is enabled and another enabled plugin registers `before_tool_call`. OpenClaw treats `block: true` as terminal, so whichever guard has the higher priority decides, and the other never sees that call. | medium if both can block, low if only Ironheights does, info if neither blocks |
| `IH-COEX-002` | Ironheights blocks the other tool | The guard is in `enforce` mode and a detected tool needs something the guard blocks: a cloud host that is not on the allowlist (`IH-GUARD-NET`), or writes to the skills folder or agent identity files (`IH-GUARD-WRITE`).         | medium in enforce, info in monitor                                             |
| `IH-COEX-003` | Two owners of the same files      | A tool that restores or removes files (`soul-guardian`, `skillvet` safe-install, `skill-guard`) is present and an Ironheights baseline exists, or the Ironheights guard watches the same agent files.                               | medium with a baseline, info without                                           |
| `IH-COEX-004` | Config rewriting                  | A tool that edits OpenClaw config or file permissions (`secureclaw` hardening, `security-audit --fix`) is present. Ironheights itself never writes `openclaw.json`.                                                                 | low                                                                            |
| `IH-COEX-005` | Shared state paths                | `IRONHEIGHTS_HOME`, the guard policy path, or the guard log path is inside, or contains, a folder that another tool uses for state.                                                                                                 | medium                                                                         |
| `IH-COEX-006` | Double network use                | Two or more detected tools contact ClawHub or a vendor cloud. A tool that uploads skill content is named.                                                                                                                           | info                                                                           |
| `IH-COEX-007` | Scheduled scans                   | A detected tool runs on a schedule. Add `ironheights scan --all` to cron at a different minute.                                                                                                                                     | info                                                                           |
| `IH-COEX-008` | Instruction overlap               | Two or more instruction-only scanner skills, or one whose text tells the agent to scan every install and allow no exceptions. They compete for the agent's attention and can disagree.                                              | low                                                                            |
| `IH-COEX-009` | Traffic-intercepting proxy        | A loopback `HTTP_PROXY` or `HTTPS_PROXY`, or the ClawSec Monitor proxy. Ironheights network commands use Node's built-in `fetch`, which does not read those variables unless `NODE_USE_ENV_PROXY` is set.                           | info                                                                           |
| `IH-COEX-010` | False trust                       | Your `ironheights.config.json` ignores, suppresses, or allowlists a path that contains the name of a detected security tool.                                                                                                        | medium                                                                         |
| `IH-COEX-011` | Plugin allowlist                  | `plugins.allow` is set and does not list `ironheights-guard`, or `plugins.deny` lists it, so a guard you set up will not load.                                                                                                      | low                                                                            |

### False trust: no allowlist by name

A security tool's own files look like an attack. `skill-vetter` quotes injection strings, `clawdefender` lists credential paths, `skill-scanner` ships rule files. Ironheights flags them. That is a false positive for the real tool, and a perfect disguise for a fake one.

So `scan` does this, and only this:

- If a scanned skill's folder name or `SKILL.md` `name:` equals a listed tool, the report gets a `knownSecurityTool` note that says **name match only, not verified**.
- Findings of the injection and credential categories that sit in Markdown files get `confidence` lowered one step (high to medium, medium to low) and a `note`. Findings in scripts, config, binaries, network, obfuscation, persistence and exec rules are not touched.
- Severity, score, grade, verdict and exit code do not change. Nothing is suppressed and nothing is allowlisted.
- `coexist` reports `IH-COEX-010` when your own config exempts such a name.

If you trust a specific copy, pin it the normal way: scan it, read the findings, then `baseline create` so that later changes show up, or add a `suppressions` entry with a reason for that file and line.

### Making the guard safe to run beside another guard

- It only ever returns `{ block, blockReason }`. It never returns `params` (no rewrites) or `requireApproval`, so it cannot collide with another plugin's rewrites or approval prompts.
- In `monitor` mode it never returns a block. An internal error in monitor mode is logged and the call is left alone.
- Its files live under `~/.ironheights` (`guard.log.jsonl`, `guard-policy.json`, `baseline.json`). They do not share a path with any tool in the list. `IH-COEX-005` checks the case where someone points `IRONHEIGHTS_HOME` at a shared folder.
- Every block reason starts with `ironheights:`, so you can tell whose block you are looking at.
- Priority is `80` by default and can be set with the plugin config key `priority`. OpenClaw runs higher priorities first and defaults to `0`. A `block: true` result stops lower-priority handlers. That has two practical effects. A monitor-mode Ironheights logs every call that reaches it, and it sees fewer calls if another guard with a higher priority blocks first. When both guards enforce, the one with the higher priority is the one that blocks and logs.
- At startup the plugin runs the same detection once and writes one line to the OpenClaw log, for example `other security tools detected: guard-scanner (plugin, enforce)`. It writes no file and sends nothing.

Recommended setup when another guard already enforces: leave Ironheights in `monitor` (the default), keep its scanner and integrity features, and let one tool own blocking.

## Using it

```bash
ironheights coexist                  # text report
ironheights coexist --json           # JSON, schemaVersion 1
ironheights coexist --fail-on medium # exit 1 when a finding is medium or higher
ironheights doctor                   # also prints a one-line summary
```

Exit codes: `0` nothing at or above `--fail-on` (the default is to never fail on findings), `1` a finding at or above `--fail-on`, `64` usage error. The command reads files only, calls no network, and writes nothing. Pass `--openclaw-config <file>` for a config in another place and `--repo <dir>` for the project whose CI files should be read. The JSON shape is in [coexistence.schema.json](coexistence.schema.json).

## The list of known tools

`src/coexist/registry.ts` holds one entry per tool, with the URL we read it from and the date. It currently covers tools found in the ClawHub research (the top security skills by installs, plus Prompt Security's ClawSec suite, GoPlus AgentGuard, guard-scanner and MoltGuard) and a few public scanner CLIs: Cisco `skill-scanner`, Snyk `snyk-agent-scan`, `gitleaks` and `ggshield`. We list a tool only after reading its listing, its repository, or its package file. Anything we could not read is not in the list. If you want a tool added, open an issue with a link to its public page.

## Limits

- Detection reads files. It cannot tell whether a plugin is loaded in the running Gateway, whether a hook is wired up correctly, or whether a tool works.
- The hook-priority and blocking facts come from the OpenClaw plugin docs checked on 11 October 2026. A later OpenClaw release can change them.
- Skill and plugin names can be copied by anyone. A hit means "something with this name is here", not "this is the real tool".
- We cannot see another tool's mode unless it is in `openclaw.json`. A guard with no `mode` set gets the default from its manifest when we know it (for example `guard-scanner` defaults to `enforce`), and `unknown` otherwise.
- Cron jobs, systemd timers and processes are not read, so scheduled overlap is only reported for tools known to schedule.
- Absence of findings is not proof that tools will not interfere.
