# Agent threat model as code (`ironheights threatmodel`)

Ironheights protects any AI bot that installs it. `ironheights threatmodel` adds a reviewed,
versioned threat model for the skills and MCP servers your agent trusts, and checks every pull
request against it. A PR that gives a skill a new network host, a new secret, shell access, a
new filesystem path, or a new MCP server fails until a reviewer widens the model in the same PR.

It runs locally. No network, no telemetry, no secrets read: environment variables are matched by
name only.

## The file: `ironheights.threatmodel.yml`

```yaml
# Schema: https://www.ironheights.dev/api/v1/threatmodel.schema.json
$schema: https://www.ironheights.dev/api/v1/threatmodel.schema.json
version: 1
skillDirs: [skills, .claude/skills] # where skills live (each folder with a SKILL.md)
mcpConfigs: [.mcp.json, .cursor/mcp.json]
defaults:
  unknownSkill: deny # deny (high, exit 2) or warn (medium, exit 1)
  unknownMcpServer: deny
  minGrade: B # optional default for every skill
  uncovered: report # report (default) or fail. fail exits 2 on a capability the model never names
  remoteInstructions: report # report (info), warn (medium) or deny (high). See below.
skills:
  weather:
    path: skills/weather
    purpose: Read-only forecasts.
    owner: '@platform-team'
    network: [api.weather.gov, '*.noaa.gov'] # exact host or *.suffix
    filesystem: ['~/.config/weather/**'] # globs; ~ and $HOME are the same
    env: [WEATHER_CONTACT] # non-secret variable names
    tokens: [WEATHER_API_KEY] # secret-shaped names (KEY, TOKEN, SECRET, ...)
    shell: false # child processes, subprocess, bash blocks
    minGrade: A # Ironheights scan grade A-F
    dataBoundaries: [no-user-data-egress] # free-form labels for reviewers; not enforced
    # remoteInstructions: true # allow the built-in remote-instructions claim for this skill
mcpServers:
  github:
    command: npx
    args: [-y, '@modelcontextprotocol/server-github']
    env: [GITHUB_PERSONAL_ACCESS_TOKEN]
```

`dataBoundaries`, `purpose` and `owner` are documentation for reviewers. They show up in the
claims list as `unenforced` and cannot fail the check. Everything else is a claim that can pass,
fail, or come back `untested`.

## What is checked

For each skill folder, Ironheights reads every text file (no execution) and profiles:

| Capability           | How it is detected                                                                                                      | Violation              | Severity                    |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------- | ---------------------- | --------------------------- |
| Network              | URL hosts (`https://`, `wss://`, `ftp://`)                                                                              | `host-not-allowed`     | high                        |
| Filesystem           | `~/...`, `$HOME/...`, `/etc`, `/var`, `/home`, `/Users`, `/root`, `/tmp`, `/proc` ... and known credential paths        | `path-not-allowed`     | high                        |
| Secrets              | env names containing KEY, TOKEN, SECRET, PASSWORD, PRIVATE, AUTH, CREDENTIAL, COOKIE, SESSION                           | `token-not-allowed`    | high                        |
| Environment          | `process.env.X`, `os.environ["X"]`, `os.getenv`, `Deno.env.get`, `$X`, `${X}` (common names like HOME and PATH ignored) | `env-not-allowed`      | medium                      |
| Shell                | `child_process`, `execSync`, `subprocess.*`, `os.system`, `Bun.spawn`, `Deno.Command`, bash code blocks, `curl \| sh`   | `shell-not-allowed`    | high                        |
| Grade                | `ironheights scan` grade below `minGrade` (or incomplete)                                                               | `grade-below-minimum`  | high                        |
| Unknown skill        | skill folder not listed                                                                                                 | `unknown-skill`        | high (deny) / medium (warn) |
| Missing skill        | listed but not present                                                                                                  | `skill-missing`        | info                        |
| MCP server           | server name not listed                                                                                                  | `unknown-mcp-server`   | high (deny) / medium (warn) |
| MCP command          | `command`, `args` or `url` differ from the model                                                                        | `mcp-command-changed`  | high                        |
| MCP env              | env key not listed                                                                                                      | `mcp-env-not-allowed`  | high                        |
| Drift (`--ledger`)   | anything `ironheights drift check` reports                                                                              | `drift`                | as drift                    |
| Remote instructions  | scanner finding `IH-INJ-004` (fetch a URL and follow it)                                                                | `remote-instructions`  | info, medium, or high       |
| Uncovered capability | a host, token, env var, MCP server or webhook no claim names (`--fail-on-uncovered` or `defaults.uncovered: fail`)      | `uncovered-capability` | high                        |

Exit codes: `0` inside the model, `1` review (medium only), `2` out-of-model change, `64` usage.
An `untested` claim and an uncovered capability in `report` mode do not change the exit code.

## Claims

`check` and `diff` add a `claims` array. One claim is one allow-list on one skill or MCP server:
`network`, `filesystem`, `env`, `tokens`, `shell`, `minGrade`, and for an MCP server
`command/args/url`, `env` and `tools`.

| Status     | Meaning                                                                                                                                                 |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `passed`   | Every observed row is on the allow-list. `detail` is the distribution, for example `3 hosts in diff, 3 on allowlist` or `2 vars referenced, 2 allowed`. |
| `violated` | At least one row contradicts the claim.                                                                                                                 |
| `untested` | The claim matched zero rows. A skill that names no hosts, or a diff that adds none, is untested. A check that cannot fire is not a pass.                |

Each claim has `enforcement` (where it is checked: network is egress/allowlist in diff, tokens are
secret reads, filesystem is a workspace write). A free-text claim such as `dataBoundaries` or
`purpose` is `unenforced`. MCP `tools` is unenforced too: the config does not list the calls a
skill will make. Untested and unenforced claims are information. They do not change the exit code.

## Uncovered capabilities

A capability is uncovered when no claim in the model mentions it. That is different from a
violation, which contradicts a claim that does exist. `check` and `diff --base` list them as
`uncovered`: `{ target, kind, value, file?, suggestedClaim }`. `kind` is `host`, `token`, `env`,
`mcp-server` or `webhook` (a `hooks.slack.com` URL, a `discord.com/api/webhooks` URL, or any URL
whose host or path contains `webhook`). `suggestedClaim` is one YAML line, for example
`skills.foo.network: [api.example.com]`.

The text report and the `--markdown` comment have "Uncovered capabilities" and "Suggested claims"
sections. By default this is a report only. Opt in to a failure with `--fail-on-uncovered` or
`defaults.uncovered: fail`. Each uncovered value then becomes a high `uncovered-capability`
violation (exit 2), unless a violation already names that same value. The Action input
`threatmodel-fail-on-uncovered` (`false` by default) passes the flag.

## Remote instructions

A hash of `SKILL.md` pins the file on disk. It does not pin a page the file tells the agent to
fetch and follow. The built-in `remote-instructions` claim reuses scanner finding `IH-INJ-004` on
each skill. When the finding is present and the skill does not set `remoteInstructions: true`:

| `defaults.remoteInstructions` | Claim      | Violation severity | Exit code                          |
| ----------------------------- | ---------- | ------------------ | ---------------------------------- |
| `report` (default)            | `violated` | info               | unchanged                          |
| `warn`                        | `violated` | medium             | 1, unless something else is higher |
| `deny`                        | `violated` | high               | 2                                  |

`remoteInstructions: true` on that skill allows the finding. The claim is `passed`.

Detection is text-based and conservative. A skill can still build a host or variable name at run
time; pair this with `ironheights scan`, `ironheights drift` and the runtime guard. See
[limits](limits.md).

## Commands

```bash
# 1. Generate a first model from what is installed today, then review and commit it.
npx ironheights@0.21.1 threatmodel init
#    --skills <dir> and --mcp <file> override the auto-detected folders; --force overwrites.

# 2. Check the working tree against the model.
npx ironheights@0.21.1 threatmodel check --markdown tm.md --sarif tm.sarif

# 3. In a PR: report only what this change adds, plus any widening of the model itself.
npx ironheights@0.21.1 threatmodel diff --base origin/main --json

# Include drift since `ironheights drift approve`:
npx ironheights@0.21.1 threatmodel check --ledger ~/.ironheights/approvals.json
```

`diff` reads the base commit with `git archive` (nothing is checked out or executed), runs the
base skills against the **head** model, and only fails on violations that are new at head. A
widened model is listed as `model-widened` (info) so a reviewer sees, for example,
`network += exfil.example.net` or `shell: false -> true` in the PR comment.

## GitHub Action

```yaml
name: agent threat model
on: pull_request
permissions:
  contents: read
  pull-requests: write # for the summary comment
jobs:
  threatmodel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: Frank-Masciopinto/ironheights@v0.21.1
        with:
          version: '0.21.1'
          mode: both # scan + threat model; or threatmodel
          # threatmodel-file: ironheights.threatmodel.yml
          # threatmodel-ledger: .ironheights/approvals.json
          # threatmodel-fail-on-uncovered: 'true'
          # comment: 'false'
```

The Action posts one comment per PR (and updates it on each push), writes the same Markdown to the
job summary, sets `threatmodel-exit-code` and `threatmodel-violations`, and fails the job on any
out-of-model addition. A complete example repository is in
[`examples/threatmodel`](../examples/threatmodel).

## JSON Schema

`docs/threatmodel.schema.json`, published at
https://www.ironheights.dev/api/v1/threatmodel.schema.json. Add the `$schema` line (as `init`
does) or `# yaml-language-server: $schema=...` for editor completion.
