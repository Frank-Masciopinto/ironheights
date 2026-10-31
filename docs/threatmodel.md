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
    dataBoundaries: [no-user-data-egress] # free-form labels for reviewers
mcpServers:
  github:
    command: npx
    args: [-y, '@modelcontextprotocol/server-github']
    env: [GITHUB_PERSONAL_ACCESS_TOKEN]
```

`dataBoundaries`, `purpose` and `owner` are documentation for reviewers; they are not enforced.
Everything else is.

## What is checked

For each skill folder, Ironheights reads every text file (no execution) and profiles:

| Capability         | How it is detected                                                                                                      | Violation             | Severity                    |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------- | --------------------- | --------------------------- |
| Network            | URL hosts (`https://`, `wss://`, `ftp://`)                                                                              | `host-not-allowed`    | high                        |
| Filesystem         | `~/...`, `$HOME/...`, `/etc`, `/var`, `/home`, `/Users`, `/root`, `/tmp`, `/proc` ... and known credential paths        | `path-not-allowed`    | high                        |
| Secrets            | env names containing KEY, TOKEN, SECRET, PASSWORD, PRIVATE, AUTH, CREDENTIAL, COOKIE, SESSION                           | `token-not-allowed`   | high                        |
| Environment        | `process.env.X`, `os.environ["X"]`, `os.getenv`, `Deno.env.get`, `$X`, `${X}` (common names like HOME and PATH ignored) | `env-not-allowed`     | medium                      |
| Shell              | `child_process`, `execSync`, `subprocess.*`, `os.system`, `Bun.spawn`, `Deno.Command`, bash code blocks, `curl \| sh`   | `shell-not-allowed`   | high                        |
| Grade              | `ironheights scan` grade below `minGrade` (or incomplete)                                                               | `grade-below-minimum` | high                        |
| Unknown skill      | skill folder not listed                                                                                                 | `unknown-skill`       | high (deny) / medium (warn) |
| Missing skill      | listed but not present                                                                                                  | `skill-missing`       | info                        |
| MCP server         | server name not listed                                                                                                  | `unknown-mcp-server`  | high (deny) / medium (warn) |
| MCP command        | `command`, `args` or `url` differ from the model                                                                        | `mcp-command-changed` | high                        |
| MCP env            | env key not listed                                                                                                      | `mcp-env-not-allowed` | high                        |
| Drift (`--ledger`) | anything `ironheights drift check` reports                                                                              | `drift`               | as drift                    |

Exit codes: `0` inside the model, `1` review (medium only), `2` out-of-model change, `64` usage.

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
