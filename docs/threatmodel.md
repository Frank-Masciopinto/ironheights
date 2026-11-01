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

## Widening in the same change (0.23.0)

By default `diff` lists model widenings as info for a reviewer (`defaults.modelChanges: note`).
Set `modelChanges: fail` in the model on your main branch, or pass `--fail-on-widen`, and `diff`
also checks the head skills against the **base** model. A capability (host, path, env var, token,
shell, MCP server) that passes only because the same PR widened the model becomes a high
`widened-in-same-change` violation whose detail is the exact delta. Accepting new scope then has
to land as its own model-only change, reviewed on its own, before the code that uses it. Changes
inside the agreed scope are not affected. The setting is read from the base model, so a PR cannot
switch it off; `modelChanges fail -> note` is reported as a widening.

Every `check` and `diff` result carries `covered` (`base` and `head` commit shas, `dirty` when
there are uncommitted changes); the PR comment says `Covers abc..def. Not checked since def.`
`notChecked` lists model skill folders that do not exist. Run the check on every pull request,
without a `paths:` filter: a lockfile bump or a CI config change can change reach without touching
a skill folder.

Suggested on Moltbook by pipnyc, nyna, kobolsix, ariesai, sheeshscout, fromthebot, narin_lab and
templeofmolt.

## Writes, triggers, observers, egress branches and review (0.24.0)

All of these are opt-in per skill (add the field) or per model (`defaults`). Existing models keep their exit codes.

```yaml
defaults:
  writes: require # every skill declares writes (writes: none is an explicit answer)
  persistence: reason # startup files and other tools' config need a reason; deny fails on declaration alone
  triggers: require # heartbeat, schedule, hook and on-startup triggers must be declared
  observers: require # reach that leaves the process needs an independent observer (warn lists it)
  egress: deny # env vars that choose a destination need an allowed set
  undeclaredFolders: fail # skill folders outside skillDirs with authority are high
  modelChanges: review # widenings need a reasons row and a non-author approver
skills:
  sync:
    path: skills/sync
    network: [api.example.com]
    tokens: [API_TOKEN]
    writes:
      - cache/
      - path: ~/.bashrc
        reason: adds the CLI to PATH
        writer: installer
    egress:
      - host: api.example.com
        secret: API_TOKEN
        branch: default when API_BASE is unset
    destinationEnv:
      API_BASE: [api.example.com]
    triggers:
      - kind: heartbeat
        owner: '@oncall-pager'
        escalation: page the owner
        lastExercised: 2026-10-20
    observers:
      - name: egress-proxy-log
        kind: external
        reaches: [network, secrets]
        identity: separate
        store: /var/log/egress/
        writeOnce: true
        heartbeat: 1h
    reasons:
      network:api.example.com:
        reason: sync endpoint
        package: example-sdk
        approvedBy: bob
        approvedAtVersion: 1.2.0
        expires: 2027-01-31
        evidence: evidence/sandbox-egress.json
        reviewerNote: api.example.com is the vendor sync API
```

| Check                                                                                                                                                                                                                            | Violation                                                                              | Severity                                                           |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Write in the files (file APIs, `>`/`>>`, `tee`, and tools writing on the skill's behalf: `pip install`, `npm i -g`, `git config --global`, `crontab`, `launchctl`, `systemctl enable`, service worker registration) not declared | `write-not-declared` (also listed in `proposedWrites` with why, for a human to accept) | high                                                               |
| `writes: require` and no `writes` field                                                                                                                                                                                          | `writes-missing`                                                                       | high                                                               |
| Startup file, another tool's config, `package.json` or `.env` without a reason (or at all with `persistence: deny`)                                                                                                              | `persistence-write` (never proposed as accepted)                                       | high                                                               |
| Declared write never named in the files                                                                                                                                                                                          | `write-declared-unused` (over-wide)                                                    | info                                                               |
| Detected trigger not declared                                                                                                                                                                                                    | `trigger-undeclared`                                                                   | high                                                               |
| Scheduled trigger with no owner/audience, or a channel as owner                                                                                                                                                                  | `trigger-no-owner`                                                                     | high / medium                                                      |
| No escalation path, never exercised, or over 90 days ago                                                                                                                                                                         | `escalation-unexercised`                                                               | medium                                                             |
| Network, secret or write reach with no observer / only a self-witness (in-skill, same identity, or a store the skill can write that is not write-once)                                                                           | `observer-missing` / `observer-self-witness`                                           | high (`require`), medium (`warn`); local read-only reach is medium |
| Observer with no declared heartbeat                                                                                                                                                                                              | `observer-no-heartbeat`                                                                | medium                                                             |
| `process.env.X \|\| 'https://host'` and similar defaults                                                                                                                                                                         | `fallback-host` names the branch; replaces `host-not-allowed` for that host            | high when not allowed                                              |
| A host named near a secret with no `egress` row carrying it                                                                                                                                                                      | `egress-secret-not-declared` / `egress-branch-undeclared`                              | high / medium                                                      |
| Env var that chooses a destination (`*_URL`, `*_HOST`, `*_ENDPOINT`, `*_WEBHOOK`, `*_BUCKET`) with no allowed set, or a default outside it                                                                                       | `destination-env-unbounded`                                                            | medium (high with `egress: deny`)                                  |
| SKILL.md folder outside `skillDirs`                                                                                                                                                                                              | `undeclared-folder`                                                                    | info; high with authority and `undeclaredFolders: fail`            |
| Reason row past `expires`                                                                                                                                                                                                        | `reason-expired`                                                                       | medium                                                             |

`diff` also:

- counts changed files against the declared scope (`scope.changedFiles`, `inScope`, `outsideScope`) and flags a changed file outside every skill dir that names hosts, env or processes (`changed-outside-scope`), so outside is never zero because the folder was not searched;
- emits `trigger-changed` (`from on-request to heartbeat`; the prior review is void), high with `triggers: require` or `modelChanges` other than `note`;
- reopens a reason row (`reason-reopened`, prefilled with the old row) when its `package` updates, is replaced by a new name (fork) or changes publisher/source in `package-lock.json`, and lists capability-free lockfile churn as info `lockfile-churn`;
- with `--review` or `modelChanges: review` (read from the base model): a widening without a `reasons` row is `widening-unjustified`; a capability widening or any change to the model file without an approver other than the author is `widening-self-approved` / `model-file-self-approved` (listed under `selfApproved`); an agent-authored change (`--author-kind agent`) needs a non-bot approver; `evidence` that does not exist at base is `widening-evidence-same-change`; a `reviewerNote` that does not name the value is `widening-review-vague`; unclassifiable model changes go to the approval tier and are counted in `extractorHealth`. Narrowing passes on comparison alone. Flags: `--author`, `--author-kind`, `--approvers a,b`. Action input `threatmodel-review` reads the PR author and approving reviews.

Static text checks: they report what the files name, not what runs. Pair with a sandboxed run for observed egress.

Suggested on Moltbook by novastellar, KitSinclair, templeofmolt, ackedagents, lobsterroyale, austingrok, theepikwebdevsslave, evil_robot_jas, athena-xenessa, vina, dapper, jakes-muse, nyna, clawhedgehog, LazyBearAI, ferrous_moth, ecdys, lilt, hermes_on_foot, fromthebot, spiritofthefleet, gorbswarm, juan_carlos, pennyworthatyourservice, sophiaalways, entitylovestudio, cerebrochain, swordfish-ming, KANA-KANA and kobolsix (0.23.0 deferred: named non-author acceptance and expiring reasons).

## Commands

```bash
# 1. Generate a first model from what is installed today, then review and commit it.
npx ironheights@0.23.0 threatmodel init
#    --skills <dir> and --mcp <file> override the auto-detected folders; --force overwrites.

# 2. Check the working tree against the model.
npx ironheights@0.23.0 threatmodel check --markdown tm.md --sarif tm.sarif

# 3. In a PR: report only what this change adds, plus any widening of the model itself.
npx ironheights@0.23.0 threatmodel diff --base origin/main --json

# Include drift since `ironheights drift approve`:
npx ironheights@0.23.0 threatmodel check --ledger ~/.ironheights/approvals.json
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
      - uses: Frank-Masciopinto/ironheights@v0.23.0
        with:
          version: '0.23.0'
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
