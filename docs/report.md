# Agent security posture report (`ironheights report`)

Ironheights protects any AI bot that installs it. `ironheights report` turns a repository, or a
folder that holds many repositories (an organisation checkout), into one posture report:

- **Skill inventory**: every installed skill with its worst reach, its grade (A-F) and the config hash that grade was computed against, verdict, finding count and top rules. The inventory is sorted by worst reach, then grade.
- **Threat-model coverage**: which repositories have an `ironheights.threatmodel.yml`, the share
  of all skills listed in one, and every violation (see [threatmodel.md](threatmodel.md)).
- **Drift**: with `--ledger`, which approved skills changed since `ironheights drift approve`.
- **OWASP Top 10 for LLM Applications 2025**: findings and skills per risk (LLM01-LLM10), from
  each rule's references, with links to the rule pages.
- **Trend**: with `--history <file.jsonl>`, each run appends a summary line and the report shows
  findings, blocked and review counts, coverage and drift over time.

```bash
npx ironheights@0.21.1 report .                                   # one repo, terminal summary
npx ironheights@0.21.1 report ~/src/my-org --html posture.html    # every repo in a folder
npx ironheights@0.21.1 report . --json-file posture.json --history .ironheights/posture.jsonl \
  --ledger ~/.ironheights/approvals.json --title "Q4 agent security review"
```

A folder counts as a repository when it has an `ironheights.threatmodel.yml` or one of
`skills/`, `.claude/skills/`, `.cursor/skills/`, `.agents/skills/`, `skill/`. A target that is not
a repository is treated as an organisation folder and its direct subfolders are checked.

The HTML is one self-contained file (no scripts, no external assets) that prints cleanly for an
audit pack. JSON carries the same data (`totals`, `owaspLlm`, `repos`, `skills`, `violations`,
`driftChanges`, `history`).

## Worst reach and config hash

Each skill row leads with `worstReach`: the highest-reach capability in that skill, with the rule
or evidence that showed it. The order, highest first, is exec or a credential read, secrets in
env, network egress to an undeclared host, writes outside the workspace, network to declared
hosts, then read-only. The grade stays next to it. Nothing about the grade calculation changes.

`configHash` is a sha256 of that skill's config inputs: frontmatter, JSON/YAML config files, the
names of env vars the skill references, and an MCP server entry when the skill names it. Secret
values are not hashed. The text and HTML rows show the first eight characters (`grade B @ cfg
1a2b3c4d`). The repo row has its own `configHash` over the skill hashes and MCP entries.

With `--history <file.jsonl>`, a later run sets `regraded: true` on a skill whose hash differs
from the previous run and prints `config changed since last report; grade recomputed`. The grade
is always recomputed. The flag says the config it was computed against changed. Older history
lines without hashes still load. A missing previous hash is not a regrade.

Exit code is `0`; `--fail-on-block` exits `2` when any skill is blocked, for a scheduled CI job.

## Scheduled in CI

```yaml
on:
  schedule: [{ cron: '0 6 * * 1' }]
jobs:
  posture:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx --yes ironheights@0.21.1 report . --html posture.html --json-file posture.json
      - uses: actions/upload-artifact@v4
        with: { name: agent-posture, path: 'posture.*' }
```

## Limits

The report adds up what the scanner, drift guard and threat model see. A grade is not proof of
safety, the OWASP mapping follows rule references (one finding can map to more than one risk), and
coverage counts listed skills, not how strict their entries are. Local only, no telemetry.
