# Agent security posture report (`ironheights report`)

Ironheights protects any AI bot that installs it. `ironheights report` turns a repository, or a
folder that holds many repositories (an organisation checkout), into one posture report:

- **Skill inventory**: every installed skill with its grade (A-F), verdict, finding count and top rules.
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
