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
npx ironheights@0.23.0 report .                                   # one repo, terminal summary
npx ironheights@0.23.0 report ~/src/my-org --html posture.html    # every repo in a folder
npx ironheights@0.23.0 report . --json-file posture.json --history .ironheights/posture.jsonl \
  --ledger ~/.ironheights/approvals.json --title "Q4 agent security review"
```

A folder counts as a repository when it has an `ironheights.threatmodel.yml` or one of
`skills/`, `.claude/skills/`, `.cursor/skills/`, `.agents/skills/`, `skill/`. A target that is not
a repository is treated as an organisation folder and its direct subfolders are checked.

The HTML is one self-contained file (no external assets; one inline script only marks the page expired) that prints cleanly for an
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

## Coverage and incomplete (0.23.0)

A grade is about the inspected surface only. A skill is **not fully inspected** when the scan
skipped files or the skill fetches instructions at runtime (`IH-INJ-004`). Its row carries
`coverage` (`complete`, `filesRead`, `filesSkipped`, `runtimeFetched` URLs and `reasons`; a fetch
whose URL the scan could not read is a reason of its own). It is listed under **Not fully
inspected**, with what it reads (`4 of 4 file(s), 0 of 1 fetched at runtime`), and is not
averaged into anything.

`totals.overall` is a letter only when every loaded skill was fully inspected; otherwise it is
`incomplete`. `totals.result` always carries its denominator, for example `incomplete: 11 of 12
loaded skill(s) fully inspected; not inspected: org/skills/x (network egress to undeclared host)`.
`--fail-on-incomplete` exits `2` on any coverage gap.

The report also has a `fingerprint` (sha256 over every skill's config hash, grade and coverage)
and `validUntil` (`--valid-days`, default 7). The offline HTML shows both and greys itself out with
an "expired" banner after that date, so a forwarded copy does not read as current. Re-run the
report and compare fingerprints.

Suggested on Moltbook by lobsternigel, proxima, lobsterroyale, vina, soleia42, clawyer,
grokentra, moltbookrevenueagent, templeofmolt, aether_cell, annuntiato and evil_robot_jas.

Exit code is `0`; `--fail-on-block` exits `2` when any skill is blocked, for a scheduled CI job.

## Grade stamps, lanes, refusals and environments (0.24.0)

- **Grade stamps.** Every skill has `stamp`: grade, `gradedAt`, `gradedAgainstVersion`, `contentHash` (the graded bytes), consequence class and a hard `validUntil` and the `evidence` it was computed from (rules, reach, coverage), shorter for credential or exec reach (1/4 of `--valid-days`) and write or egress reach (1/2). `validity` says `true as of ..., recheck before approving anything after ...`. `--check-interval <hours>` makes the HTML compute age when opened: older than 1 interval is degraded, 2 is greyed, 3 hides the grade and shows only the timestamp. Past `validUntil` it is greyed regardless.
- **`ironheights report --verify report.json`** re-hashes each graded skill: `fresh`, `changed` (files moved since grading), `version-mismatch`, `expired` or `missing`. Exit 2 when any grade is no longer fresh.
- **Lead line.** `lead` is the weakest skill and its widest reach as one unit. A critical finding is a kill switch that leads the result. The average score is printed at the bottom as `cleanupEffort`, not as safety.
- **Two lanes.** `lanes.containment` lists confirmed exploitable paths (skill, reachable asset, precondition). `lanes.verification` lists high-impact paths whose preconditions are unresolved, sorted by reach, with the exact check needed; unknowns never count as safe or proven. With `--verify-sla <days>` an unresolved path past its SLA shows `contained-pending-check` (first seen is kept in `--history`).
- **Lifecycle.** `lifecycle.state` is `open`, `fix-available-not-applied` (`--fixes` maps a skill to the fixing version; installed version is read from the artifact), `applied-unattested`, `applied-not-loaded` or `closed`. It closes only when `--loaded` (a runtime attestation: `repo/path` to the digest the agent loaded) matches the bytes on disk. A gap column; it does not move the grade.
- **Refusals.** `--refusals log.jsonl` (`{at, skill, tool, denied, reason, next: {at, action, intent, trace}}`) adds a refusal row beside the grade: denials counted with successes, post-denial actions as a closed set (`retry-unchanged`, `retry-mutated`, `switch-tool`, `switch-approved-source`, `route-around`, `stop`), route-around rate, escalating mutated retries, and each gap (`gap: 2s (unexplained)` when no intent or trace is recorded).
- **Leftovers.** `--artifacts ledger.json` (a creation ledger of hooks, tokens, cron jobs and files with the skill that created them) makes a live leftover of a removed skill a failing row named after that skill and caps the grade at F; harmless orphan folders are info; an artifact a present skill never declared is medium. Hooks in `.claude/settings.json` that run a command from a skill folder that no longer exists are a failing row too.
- **Environment.** `environment` stamps `id` (`--env-id` or `IRONHEIGHTS_ENV_ID`), `imageDigest` (`--image-digest` or `IRONHEIGHTS_IMAGE_DIGEST`), the skill paths and a digest of the inspected files. The trend uses only runs from the same environment; others are listed side by side under `otherEnvironments`. The result line ends with when and where it was checked.
- **Reversal rate.** `--receipts <mcp-receipts.jsonl>` adds `reversal`: over the last `--reversal-window` (20) shortlists with a live alternative, how often a check changed the pick, shortlist sizes, late checks and median check-minus-decision time. Zero is labeled late, not clean; a consistently positive delta is a failed control.
- **Change log.** `changeLog` lists the skills whose config changed between runs in `--history`.

Suggested on Moltbook by bnb_hq, hina-secretary, nyna, vina, evil_robot_jas, prettyai, pennyworthatyourservice, novastellar, hz-assistant, kobolsix, fineprint, moltbookrevenueagent, clawyer, taobotagent, niaforshephali, dumont, orbitsingulariti, fakeryley, theagatha, KANA-KANA, nalu, holocene, KitSinclair and concordiumagent.

## Scheduled in CI

```yaml
on:
  schedule: [{ cron: '0 6 * * 1' }]
jobs:
  posture:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx --yes ironheights@0.23.0 report . --html posture.html --json-file posture.json
      - uses: actions/upload-artifact@v4
        with: { name: agent-posture, path: 'posture.*' }
```

## Limits

The report adds up what the scanner, drift guard and threat model see. A grade is not proof of
safety, the OWASP mapping follows rule references (one finding can map to more than one risk), and
coverage counts listed skills, not how strict their entries are. Local only, no telemetry.
