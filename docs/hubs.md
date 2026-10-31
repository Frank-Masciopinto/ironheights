# Add Ironheights to your skill hub in one line

Ironheights is the npm audit for AI skills. A hub (ClawHub, grokpot, Claude Duet, an MCP registry, or your own catalog) can grade every skill A to F before it is listed, with the same rules people run locally. Ironheights protects any AI bot's skills: OpenClaw, Claude, Grok Bot, Codex, Cursor and MCP servers.

- The scan is local. No skill text leaves the machine that runs it. No telemetry, no API key, no account.
- Every finding carries its OWASP Top 10 for LLM Applications (2025) id and an OpenCRE link, so a reviewer sees which control it maps to.
- A grade is a pattern-match score for a human to look at. Absence of findings is not proof of safety, and a low grade is not proof of malice.

## 1. Skill repositories: the GitHub Action

```yaml
- uses: Frank-Masciopinto/ironheights@v0.23.0
  with:
    version: '0.23.0'
    path: skills
    badge-file: ironheights-badge.json
```

Outputs: `grade` (A-F), `score` (0-100), `verdict` (`no-findings`, `review`, `block`, `incomplete`), `findings`, `exit-code`, `json-file`, `sarif-file`. The job summary lists the top findings with links to each rule page. Set `job-summary: 'false'` to turn that off. Full input list: [ci.md](ci.md).

## 2. Hubs: one command per uploaded skill

Run this in your ingest worker, in a sandbox with no network if you can:

```bash
npx --yes ironheights@0.23.0 scan ./uploaded-skill --json > result.json
```

`result.json` has `grade.letter`, `grade.score`, `verdict` and, per skill, `skills[].findings[]` with `ruleId`, `severity`, `file`, `line`, `message`, `remediation` and `links` (OWASP and OpenCRE). Exit code `0` no findings, `1` review, `2` block, `3` incomplete. Pin an exact version so grades do not move under you; bump it when you are ready to re-grade.

Suggested listing policy, yours to change: show the grade on the listing; hold `block` for human review; never auto-delete on a grade alone.

## 3. The badge

The Action's `badge-file` (or your own code) writes a [shields.io endpoint](https://shields.io/badges/endpoint-badge) JSON:

```json
{ "schemaVersion": 1, "label": "ironheights", "message": "A (100/100)", "color": "brightgreen" }
```

If you do not want to host JSON, use a static badge per grade from the site, for example `https://www.ironheights.dev/api/v1/badge/a.json` (letters `a` to `f`):

```markdown
![ironheights](https://img.shields.io/endpoint?url=https://www.ironheights.dev/api/v1/badge/a.json)
```

## 4. Rule metadata

`https://www.ironheights.dev/api/v1/rules.json` lists every rule with its severity, title, OWASP LLM id and OpenCRE ids. It is a static file (CORS open) you can cache. `https://www.ironheights.dev/api/v1/index.json` lists the endpoints.

## Questions

Open an issue on [GitHub](https://github.com/Frank-Masciopinto/ironheights/issues). We are happy to help a hub wire this in.
