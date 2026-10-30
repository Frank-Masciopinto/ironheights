# Monthly public AI-skill security dataset

`monthly.py` builds the open dataset behind the monthly report on [ironheights.dev/reports](https://www.ironheights.dev/reports/). Stdlib Python 3, no dependencies.

1. **list** the public ClawHub catalog (`GET https://clawhub.ai/api/v1/skills`, paged, read-only, no login).
2. **select** the top `--top` skills by downloads plus a uniform random sample of `--sample` of the rest (seed `ironheights-<month>`), or every skill with `--all`.
3. **fetch** each selected skill's latest version through the per-file API. No zip download, so authors' download counters are not inflated. Files are written as inert bytes, sha256-checked against the listing, never run or unpacked. Files over 1 MiB get a same-size placeholder. Paths with `..` or absolute paths are refused. 429s back off and honor `Retry-After`.
4. **scan** each skill with a pinned `ironheights` binary inside bubblewrap (no network, read-only root, empty `HOME`), 120 s timeout.
5. **publish** `public/skills.csv`, `public/skills.json`, `public/summary.json` under CC BY 4.0.

## Responsible handling

- Public files contain no skill name, owner, slug or skill text. Each row has an opaque id (`sha256(salt + owner/slug)`, salt kept in `private/`), so the mapping is not public.
- A flag is a pattern match for a person to review, not a finding of malice. The report says so and does not name authors.
- `private/disclosure-queue.json` lists `block` verdicts with at least one rule outside the three low-signal ones (`IH-NET-001`, `IH-FS-001`, `IH-META-001`). Before anything is published about a specific skill, a person reviews it and, if it holds up, reports it privately to the author and to ClawHub (security@ or the skill's report button), with 30 days before any public detail.
- An author can ask which row is theirs, or ask for a re-scan, by opening an issue or emailing the address in [SECURITY.md](../../SECURITY.md).

## Run

```bash
npm i --prefix ./bin ironheights@<version>
python3 monthly.py all --month 2026-11 --out /data/ih-2026-11 \
  --ironheights ./bin/node_modules/.bin/ironheights --top 2000 --sample 2000
```

Each step is resumable. `--all` scans every listed skill: plan for about a day of polite fetching at the default 8 workers.

Not covered yet: GitHub-hosted skills and MCP registries. The official MCP registry lists server metadata, not skill text; scanning MCP server source needs a separate fetcher.
