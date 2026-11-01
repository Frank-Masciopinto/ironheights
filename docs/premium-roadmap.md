# Premium roadmap (Planned tiers on ironheights.dev/pricing)

Ironheights protects any AI bot that installs it. The pricing page lists Pro, Team / Fleet, Publisher / Registry and Enterprise as **Planned**; prices are hypotheses and nothing paid can be bought. This file tracks what each planned feature needs, what already exists in the open CLI, and the build order. Everything below ships as open, opt-in Apache-2.0 code first. No payments, licensing checks or billing code live in this repo, and no premium feature weakens or gates detection: the scanner, rules and verdicts stay the same for everyone.

## Pro (per protected bot per month, Planned)

| Feature                                       | Exists today                                                                                              | Missing                                                        | Status                                                                      |
| --------------------------------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Retained signed logs and receipts             | `watch --activity` signed hash-chained log (0.25.0); MCP `check_skill` receipts + `verify_check` (0.23.0) | Long-term local store, retention, export, offline verification | **Built in 0.26.0**: `ironheights receipts ingest/list/export/verify/prune` |
| "Verified by Ironheights" badge / attestation | Scan verdict, content digest, rule-set hash                                                               | Signed statement + badge                                       | **Built in 0.26.0**: `ironheights attest <skill>` (JSON + SVG, `--verify`)  |
| Priority signature updates                    | Signed advisory feed (`advisories update`), 6-hourly version check                                        | Faster channel (e.g. advisory push / shorter poll), feed tiers | Planned; needs hosted feed, not CLI-only                                    |
| Credential broker                             | Guard blocks secret reads; `audit-config`                                                                 | Broker that hands scoped short-lived credentials to skills     | Not started (also not on the free tier yet)                                 |
| Injection screening                           | Prompt-injection rules in static scan; `scan --llm`                                                       | Runtime screening of tool outputs / fetched content            | Not started                                                                 |

## Team / Fleet (per bot with a minimum, Planned)

| Feature                                            | Exists today                                                  | Missing                                                                                                            |
| -------------------------------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | --- | ----- |
| Cloud console                                      | None (local-only by design)                                   | Hosted service; out of scope for this repo until a backend exists                                                  |
| Fleet inventory                                    | `report` posture per machine, `doctor`                        | Merge multiple posture reports / retention bundles into one inventory (`ironheights fleet inventory <bundles...>`) |
| Policy templates                                   | Guard policy file, threat model as code                       | Shipped template library (`ironheights policy init --template strict                                               | ci  | dev`) |
| CI gates `--fail-on-incomplete`, `--fail-on-widen` | **Exist** (report and threatmodel)                            | Docs: one recommended fleet CI recipe                                                                              |
| Alerts                                             | Drift watch, activity log refusals                            | Webhook/command hook on block, drift or chain break (`--on-alert <cmd>`)                                           |
| Audit log                                          | Guard audit log, signed activity log, now the retention store | Cross-bot export format (builds on `receipts export`)                                                              |

## Publisher / Registry (Planned)

| Feature              | Exists today                            | Missing                                                                                      |
| -------------------- | --------------------------------------- | -------------------------------------------------------------------------------------------- |
| Pre-verified skills  | `attest` (0.26.0)                       | Attestation for a ClawHub ref (`attest owner/slug@version`), registry-side verification docs |
| Trust badge          | Badge SVG from `attest` (0.26.0)        | Hosted endpoint serving badge by digest                                                      |
| Publisher reputation | None                                    | History of attestations per publisher, derived from retained records                         |
| Bulk lookups         | `scan` over many folders, advisory feed | `attest --batch` / JSON list in, attestations out                                            |

## Enterprise (Custom)

SSO, SLA, on-prem option and compliance reports need a hosted product and contracts; none are code in this repo. The local pieces that compliance reports can build on are the retention bundle (`receipts export`) and attestations. A `report --compliance` view mapping these to controls is the only Enterprise item planned for the CLI.

## Build order

1. Retained signed logs and receipts (**0.26.0, done**)
2. Verified-by-Ironheights attestation + badge (**0.26.0, done**)
3. Alerts hook for block, drift and failed verification (**0.26.0, done**)
4. Policy templates (**0.26.0, done**)
5. Fleet inventory and cross-bot audit export (**0.26.0, done**)
6. Publisher: ClawHub attestations, batch attest, publisher reputation (**0.26.0, done**)
7. Priority signature channel (needs hosted feed)
8. Credential broker, runtime injection screening (larger design work; free-tier parts first)
9. Hosted console, badge endpoint, Enterprise (needs a backend; outside this repo)
