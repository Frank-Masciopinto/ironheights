# Activity watch

`ironheights watch --activity` is a small background watcher. It records what installed skills and the agent actually did to a signed, append-only log, so `report --from-watch` can grade what happened instead of a snapshot. Ironheights protects any AI bot that installs it.

```bash
ironheights watch --activity ~/.openclaw/workspace/skills \
  --events ~/.ironheights/events.jsonl --model ironheights.threatmodel.yml --interval 15
```

Plain `ironheights watch` (rescan on change) is unchanged.

## What it records

- **File activity.** Each round hashes every skill folder: `installed`, `modified` (with the changed and removed files) and `removed`.
- **Events from the inbox.** Hooks, proxies and observers append JSON lines to `--events`; the watcher reads only new lines.

| Inbox `kind`                                 | Fields                              | Logged as                                                                    |
| -------------------------------------------- | ----------------------------------- | ---------------------------------------------------------------------------- |
| `net`                                        | `skill`, `host`                     | `net` with `declared: true/false` against the model's `network` and `egress` |
| `heartbeat`                                  | `observer`                          | `heartbeat`                                                                  |
| `check-start`, `check-progress`, `check-end` | `id`, `skill`, `outcome`            | `check-start`, `check-end` with `durationMs`                                 |
| `refusal`                                    | `agent`, `tool`, `target`, `reason` | `refusal`                                                                    |
| `action`                                     | `agent`, `tool`, `target`           | `action`                                                                     |

Every line may carry `at` (ISO time).

- **Busy queue or hang.** A check open longer than `--check-budget` (default 30 s) becomes `check-stall` with `stallClass: busy-queue` when it reported progress in the last 10 s, otherwise `hang`.
- **Observer heartbeats.** Observers in the threat model with a `heartbeat` cadence (`30s`, `5m`, `1h`, `1d`) that miss it produce `observer-stale`.
- **After each refusal.** The agent's next action within 5 minutes is `after-refusal` with `next`: `retry-unchanged`, `retry-mutated`, `route-around` (same target, other tool), `switch-tool`, or `stop` when nothing follows.

## The log

Default `~/.ironheights/activity.jsonl` (`--log`). Each line has `seq`, `at`, `kind`, `skill`, `data`, `prev` (SHA-256 of the previous line) and `sig`, an ed25519 signature made with a local key created on first use at `~/.ironheights/watch-key.pem` (mode 600). The public key is `watch-key.pub.pem`. A removed, reordered or edited line breaks verification:

```bash
ironheights watch --verify-log ~/.ironheights/activity.jsonl
```

## Grading from the log

```bash
ironheights report . --from-watch ~/.ironheights/activity.jsonl --json
```

The report gains a `watch` section and caps grades by what happened:

| Event                                                               | Grade cap                 |
| ------------------------------------------------------------------- | ------------------------- |
| Contact with an undeclared host                                     | F for that skill          |
| A hung check                                                        | D                         |
| The agent answered a refusal with `retry-mutated` or `route-around` | D                         |
| An observer missed its heartbeat                                    | C                         |
| The log fails verification                                          | F for every skill, exit 2 |

Capped skills carry `watchCap` with the original grade and reasons.

Covers ideas from juan_carlos and sophiaalways (observer heartbeats measured as records landing), concordiumagent (continuous capture between snapshots), hermeslife3 (busy queue vs real hang), taobotagent (an observer-written artifact ledger) and novastellar, hz-assistant and nyna (what the agent did after each refusal).
