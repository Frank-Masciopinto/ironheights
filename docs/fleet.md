# Alerts, policy templates and fleet inventory

New in 0.26.0, Team / Fleet track features shipped as open, opt-in code. Ironheights protects any AI bot that installs it; nothing here changes a verdict or an exit code.

## Alerts hook

Off unless you set `IRONHEIGHTS_ALERT_WEBHOOK`, `IRONHEIGHTS_ALERT_COMMAND`, or `IRONHEIGHTS_HOME/alerts.json` (`{"webhook": "...", "command": "..."}`). Then these send an alert:

- `scan` / `review` with a `block` verdict
- `drift check` with drift since approval
- a failed `watch --verify-log`, `receipts verify` (store or bundle) or `attest --verify`

The payload is JSON (`type: ironheights-alert/1`, kind, time, host, version, key id, summary, data). It is signed with the local ed25519 watch key over the exact body bytes. Webhooks get a POST with `x-ironheights-signature` and `x-ironheights-key-id` headers; only https, or http to localhost, is allowed. A command gets the body on stdin and the signature in `IRONHEIGHTS_ALERT_SIGNATURE`. Every alert is also kept in the retention store. Check one with `ironheights alerts verify --body body.json --signature <base64> [--public-key key.pem]`; send a test with `ironheights alerts test`.

## Policy templates

`ironheights policy init --template strict|balanced|ci [--dir .] [--force]` writes `ironheights.config.json` and `guard-policy.json` (`--list` shows them). Templates only tighten: none raises a threshold, disables a rule, adds a suppression or allows a domain.

- `balanced`: the defaults made explicit, fail on high, guard monitors.
- `strict`: fail on medium, block/review thresholds 40/5, guard enforces.
- `ci`: fail on high, guard enforces, plus `.github/workflows/ironheights.yml` running `scan`, `report --fail-on-incomplete` and `threatmodel check --fail-on-widen`.

## Fleet inventory

`ironheights fleet inventory claude=~/.claude/skills grok=~/grok/skills other-host.json [--out inv.json] [--audit-export audit.json] [--trust-key key.pem] [--json]`

Scans each `bot=dir` on this host and merges signed inventories exported from other hosts (`.json` targets; tampered or untrusted ones are refused). Prints bots, hosts, skills, verdict counts, blocked skills and skills whose bytes differ between bots; exit 1 when any skill is blocked. The output is signed with the local key. `--audit-export` adds the retention bundle (receipts, attestations, alerts) to the signed inventory as the cross-bot audit record.
