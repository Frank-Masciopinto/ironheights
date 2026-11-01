# Retained receipts and attestations

New in 0.26.0, the first Pro-track features, shipped as open, opt-in code. Ironheights protects any AI bot that installs it; these commands keep the proof.

## Retention store

`ironheights receipts <action>` keeps a local, signed, append-only store in `IRONHEIGHTS_HOME/retained/` (override with `IRONHEIGHTS_RETAINED_DIR`). Records use the same ed25519 key (`watch-key.pem`) and hash-chained format as `watch --activity`, one segment per month (`receipts-YYYY-MM.jsonl`).

- `receipts ingest [--from <file>] [--activity <log>] [--retention-days <n>]` copies MCP `check_skill` receipts (default `mcp-receipts.jsonl`) into the store, once per check id, and optionally retains a reference (record count, head hash, file hash) to a `watch --activity` log after verifying it. It then applies retention.
- `receipts list [--since <date>] [--skill <name>] [--kind <kind>] [--json]`
- `receipts export --out bundle.json` writes the public key and the raw signed segments.
- `receipts verify [--bundle bundle.json]` checks every signature and chain link; exit 2 on any break.
- `receipts prune [--retention-days <n>]` applies retention.

Retention (default 365 days, or `IRONHEIGHTS_RETENTION_DAYS`) never edits a segment. It deletes whole months older than the window and first appends a signed `retention-prune` record naming the segment, its record count and its last line hash, so a deletion is always visible.

## Attestation

`ironheights attest ./skill [--out file] [--badge file] [--valid-days 30]` scans the skill and signs a statement with its content digest, verdict, finding count, tool version and rule-set hash. Only a `no-findings` verdict is marked `verified`; anything else is attested honestly as not verified (exit 1). Output defaults to `./<skill>.attestation.json` and `.svg` in the current folder, never inside the skill. The attestation is also retained in the store.

`ironheights attest ./skill --verify file.json [--public-key key.pem]` checks the signature, expiry and that the files still match the digest; pass `--public-key` to pin the publisher's key instead of trusting the embedded one. Exit 0 only when verified.

The badge is a static SVG, ready for a README or a registry endpoint.
