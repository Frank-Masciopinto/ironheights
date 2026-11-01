# Guarded install

`ironheights install` installs a skill itself instead of advising. It writes only the exact bytes that were checked, plus the pinned dependency closure, and refuses on any mismatch. Ironheights protects any AI bot that installs it.

```bash
# On the reviewed copy: record exactly what was checked
ironheights install ./weather --write-lock weather.lock.json

# Later, anywhere: install only if the bytes still match
ironheights install ./weather --lock weather.lock.json --dir ~/.openclaw/workspace/skills
ironheights install acme/weather@1.2.0 --lock weather.lock.json --dir ./skills

# Or bind to the contentDigest returned by the MCP check_skill tool
ironheights install ./weather --expect-digest <sha256> --dir ./skills
```

## Checks, in order

1. Stage the skill (copy a local folder, or download from ClawHub).
2. Hash every file. Symlinks and files too large to hash refuse.
3. The digest must equal the lock's digest or `--expect-digest`. With a lock, every file must be present with the same hash and no other file may exist.
4. The dependency closure (`package-lock.json` with integrity hashes, `requirements.txt` with `--hash`) must be fully pinned and identical to the lock's closure. A range or a missing hash refuses.
5. The scan verdict must be `no-findings` (`review` with `--accept-review`; `block` and `incomplete` never install).
6. Each file is re-read and re-hashed right before writing; the buffer written is the buffer hashed, so a change between check and write refuses.
7. Files go to a temporary folder next to the destination, then are moved into place. An existing install is backed up to `~/.ironheights/install-backups/` and restored on failure. Every install is appended to `~/.ironheights/installs.jsonl`.

## Dependencies

`--with-deps` installs the closure and nothing else:

- `npm ci --ignore-scripts --omit=dev` (npm verifies every integrity hash from the lockfile; install scripts do not run)
- `python3 -m pip install --require-hashes --no-deps --only-binary=:all: --target .deps -r requirements.txt`

Without `--with-deps` the commands are printed, not run.

Exit codes: 0 installed (or lock written), 2 refused, 64 usage.

Covers ideas from clawlogan and nanoswarm (an installer that consumes the pinned closure manifest without re-resolving).
