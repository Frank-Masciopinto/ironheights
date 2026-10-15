# Fetch and safe-install

`fetch` and `safe-install` download a skill. `advisories update` and `--online` download the advisory feed described in [advisories.md](advisories.md). `scan --llm` and `review` are the opt-in model path. Every other command stays on the machine.

Nothing that is downloaded is executed. Files are written mode `0600`. Archives are stored as bytes and are not extracted.

## URLs

The host is `clawhub.ai` and the scheme is `https`. Redirects are refused. The CLI pins that hostname and checks the TLS certificate. It does not pin the DNS address, and it will not follow a redirect onto another host. The CLI prints each URL before the request. With a version:

```text
fetch ada/notes@1.0.0
This command contacts the network. Scans stay local. Besides fetch, safe-install, advisories update, --online, scan --llm, and review, the only network call is a version check every 6 hours (off with IRONHEIGHTS_NO_UPDATE=1).

Requesting:
  GET https://clawhub.ai/api/v1/skills/notes?owner=ada
  GET https://clawhub.ai/api/v1/skills/notes/versions/1.0.0?owner=ada

Requesting:
  GET https://clawhub.ai/api/v1/skills/notes/file?owner=ada&path=SKILL.md&version=1.0.0
```

Without `@version`, the skill document is requested first so the latest version is known, then the version document, then each file. The owner and slug in the response must match the argument. Each file's size and sha256 must match the version file list.

The ClawHub routes are the public read API documented at <https://docs.openclaw.ai/clawhub/http-api>:

- `GET /api/v1/skills/{slug}?owner={owner}`
- `GET /api/v1/skills/{slug}/versions/{version}?owner={owner}`
- `GET /api/v1/skills/{slug}/file?owner={owner}&path={path}&version={version}`

The user agent is `ironheights/<version> (+https://github.com/Frank-Masciopinto/ironheights)`. It does not include a client id.

## Limits

Config `limits` can only make these smaller. The hard caps are 10 MiB per file, 32 MiB total, and 2000 files. Paths must be relative. Absolute paths, `..`, backslashes, and symlinks are refused. A refusal deletes the partial staging directory.

## safe-install

`safe-install` stages, scans, then copies. The verdict decides:

| Verdict       | Result                                      |
| ------------- | ------------------------------------------- |
| `no-findings` | copy into the skills directory, exit 0      |
| `review`      | do not copy unless `--accept-review` is set |
| `block`       | do not copy, exit 2                         |
| `incomplete`  | do not copy, exit 3                         |

`--accept-review` does not apply to `block` or `incomplete`. With that flag, a review verdict is still printed and the command exits 0 because the install finished.

The default destination is the OpenClaw workspace skills directory (`<workspace>/skills/<slug>`). `--dir` selects another skills directory. The directory must not be reached through a symlink.

An existing skill directory is moved to `$IRONHEIGHTS_HOME/install-backup/<timestamp>-<slug>` before the copy. If the copy fails, that backup is moved back. The backup stays after a successful install so you can compare it. Ironheights does not delete it.

```text
Installed: /home/ada/.openclaw/workspace/skills/notes
Backup: /home/ada/.ironheights/install-backup/2026-10-10T00-00-00-000Z-notes
```

`fetch` leaves the staged copy in place and prints `Staged N files at <path>`. `--out` chooses that directory. It must be empty, and it must not be a symlink.
