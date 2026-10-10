# audit-config

`ironheights audit-config` reads the OpenClaw config file and reports a short list of high-risk settings. `ironheights doctor audit` is the same command.

```bash
ironheights audit-config
ironheights audit-config --json
ironheights audit-config --sarif config.sarif --fail-on high
ironheights audit-config --openclaw-config ./fixtures/openclaw.json
```

The file is `$OPENCLAW_CONFIG_PATH` or `$OPENCLAW_STATE_DIR/openclaw.json`, and otherwise `~/.openclaw/openclaw.json` (`%USERPROFILE%\.openclaw\openclaw.json` on Windows). `--openclaw-config` points at one file and returns exit 64 when that path is missing. A missing default file is exit 0: OpenClaw's own default is a safe local config, and there was nothing on disk to grade.

The command is read-only. It does not chmod files, does not start the Gateway, and does not open a socket.

## What OpenClaw already audits

OpenClaw ships `openclaw security audit` and `openclaw security audit --deep`. The plain command is a cold read of config and filesystem metadata. `--deep` adds a live Gateway probe and plugin or skill code scans. `--fix` can tighten some permissions and flip open group policies. The catalog is [Security audit checks](https://docs.openclaw.ai/gateway/security/audit-checks).

Ironheights does not reimplement that catalog and does not contradict it. Each `IH-CFG` rule below names the native `checkId` it overlaps. Token length, rate limits, Tailscale Serve, hooks, browser control, plugins, mDNS, sandbox mounts, and Windows ACLs stay in the native command. Run both when you want both: Ironheights for a small offline report you can put in CI, and `openclaw security audit` for the rest.

## Rules

Generated examples are in [rules.md](rules.md). Severities below are the usual ones. A finding can be raised when the same file also opens a room or enables host exec.

| Rule       | Usual severity                                                                       | Native overlap                                                                          | Reports                                                                                                                | Stays quiet                                                                 |
| ---------- | ------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| IH-CFG-001 | high, critical for `0.0.0.0` or Funnel, medium for `auto`                            | `gateway.bind_no_auth`, `gateway.tailscale_funnel`                                      | `lan`, `tailnet`, non-loopback `custom`, all-interfaces addresses, `tailscale.mode: funnel`                            | `loopback`, omitted bind, `custom` aimed at `127.0.0.1`                     |
| IH-CFG-002 | critical                                                                             | `gateway.bind_no_auth`, `gateway.token_placeholder_value`, `gateway.trusted_proxy_auth` | `auth.mode: none`, `trusted-proxy`, a non-loopback bind with no `gateway.auth`, empty or placeholder token or password | loopback with auth omitted, `${OPENCLAW_GATEWAY_TOKEN}`, a SecretRef object |
| IH-CFG-003 | critical                                                                             | `channels.<channel>.dm.open`                                                            | `dmPolicy` or `dm.policy` `open`                                                                                       | `pairing`, `allowlist`, `disabled`                                          |
| IH-CFG-004 | high, critical if tools or DMs are also open                                         | `security.exposure.open_groups_with_elevated`                                           | `groupPolicy: open`                                                                                                    | `allowlist`, `disabled`                                                     |
| IH-CFG-005 | high                                                                                 | `config.secrets.gateway_password_in_config`, `config.secrets.hooks_token_in_config`     | a literal token, password, secret, or API key                                                                          | `${ENV}` and SecretRef objects (`env`, `file`, `exec`, `store`)             |
| IH-CFG-006 | critical for world or group write and world read, medium for group read or a symlink | `fs.config.perms_*`, `fs.config.symlink`                                                | POSIX modes and symlinks                                                                                               | mode `0600` or `0400`. No permission finding on Windows                     |
| IH-CFG-007 | high, critical when elevated `allowFrom` is `*` or exec `full` meets an open room    | `tools.exec.security_full_configured`, `tools.elevated.allowFrom.*.wildcard`            | `security: full`, `ask: off` while security is not `deny`, elevated enabled                                            | `security: deny`, allowlist with `ask: always`, elevated off                |
| IH-CFG-008 | medium, critical for `~`, `/`, a drive root, or `..`                                 | none. Native `skills.workspace.symlink_escape` walks the workspace instead              | `skills.load.extraDirs`, `skills.load.allowSymlinkTargets`                                                             | the keys omitted or empty                                                   |
| IH-CFG-009 | medium or high                                                                       | `sandbox.docker_config_mode_off`, exposure checks                                       | sandbox `off` or omitted while exec is `full`, elevated is on, a room is open, or `sandbox.docker` is set              | sandbox `all`, or sandbox off with exec `deny` and elevated off             |

Evidence for IH-CFG-005 and for placeholder tokens is the key path plus `<redacted>`. The value is not printed. A placeholder gateway token is IH-CFG-002 only, so it is not also IH-CFG-005.

## Output

JSON is the scan document plus fields. `schemaVersion` remains `1`.

```json
{
  "schemaVersion": 1,
  "tool": { "name": "ironheights", "version": "0.1.5" },
  "scannedAt": "2026-10-10T00:00:00.000Z",
  "verdict": "no-findings",
  "skippedFileCount": 0,
  "grade": {
    "letter": "A",
    "score": 100,
    "disclaimer": "Absence of findings is not proof of safety."
  },
  "scanMode": "directory",
  "summary": "ironheights 0.1.5 | openclaw-config | grade A (100/100) | verdict no-findings | 0 findings",
  "badge": "[ironheights 0.1.5: grade A (100/100), verdict no-findings](https://github.com/Frank-Masciopinto/ironheights) — Absence of findings is not proof of safety.",
  "skills": [
    {
      "skillName": "openclaw-config",
      "root": "/home/me/.openclaw",
      "filesScanned": 1,
      "filesSkipped": [],
      "skippedFileCount": 0,
      "findings": [],
      "suppressed": [],
      "suppressedCount": 0,
      "suppressionRefused": [],
      "suppressionRefusedCount": 0,
      "score": 0,
      "verdict": "no-findings"
    }
  ],
  "command": "audit-config",
  "configPath": "/home/me/.openclaw/openclaw.json",
  "configFound": true,
  "configParsed": true,
  "nativeAudit": "openclaw security audit",
  "limits": []
}
```

Exit codes match `scan`: 0, 1, 2, 3, 64, and 70. A config file that cannot be parsed is exit 3. `--fail-on` works the same way as scan. Thresholds are the scan defaults, block 80 and review 15. `audit-config` does not read `ironheights.config.json`.

SARIF is 2.1.0, same renderer as `scan`.

## Limits

- The Gateway is not contacted. `auto` bind and Tailscale Serve are not resolved. Funnel is reported because it is a config value.
- `$include` files are not opened. A file that only points at another file can look clean.
- SecretRefs and `OPENCLAW_GATEWAY_TOKEN` / `OPENCLAW_GATEWAY_PASSWORD` are not read. A loopback bind that omits `gateway.auth` is not flagged. Native `gateway.loopback_no_auth` can still fire after OpenClaw resolves the effective auth.
- Per-agent precedence is not computed. An explicit dangerous value is reported even if another agent tightens it.
- Mutable `allowFrom` entries, token length, rate limits, hooks, browser, plugins, and sandbox mount paths are not checked.
- JSON5 support is the existing comment, trailing-comma, and unquoted-key subset.
- On Windows, `IH-CFG-006` does not treat Node's mode bits as ACLs and does not run `icacls`. Use `openclaw security audit` for that. CI covers the command on `windows-latest` as part of `npm test`, not a live Windows Gateway.

Absence of findings is not proof of safety.
