# Drift watch: catch a skill or MCP tool that changes after you approved it

A skill or MCP server can pass review and then change. The "rug pull" pattern: the tool description, the skill text or the server command is swapped after people trust it. `ironheights drift` records what you approved and tells you when it moves. It is opt-in, local only, and sends nothing anywhere (no telemetry).

```bash
# Approve what you reviewed (skills in any agent: OpenClaw, Claude, Grok Bot, Codex, Cursor)
ironheights drift approve ~/.claude/skills ~/.openclaw/workspace/skills
ironheights drift approve --all            # every configured skill directory

# MCP: approve server entries and, optionally, a saved tools/list response
ironheights drift approve --mcp ~/.cursor/mcp.json --tools ./calc-tools.json

# Later, or in a cron / login hook
ironheights drift check --all --mcp ~/.cursor/mcp.json --tools ./calc-tools.json
ironheights drift watch --all --interval 60   # print each new change once, keep running
```

## What counts as drift

| Change                   | Severity       | Meaning                                                                                                                                                    |
| ------------------------ | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `description-changed`    | high           | The SKILL.md `description` changed. This is what the model reads to decide to use it.                                                                      |
| `new-host`               | high           | The skill text names a URL host that was not there when you approved it.                                                                                   |
| `new-credential-path`    | high           | The skill text names a credential path (`~/.ssh`, `~/.aws`, `.env`, wallets, ...).                                                                         |
| `mcp-tool-changed`       | high           | An MCP tool's description or input schema changed (tool poisoning / rug pull).                                                                             |
| `mcp-server-changed`     | high           | An MCP server's command, args, URL or env changed, for example a pin moved to latest.                                                                      |
| `file-added`             | medium         | A new file in an approved skill.                                                                                                                           |
| `file-changed`           | medium         | A file's sha256 changed.                                                                                                                                   |
| `skill-unapproved`       | medium         | A skill that is not in the ledger.                                                                                                                         |
| `mcp-server-added`       | medium         | A server that is not in the ledger.                                                                                                                        |
| `mcp-tool-added`         | medium         | A tool that is not in the ledger.                                                                                                                          |
| `file-removed`           | info           | A file is gone.                                                                                                                                            |
| `skill-missing`          | info           | An approved skill is gone (`--all` only).                                                                                                                  |
| `config-key-added`       | medium or high | A config key the source never set. High when the name touches auth, network or tool scope.                                                                 |
| `restriction-removed`    | medium or high | A restriction key disappeared (`timeout`, `limit`, `max`, `allowlist`, `readonly`, ...).                                                                   |
| `restriction-loosened`   | medium or high | A restriction got looser: a limit raised or set to `0` / `unlimited`, an allow-list gained `*`, a `readonly` or `sandbox` flag flipped from true to false. |
| `config-keys-unrecorded` | info           | This ledger was written before config keys were recorded. Not a block.                                                                                     |

Exit code: `0` no drift, `1` medium, `2` high. After you review a change, run `approve` again to accept it. Then run `ironheights scan` on the changed skill for the full rule check.

## Config keys

`drift approve` stores the flattened keys a skill sets: `SKILL.md` frontmatter (including
`metadata.*` and OpenClaw config) and JSON/YAML files in the skill folder (`*.json`, `*.yml`,
`*.yaml`). Lockfiles and files over 256 KiB are skipped. `drift approve --mcp` stores each MCP
server's command, url, env keys and long-option args the same way.

`drift check` and the MCP tool `drift_status` compare that map:

- a key that was not there → `config-key-added`
- a restriction key that disappeared → `restriction-removed`
- a restriction whose value got looser → `restriction-loosened` (treated with the same severity as a new key)

Severity is **block** (high, exit 2) when the key name matches auth, network or tool scope
(`auth`, `token`, `key`, `secret`, `credential`, `password`, `oauth`, `host`, `url`, `endpoint`,
`proxy`, `network`, `egress`, `domain`, `allow.*host`, `tool`, `tools`, `scope`, `permission`,
`exec`, `shell`, `command`), and when an allow-list or scope gains `*`. Anything else is **warn**
(medium, exit 1). A file that changed is still reported as `file-changed`, as before.

JSON from `drift check --json` and from `drift_status` adds:

```json
{
  "configKeys": [
    {
      "source": "/path/skill",
      "key": "config.json:timeout",
      "change": "restriction-loosened",
      "before": "30",
      "after": "0",
      "severity": "warn",
      "reason": "restriction loosened"
    }
  ],
  "decision": "warn"
}
```

`decision` is `block`, `warn` or `ok` from the worst change in the report. `severity` on a config
key is `block`, `warn` or `info`.

Values that look like secrets are stored and printed as `<redacted>`. Before/after values are
shown only for restrictions that are not secrets. A ledger from before 0.22.0 has no `configKeys`
field. It still loads. The check reports `config-keys-unrecorded` (info) and does not invent a
block from keys it never recorded.

## MCP tool descriptions

Ironheights does not start MCP servers. To track tool descriptions, save a server's `tools/list` response to a file (for example with the MCP Inspector) and pass it with `--tools`. Key order and whitespace do not count as drift.

## Where the ledger lives

`<ironheights home>/approvals.json` (mode `0600`), or `--ledger <file>`. Anyone who can write that file can approve a change, so this is a tripwire for supply-chain changes, not a defense against code already running as you.

## What happens at run time

For OpenClaw, the [runtime guard](guard.md) watches tool calls as they happen and flags credential reads, download-and-execute, undeclared network hosts and writes to skill folders, and can block them. Other agents do not expose a pre-tool-call hook to plugins today, so for them drift watch checks what the skill and tool definitions say, not what a process does.

## Threat model

`ironheights threatmodel check --ledger <approvals.json>` adds every drift change to the threat model report, so one PR check covers both. See [threatmodel.md](threatmodel.md).
