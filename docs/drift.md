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

| Change                | Severity | Meaning                                                                               |
| --------------------- | -------- | ------------------------------------------------------------------------------------- |
| `description-changed` | high     | The SKILL.md `description` changed. This is what the model reads to decide to use it. |
| `new-host`            | high     | The skill text names a URL host that was not there when you approved it.              |
| `new-credential-path` | high     | The skill text names a credential path (`~/.ssh`, `~/.aws`, `.env`, wallets, ...).    |
| `mcp-tool-changed`    | high     | An MCP tool's description or input schema changed (tool poisoning / rug pull).        |
| `mcp-server-changed`  | high     | An MCP server's command, args, URL or env changed, for example a pin moved to latest. |
| `file-added`          | medium   | A new file in an approved skill.                                                      |
| `file-changed`        | medium   | A file's sha256 changed.                                                              |
| `skill-unapproved`    | medium   | A skill that is not in the ledger.                                                    |
| `mcp-server-added`    | medium   | A server that is not in the ledger.                                                   |
| `mcp-tool-added`      | medium   | A tool that is not in the ledger.                                                     |
| `file-removed`        | info     | A file is gone.                                                                       |
| `skill-missing`       | info     | An approved skill is gone (`--all` only).                                             |

Exit code: `0` no drift, `1` medium, `2` high. After you review a change, run `approve` again to accept it. Then run `ironheights scan` on the changed skill for the full rule check.

## MCP tool descriptions

Ironheights does not start MCP servers. To track tool descriptions, save a server's `tools/list` response to a file (for example with the MCP Inspector) and pass it with `--tools`. Key order and whitespace do not count as drift.

## Where the ledger lives

`<ironheights home>/approvals.json` (mode `0600`), or `--ledger <file>`. Anyone who can write that file can approve a change, so this is a tripwire for supply-chain changes, not a defense against code already running as you.

## What happens at run time

For OpenClaw, the [runtime guard](guard.md) watches tool calls as they happen and flags credential reads, download-and-execute, undeclared network hosts and writes to skill folders, and can block them. Other agents do not expose a pre-tool-call hook to plugins today, so for them drift watch checks what the skill and tool definitions say, not what a process does.

## Threat model

`ironheights threatmodel check --ledger <approvals.json>` adds every drift change to the threat model report, so one PR check covers both. See [threatmodel.md](threatmodel.md).
