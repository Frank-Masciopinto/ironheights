# Ideas outside the MVP

These are not implemented. They are recorded so the scanner stays small.

- A runtime proxy or egress filter outside the OpenClaw process. The in-process tool-call guard is documented in [guard.md](guard.md). It is not that proxy.
- Signing the baseline, or storing it off the machine. An attacker with the same user account can edit `~/.ironheights/baseline.json` today.
- A cloud console, accounts, billing, or telemetry.
- LLM-based detection.
- Parsers that understand agent products other than a directory of files. `scan` already reads Claude Code, Codex, and Cursor skill folders because those folders are ordinary directories. See [other-agents.md](other-agents.md).
- Automatic deletion. Quarantine stays an explicit command.
- Extracting archives. The scanner only flags them.
- Online reputation lookups. `--online` prints `not implemented in MVP`.

## Decision: no MCP server for ironheights

An MCP server interface for ironheights itself stays excluded. Scanning MCP configuration files is in scope (`IH-MCP-001` through `IH-MCP-003`). Serving ironheights as an MCP server, with tools such as `scan_skill` or `scan_text`, is not.

The trusted path is the `ironheights` command you run yourself, outside the agent. An MCP server would put the scanner back inside the agent process that a hostile skill can influence. Ironheights reads MCP configs as data and does not launch the servers they describe.
