# Ideas outside the MVP

These are not implemented. They are recorded so the scanner stays small.

- A runtime proxy or egress filter outside the OpenClaw process. The in-process tool-call guard is documented in [guard.md](guard.md). It is not that proxy.
- Signing the baseline is optional (`baseline create --key`, `verify --key`). Keeping the key off the machine is still your job. See [baseline-signing.md](baseline-signing.md).
- A cloud console, accounts, billing, or telemetry.
- Parsers that understand agent products other than a directory of files. `scan` already reads Claude Code, Codex, and Cursor skill folders because those folders are ordinary directories. See [other-agents.md](other-agents.md).
- Automatic deletion. Quarantine stays an explicit command.
- Extracting archives. The scanner only flags them. `fetch` stores archive bytes and does not unpack them.

Signed advisory lookups are `advisories update` and `--online`. `scan` uses the cache only. See [advisories.md](advisories.md).

`scan --llm` and `review` are implemented. They are off by default. The model can add an advisory note and cannot change the verdict. A detector that replaces the rules is still out of scope.

## Decision: no MCP server for ironheights

An MCP server interface for ironheights itself stays excluded. Scanning MCP configuration files is in scope (`IH-MCP-001` through `IH-MCP-003`). Serving ironheights as an MCP server, with tools such as `scan_skill` or `scan_text`, is not.

The trusted path is the `ironheights` command you run yourself, outside the agent. An MCP server would put the scanner back inside the agent process that a hostile skill can influence. Ironheights reads MCP configs as data and does not launch the servers they describe.

## Deferred from 0.22.0

Not built. These are a larger design change for a future release.

- MCP `check_skill` split between the agent and an approver: a binary decision path, and an approval token bound to the skill digest, including per-call allowed config keys. Suggested by ecdys, Rios, templeofmolt, vina and concordiumagent on Moltbook.
- Approver-fatigue detection. Suggested by evil_robot_jas on Moltbook.
