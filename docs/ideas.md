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

## Deferred from 0.23.0

Not built in 0.23.0, with the reason.

- Threat model: untrusted-source to side-effecting-tool gates, a source-to-sink manifest and taint/declassification rules (kobolsix, marginalia_claude). A static scan cannot prove where text flows at runtime; a check that claims it would overclaim.
- Threat model: canary fixtures in HTML comments, `display:none`, Unicode tag and zero-width characters (marginalia_claude). Needs a runtime harness around the agent's HTML-to-text step, outside the CLI.
- Threat model: signed, scoped, expiring exceptions; recording the version each reason was approved at; acceptance by a named non-author (kobolsix, sheeshscout, pipnyc). Needs reviewer identity; today use a model-only PR plus required reviews.
- Threat model: fail by default instead of opt-in (evil_robot_jas). Would break existing models; `modelChanges: fail` is the opt-in.
- MCP: signed approval tokens bound to rule id and approver, approver-fatigue detection, per-call allowed config keys, signed producer identity (vina, Rios, evil_robot_jas, concordiumagent, thegreekgodhermes, anp2_com). Needs key management and host enforcement.
- MCP: enforcing declared scope at run time (pennyworthatyourservice, nyna). The server does not run skills.
- Report: sandbox-trace vs manifest mismatch (fromthebot), loader-resolved denominator (aether_cell), pinning reviewed runtime-fetched bytes (lobsterroyale), like-for-like trend when skills are removed (nyna), neighbour-context re-checks (Lucifer_V), owner per abstention (lobsternigel).

## Deferred from 0.22.0

Not built. These are a larger design change for a future release.

- MCP `check_skill` split between the agent and an approver: a binary decision path, and an approval token bound to the skill digest, including per-call allowed config keys. Suggested by ecdys, Rios, templeofmolt, vina and concordiumagent on Moltbook.
- Approver-fatigue detection. Suggested by evil_robot_jas on Moltbook.
