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

## Decision (superseded): no MCP server for ironheights

Superseded: Ironheights now ships an MCP server; see [mcp.md](mcp.md). The original reasoning is kept below for history.

An MCP server interface for ironheights itself stays excluded. Scanning MCP configuration files is in scope (`IH-MCP-001` through `IH-MCP-003`). Serving ironheights as an MCP server, with tools such as `scan_skill` or `scan_text`, is not.

The trusted path is the `ironheights` command you run yourself, outside the agent. An MCP server would put the scanner back inside the agent process that a hostile skill can influence. Ironheights reads MCP configs as data and does not launch the servers they describe.

## Built in 0.25.0

The runtime ideas deferred from 0.24.0 and 0.23.0 are built as `sandbox run` (austingrok, templeofmolt, evil_robot_jas, fromthebot), `watch --activity` with `report --from-watch` (juan_carlos, sophiaalways, concordiumagent, taobotagent, hermeslife3) and `install` (clawlogan, nanoswarm). Still not built: refusing unversioned `get_rule` by default (practicalstable43; opt-in stays `IRONHEIGHTS_MCP_PIN_RULES=1`) and enforcing declared scope inside the agent at run time (pennyworthatyourservice, nyna); `sandbox run` and `watch --activity` observe and grade it, they do not block the agent.

## Deferred from 0.24.0

Built in 0.24.0 as far as a static, local tool can go. Not built, with the reason:

- Threat model: one sandboxed run diffing observed egress hosts against the model (austingrok), reconciling an external count against the skill log (templeofmolt), and measuring observer heartbeats as new records landing in the store (juan_carlos, sophiaalways). These need a runtime harness; 0.24.0 checks the declared cadence, store and identity, and accepts sandbox output as `reasons.*.evidence`.
- Threat model: flagging declared writes that never fire across N runs (evil_robot_jas). Ironheights does not observe runs; 0.24.0 flags declared writes the files never name (`write-declared-unused`).
- Posture: an authoritative artifact ledger written by an observer at the credential store (taobotagent). Ironheights reads the creation ledger you pass and agent hook registries; it does not watch a credential store.
- Posture: a timestamped capture of capability changes between scheduled snapshots (concordiumagent). `changeLog` shows changes between report runs; continuous capture is `ironheights drift watch`.
- MCP: refusing unversioned `get_rule` by default (practicalstable43). It would break existing clients; `IRONHEIGHTS_MCP_PIN_RULES=1` opts in.
- MCP: an installer that consumes the pinned closure manifest without re-resolving (clawlogan, nanoswarm). Ironheights reports and gates on the closure; it is not the installer.
- MCP: stall classes "busy queue" vs "real hang" (hermeslife3). The checker cannot tell them apart from inside one process; both report as `timeout`.

From 0.23.0, now built: expiring reasons with a named non-author approver (`reasons`, `--review`) and signed, scoped, expiring authorizations (`redeem_authorization`).

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
