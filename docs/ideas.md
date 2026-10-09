# Ideas outside the MVP

These are not implemented. They are recorded so the scanner stays small.

- Runtime proxy, egress filtering, and command approval.
- Signing the baseline, or storing it off the machine. An attacker with the same user account can edit `~/.ironheights/baseline.json` today.
- A cloud console, accounts, billing, or telemetry.
- LLM-based detection.
- Support for agent frameworks other than OpenClaw.
- Automatic deletion. Quarantine stays an explicit command.
- Extracting archives. The scanner only flags them.
- Online reputation lookups. `--online` prints `not implemented in MVP`.
- A Model Context Protocol server. The trusted interface is the CLI.
