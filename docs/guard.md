# Runtime guard

The guard watches OpenClaw tool calls for four high-risk behaviors the scanner already describes: reading credential paths, shell commands that download and execute, outbound requests to undeclared or high-risk hosts, and writes to agent identity files, memory files, and skill folders.

It is off until you load the OpenClaw plugin. The default mode is `monitor`: append a local audit line and do not block. `enforce` blocks the call and tells you the rule id. An allow entry in the policy file is the explicit approval. The guard does not prompt inside the chat.

## What a block can and cannot do

OpenClaw's documented `before_tool_call` hook runs after the model picks a tool and before OpenClaw runs it. The plugin returns `{ block: true, blockReason }` in enforce mode. That hook is registered with `api.on("before_tool_call", ...)` inside the OpenClaw process. Checked against the OpenClaw plugin docs on 10 October 2026 (`docs.openclaw.ai/plugins/hooks` and `docs.openclaw.ai/plugins/hooks/tool-policy`).

This is defense in depth. It is not a sandbox, and it is not a process outside the agent.

- A hook inside the OpenClaw process can be bypassed by a compromised skill that can turn the plugin off, edit `openclaw.json`, edit the policy file, or replace the plugin file. Those are the same user account.
- The guard sees the tool name and parameters OpenClaw passes in. It does not see a shell that is already running, a host hidden in an environment variable, or a connection that never appears as a URL in the command.
- `derivedPaths` from the host are hints. The docs say they can miss paths or include paths the tool will not touch. A symlink is resolved when the path already exists. A path that does not exist yet is judged lexically.
- OpenClaw treats a thrown or timed-out `before_tool_call` hook as fail-closed (the tool does not run). The guard catches its own errors so it does not crash the agent. In monitor mode an internal error is logged and the call is allowed. In enforce mode an internal error blocks, with a reason that says the guard could not evaluate the call.
- An invalid policy file falls back to monitor, unless the plugin config sets `mode` to `enforce`. A typo should not lock every tool. Someone who can write the policy file can also set `mode` to `monitor`. `ironheights guard status` prints when the file is invalid.
- The audit log is append-only until it rotates. It is mode `0600`. Anyone who can write the ironheights home directory can edit or delete it. It is not a tamper-proof ledger.

Absence of a block is not proof the call was safe.

## Behaviors

| Rule             | What it matches                                                                                                                                                                                                                  | Scanner rule it lines up with |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| `IH-GUARD-CRED`  | `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.azure`, private key files, `wallet.dat`, `.electrum`, `.env` (not `.env.example`), OpenClaw `credentials/` and `openclaw.json`                                                               | `IH-CRED-001`                 |
| `IH-GUARD-EXEC`  | `curl`/`wget` piped into a shell, command substitution, `base64 -d` piped into a shell, or `curl -o file && bash file` when both steps name the same file                                                                        | `IH-EXEC-001`                 |
| `IH-GUARD-NET`   | A URL in `web_fetch`, `browser`, `web_search`, or a shell command whose host is not on the effective allowlist. High-risk hosts (paste sites, file-drop hosts, tunnel hosts, raw IP addresses) are the same set as `IH-NET-001`. | `IH-NET-001`                  |
| `IH-GUARD-WRITE` | Writes, edits, patches, or shell redirects that target `AGENTS.md`, `SOUL.md`, `IDENTITY.md`, `USER.md`, `TOOLS.md`, `BOOTSTRAP.md`, `MEMORY.md`, `memory/`, or a file inside a skill directory                                  | integrity watch list          |

`web_search` is a violation only when the query itself contains a URL to an undeclared or high-risk host. The search provider is chosen in OpenClaw config, not in the tool call.

A download saved to disk and executed in a later, separate tool call is not tied together. A command such as `curl https://example.com/health && bash scripts/test.sh` is not treated as download-and-execute, because the shell is not running the downloaded file.

## Modes

| Mode      | Effect                                                                                                            |
| --------- | ----------------------------------------------------------------------------------------------------------------- |
| `monitor` | Default. Log the decision. Do not block.                                                                          |
| `enforce` | Block when any violation is left after allow entries. The reason includes the rule id and how to add an approval. |

Mode comes from the plugin config `plugins.entries.ironheights-guard.config.mode` when that value is `monitor` or `enforce`. Otherwise it comes from the policy file. Otherwise it is `monitor`.

The guard does not use OpenClaw's `requireApproval` prompt. A chat approval can be talked into, and OpenClaw does not persist `allow-always` unless the plugin stores it. The durable approval is an allow entry you write in the policy file.

## Enable it

Install ironheights, then point OpenClaw at this package. The package manifest `openclaw.plugin.json` and `package.json` field `openclaw.extensions` point at `dist/openclaw/plugin.js`. `before_tool_call` does not need `hooks.allowConversationAccess`.

```bash
openclaw plugins install --link /path/to/ironheights --force
openclaw plugins enable ironheights-guard
```

In `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "ironheights-guard": {
        "enabled": true,
        "config": { "mode": "monitor" }
      }
    }
  }
}
```

Create `~/.ironheights/guard-policy.json` when you want enforce mode or extra hosts. A missing file means monitor mode and the built-in hosts only, plus any `allowDomains` in `ironheights.config.json`.

```json
{
  "version": 1,
  "mode": "monitor",
  "allowDomains": ["api.example.com"],
  "skills": {
    "weather": { "allowDomains": ["api.weather.example"] }
  },
  "allow": [
    {
      "id": "known-hosts",
      "reason": "SSH host keys are not private keys.",
      "rule": "IH-GUARD-CRED",
      "path": "**/.ssh/known_hosts"
    }
  ],
  "log": { "maxBytes": 1048576, "maxFiles": 5 }
}
```

Unknown keys are an error. An allow entry needs a `reason` and at least one of `rule`, `tool`, `skill`, `path`, or `host`.

Set `IRONHEIGHTS_HOME` to move the policy and the log. Set `IRONHEIGHTS_GUARD_POLICY` or the plugin `policyPath` to point at a different policy file.

## Allowlist precedence

A host is allowed when it matches any of these, including subdomains. Loopback addresses are allowed. This is the same `allowDomains` match the scanner uses.

1. Built-in hosts: `example.com`, `example.org`, `example.net`, `localhost`, `github.com`, `githubusercontent.com`, `npmjs.org`, `yarnpkg.com`, `pypi.org`, `pythonhosted.org`, `openclaw.ai`.
2. `allowDomains` in `ironheights.config.json`.
3. `allowDomains` in the guard policy (every skill).
4. The skill's own hosts, only when the tool call names that skill (`params.skill` or `params.skillName`): `skills.<name>.allowDomains` in the policy, and `metadata.ironheights.allowDomains` in that skill's `SKILL.md`.

A call that does not name a skill does not inherit any skill's hosts. That is deliberate. OpenClaw's `before_tool_call` context does not say which skill triggered the call.

An allow entry then suppresses one matching violation. It does not clear other rules on the same call. A host on the allowlist is allowed even when it would otherwise be high-risk. That matches `IH-NET-001`. Putting `webhook.site` in `allowDomains` is an explicit choice.

## Audit log

The log is `~/.ironheights/guard.log.jsonl`, one JSON object per line, `schemaVersion` 1. Secrets that look like private keys, `AKIA` keys, GitHub tokens, Slack tokens, bearer tokens, and quoted secret assignments are masked before the line is written. The block reason is masked too, because the agent can read it.

The current file is appended until it passes `log.maxBytes` (default 1 MiB). It is then renamed to `guard.log.1.jsonl`. Older files shift up. `log.maxFiles` (default 5, including the current file) is the cap. The guard drops the oldest file. A log write that fails, or takes longer than a short bound, does not change the allow or block decision and does not throw into OpenClaw.

Ordinary reads of workspace files are not logged. Violations, allows, exec, network, and write calls are logged.

## Commands

```text
ironheights guard status [--policy <file>] [--config <file>] [--json]
ironheights guard policy check [--policy <file>] [--call <json>] [--call-file <file>] [--json]
ironheights guard log [--tail <n>] [--policy <file>] [--json]
```

`status` prints the mode, whether the policy parsed, and whether `plugins.entries.ironheights-guard` is enabled. `policy check` exits 64 when the policy is invalid, 1 when the sample call would block, and 0 when it would be allowed. `log` prints the newest lines of the current file.

Nothing in the guard calls the network. There is no telemetry.

## Decisions

- The enforcement point is OpenClaw's `before_tool_call` plugin hook, because that is the documented way to block a tool call. A separate proxy is still not built.
- The plugin export is a plain `{ id, register }` object. The loader accepts `register`. `definePluginEntry` would import `openclaw/plugin-sdk`, and this package does not depend on OpenClaw.
- Approval is an allow entry with a reason, not an in-chat prompt.
- Invalid policy falls back to monitor so a typo cannot brick the agent. Plugin config `mode: "enforce"` still enforces, using the built-in hosts and `ironheights.config.json`.
- Internal errors never throw out of the hook. Enforce fails closed. Monitor fails open and logs.
- The four rules stay aligned with the scanner. The guard does not add a second, larger pattern set.

## Website notes

The site should say that ironheights can log and, in enforce mode, block a short list of tool calls through an OpenClaw plugin. It should say the plugin runs inside OpenClaw, that a compromised agent can disable it, and that monitor mode does not block. It should link the four rule ids, the policy file, and `ironheights guard status`. It should not say the guard is outside the agent, a sandbox, an antivirus, or a guarantee. "Absence of findings is not proof of safety" still applies to a scan, and a quiet guard log is not proof either.
