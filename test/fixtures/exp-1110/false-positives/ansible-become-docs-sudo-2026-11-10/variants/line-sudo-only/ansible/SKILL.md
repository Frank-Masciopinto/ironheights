---
name: Ansible
description: Avoid common Ansible mistakes — YAML syntax traps, variable precedence, idempotence failures, and handler gotchas.
metadata: {"clawdbot":{"emoji":"🔧","requires":{"bins":["ansible"]},"os":["linux","darwin"]}}
---

## YAML Syntax Traps
- Jinja2 in value needs quotes — `"{{ variable }}"` not `{{ variable }}`
- `:` in string needs quotes — `msg: "Note: this works"` not `msg: Note: this`
- Boolean strings: `yes`, `no`, `true`, `false` parsed as bool — quote if literal string
- Indentation must be consistent — 2 spaces standard, tabs forbidden

## Variable Precedence
- Extra vars (`-e`) override everything — highest precedence
- Host vars beat group vars — more specific wins
- `vars:` in playbook beats inventory vars — order: inventory < playbook < extra vars
- Undefined variable fails — use `{{ var | default('fallback') }}`

## Idempotence
- `command`/`shell` modules aren't idempotent — always "changed", use `creates:` or specific module
- Use `apt`, `yum`, `copy` etc. — designed for idempotence
- `changed_when: false` for commands that don't change state — like queries
- `creates:`/`removes:` for command idempotence — skips if file exists/doesn't

## Handlers
- Handlers only run if task reports changed — not on "ok"
- Handlers run once at end of play — not immediately after notify
- Multiple notifies to same handler = one run — deduplicated
- `--force-handlers` to run even on failure — or `meta: flush_handlers`

## Become
- Password needed for sudo — use `--ask-become-pass`
