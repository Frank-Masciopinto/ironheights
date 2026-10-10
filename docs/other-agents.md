# Other agent skill folders and MCP configs

Ironheights scans directories. It does not need a plugin for Claude Code, Codex, or Cursor. Point `scan` at the skill folder. The rules are the same ones used for OpenClaw. A clean grade is still not proof of safety.

These paths were checked against the public docs on 10 October 2026. Products move directories. If a folder has no `SKILL.md`, pass the skill directory that contains it.

## Claude Code

| Scope    | Path                                      |
| -------- | ----------------------------------------- |
| Project  | `.claude/skills/<name>/SKILL.md`          |
| Personal | `~/.claude/skills/<name>/SKILL.md`        |
| Nested   | `<subdir>/.claude/skills/<name>/SKILL.md` |

```bash
ironheights scan .claude/skills/some-skill
ironheights scan ~/.claude/skills/some-skill
```

## Codex

Current Codex discovery uses `.agents/skills` from the working directory up to the repository root, plus `~/.agents/skills`. Older installs still keep skills in `~/.codex/skills`. Admin skills may live in `/etc/codex/skills`.

```bash
ironheights scan .agents/skills/some-skill
ironheights scan ~/.agents/skills/some-skill
ironheights scan ~/.codex/skills/some-skill
```

## Cursor

Cursor loads project skills from `.agents/skills/` and `.cursor/skills/`, and user skills from `~/.agents/skills/` and `~/.cursor/skills/`. For compatibility it also reads `.claude/skills/`, `.codex/skills/`, `~/.claude/skills/`, and `~/.codex/skills/`.

```bash
ironheights scan .cursor/skills/some-skill
ironheights scan ~/.cursor/skills/some-skill
```

## MCP configuration files

`IH-MCP-001`, `IH-MCP-002`, and `IH-MCP-003` read MCP configs as data. They never start the server and never run `command`.

A file is an MCP config when it is named `mcp.json`, `.mcp.json`, or `claude_desktop_config.json`, or when its text contains `"mcpServers"` or a `[mcp_servers` table. Other files that mention `npx` are left alone.

| Rule         | What it reports                                                                                                                                                      |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `IH-MCP-001` | `curl` or `wget` piped into a shell (critical), or `npx` / `bunx` / `pnpm dlx` / `yarn dlx` of a package that is not pinned to a numeric version or a commit (high). |
| `IH-MCP-002` | A literal secret in that server's `env` map. `${API_KEY}` and other references are not literals.                                                                     |
| `IH-MCP-003` | An argument that is `/`, `~`, `$HOME`, a home directory such as `/home/alex`, or a Windows drive root such as `C:\`. A project subdirectory is not.                  |

Pinned and local examples that stay quiet:

```json
{
  "mcpServers": {
    "notes": {
      "command": "npx",
      "args": ["-y", "@example/mcp-notes@1.2.3", "./notes"],
      "env": { "API_KEY": "${API_KEY}" }
    }
  }
}
```

```bash
ironheights scan .cursor/mcp.json
ironheights scan .mcp.json
ironheights scan ~/.codex/config.toml
```

Claude Desktop keeps `claude_desktop_config.json` in its application support directory. Claude Code uses `.mcp.json` in the project. Cursor uses `.cursor/mcp.json` and `~/.cursor/mcp.json`. Codex uses `[mcp_servers]` in `~/.codex/config.toml`.

Suppressions, grades, and `--since-baseline` apply to these files the same way they apply to a skill. A critical shell pipe stays visible unless `suppressCritical` is true. See the README.
