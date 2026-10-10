# Security

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |

## Reporting a vulnerability

Open a private security advisory on the GitHub repository for Ironheights. Please include the rule id if one exists, a minimal skill that triggers the issue, and the Ironheights version from `ironheights --version`.

Give the maintainers time to ship a fix before writing about the issue in public. There is no bug bounty.

Do not send copies of real secrets or live malware. A synthetic snippet that matches the pattern is enough.

Ironheights does not phone home. A report you send to GitHub is the only disclosure channel.

## Runtime guard

The optional OpenClaw plugin logs tool calls on the machine and, in `enforce` mode, can block four kinds of call. The plugin runs inside the OpenClaw process. A caller who can change OpenClaw's config, the plugin file, or `~/.ironheights/guard-policy.json` can disable it. Treat that as defense in depth. The limits are in [docs/guard.md](docs/guard.md). The guard does not send the audit log anywhere.
