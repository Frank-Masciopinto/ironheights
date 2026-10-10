# Security

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |

## Reporting a vulnerability

Open a private security advisory on the GitHub repository for Ironheights. Please include the rule id if one exists, a minimal skill that triggers the issue, and the Ironheights version from `ironheights --version`.

Give the maintainers time to ship a fix before writing about the issue in public. There is no bug bounty.

Do not send copies of real secrets or live malware. A synthetic snippet that matches the pattern is enough.

Ironheights does not phone home during `scan`. `fetch`, `safe-install`, `advisories update`, and `--online` are explicit network commands. Each one prints the URL before connecting, talks only to `clawhub.ai` or `ironheights.dev` over HTTPS, and refuses redirects. A report you send to GitHub is the disclosure channel. The advisory feed is a signed document you choose to download. It is not telemetry.

## Advisory signatures

The production advisory private key is not in this repository. The CLI rejects a feed whose signature does not match the public key in `src/advisories/pinned-key.ts`. Until that constant is set, every feed is rejected. See [docs/advisories.md](docs/advisories.md).

## Runtime guard

The optional OpenClaw plugin logs tool calls on the machine and, in `enforce` mode, can block four kinds of call. The plugin runs inside the OpenClaw process. A caller who can change OpenClaw's config, the plugin file, or `~/.ironheights/guard-policy.json` can disable it. Treat that as defense in depth. The limits are in [docs/guard.md](docs/guard.md). The guard does not send the audit log anywhere.
