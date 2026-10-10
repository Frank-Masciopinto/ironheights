# Security

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.2.x   | yes       |
| 0.1.x   | yes       |

## Reporting a vulnerability

Open a private security advisory on the GitHub repository for Ironheights. Please include the rule id if one exists, a minimal skill that triggers the issue, and the Ironheights version from `ironheights --version`.

Give the maintainers time to ship a fix before writing about the issue in public. There is no bug bounty.

Do not send copies of real secrets or live malware. A synthetic snippet that matches the pattern is enough.

Ironheights does not phone home during `scan`. `fetch`, `safe-install`, `advisories update`, and `--online` are explicit network commands. `scan --llm` and `review` are the other network path, and they are off unless you pass them. Each download command prints the URL before connecting, talks only to `clawhub.ai` or `ironheights.dev` over HTTPS, and refuses redirects. A report you send to GitHub is the disclosure channel. The advisory feed is a signed document you choose to download. It is not telemetry.

## Advisory signatures

The production advisory private key is not in this repository. The CLI rejects a feed whose signature does not match the public key pinned in `src/advisories/pinned-key.ts` (`8424b837422792656e6e7500869395a5afe64bf163baa63acea83f1e97cc2b6c`). See [docs/advisories.md](docs/advisories.md).

## Runtime guard

The optional OpenClaw plugin logs tool calls on the machine and, in `enforce` mode, can block four kinds of call. The plugin runs inside the OpenClaw process. A caller who can change OpenClaw's config, the plugin file, or `~/.ironheights/guard-policy.json` can disable it. Treat that as defense in depth. The limits are in [docs/guard.md](docs/guard.md). The guard does not send the audit log anywhere.

## Optional model review

`scan --llm` and `review` are off unless you pass them. A localhost model server stays on the machine. Any other host needs `--llm-consent` and `IRONHEIGHTS_LLM_API_KEY`. Ironheights redacts common secret shapes before sending and prints the request body first. Redaction can miss a secret. Do not send a skill that contains a live secret to a remote model. Model notes are advisory and can be wrong. A report to GitHub should still use a synthetic snippet, not a live secret.
