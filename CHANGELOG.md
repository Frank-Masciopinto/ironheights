# Changelog

## 0.1.2

`scan --all` and `doctor` now include OpenClaw bundled skills, custodian skills, and the real directories behind `~/.openclaw/plugin-skills` symlinks.

A scan of the local OpenClaw 2026.9.3 skill trees showed several false-positive shapes. `process.env` and a mentioned `.env` are not a dotenv path, the word "cookies" is not the browser cookie store, and the word `curl` is not a request. Loopback addresses are treated like `localhost`. Homepage fields, license URLs, XML namespaces, placeholder hosts, and documentation links are not network destinations. An exfiltration finding requires the secret and the request in the same few lines. A package install is a URL install only when the URL is on that same line. Requests the skill actually makes, such as `curl` to an API host, still report `IH-NET-001`.

## 0.1.1

Fixed a silent exit 0 when `ironheights` or `ih` is started through an npm bin (`npx`, a local install, or a global install). The entry check resolves the real script path, so a symlink or a Windows shim that passes a relative path still runs the command.

## 0.1.0

First MVP: local skill scanning, P0 and P1 rules, baseline verification, quarantine, SARIF output, and the synthetic benchmark.
