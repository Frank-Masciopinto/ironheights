# Changelog

## 0.1.2

`scan --all` and `doctor` now include OpenClaw bundled skills, custodian skills, and the real directories behind `~/.openclaw/plugin-skills` symlinks.

A scan of the local OpenClaw 2026.9.3 skill trees showed five false-positive shapes. `process.env` is no longer treated as a `.env` file, the word "cookies" is no longer treated as the browser cookie store, loopback addresses are treated like `localhost`, a documentation URL is not an outbound request, and a package install is a URL install only when the URL is on that same line. Undeclared vendor hosts in bundled skills still report `IH-NET-001`.

## 0.1.1

Fixed a silent exit 0 when `ironheights` or `ih` is started through an npm bin (`npx`, a local install, or a global install). The entry check resolves the real script path, so a symlink or a Windows shim that passes a relative path still runs the command.

## 0.1.0

First MVP: local skill scanning, P0 and P1 rules, baseline verification, quarantine, SARIF output, and the synthetic benchmark.
