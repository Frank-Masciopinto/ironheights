# Sandbox run

`ironheights sandbox run` runs a skill once and compares what it did with the threat model. Ironheights protects any AI bot that installs it; a static scan reads what a skill says, this shows what it does.

```bash
ironheights sandbox run ./skills/weather -- node run.js --city Warsaw
```

## What happens

1. The skill folder is copied to a temporary directory. The container gets that copy at `/skill`, an empty home at `/home/sandbox` and a trace directory.
2. The container runs with `--network none`, all capabilities dropped except `SYS_PTRACE`, `no-new-privileges`, a 256-process and 512 MB limit.
3. `HTTP_PROXY` and `HTTPS_PROXY` point at a proxy inside the container. It logs every request and `CONNECT` target and answers 403. Nothing leaves the machine.
4. When the image has `strace`, the run is traced with `-f`: every `execve` (child processes), every open for writing, rename, unlink and mkdir (with the pid, so writes by child processes are marked), and every `connect`.
5. Writable mounts are hashed before and after, so writes are recorded even without `strace`.
6. The container and the copy are removed.

The default image is `node:20-bookworm-slim` (no `strace`). Use `--image` or `IRONHEIGHTS_SANDBOX_IMAGE` for an image with `strace`; without it, child processes are reported as `not-measured`. `IRONHEIGHTS_CONTAINER=podman` picks podman. With no docker or podman the command exits 3 and says so.

## Findings

| Kind                       | Severity | Meaning                                                                                   |
| -------------------------- | -------- | ----------------------------------------------------------------------------------------- |
| `sandbox-write-undeclared` | error    | A path written that is not in `writes` or `filesystem`. Writes by child processes say so. |
| `sandbox-host-undeclared`  | error    | A host tried (proxy or `connect`) that is not in `network` or `egress`.                   |
| `sandbox-child-undeclared` | error    | A child process started when the model has `shell: false`.                                |
| `sandbox-child-write`      | warning  | A declared write made by a child process while `shell` is false.                          |
| `sandbox-write-unused`     | info     | A declared write that never happened in this run. `--fail-on-unused` makes it fail.       |
| `sandbox-record-mismatch`  | error    | The outside record (`--external`) disagrees with what the sandbox saw.                    |
| `sandbox-not-measured`     | warning  | No `strace` in the image.                                                                 |

Paths are matched the way the threat model writes them: `/home/sandbox/x` is `~/x`, `/skill/x` is `x`. `/proc`, `/dev`, `/sys`, `/tmp` and `/run` are ignored.

Exit codes: 0 matches the model, 2 a failing finding, 3 no container engine, 64 usage.

## Outside records

`--external records.json` reconciles the trace with something the skill does not control, such as an egress firewall log or an audit store:

```json
[
  { "kind": "host", "value": "api.example.com", "count": 2 },
  { "kind": "write", "value": "~/.demo/cache.json" }
]
```

Every listed item must have been seen exactly `count` times (default 1), and every host the sandbox saw must be in the record.

## Recorded traces and CI

`--save-trace trace.json` keeps the trace; `--trace trace.json` compares a saved trace without running anything, which is how the test suite runs without docker.

In the GitHub Action:

```yaml
- uses: Frank-Masciopinto/ironheights@v0.27.0
  with:
    version: '0.27.0'
    mode: threatmodel
    path: .
    sandbox-skill: skills/weather
    sandbox-run: node run.js --dry-run
```

`sandbox-exit-code` is an output; a non-zero code fails the job.

Covers ideas from austingrok (sandboxed egress diff), templeofmolt (reconcile an outside count), fromthebot (sandbox trace vs manifest) and evil_robot_jas (declared writes that never fire).
