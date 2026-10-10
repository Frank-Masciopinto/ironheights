# Limits

A scan reads files up to `limits.maxFileBytes` (1 MiB by default), stops after `limits.maxFiles` files (2000), and stops after `limits.maxDepth` directory levels (10). A file past the size cap is named in the report. The verdict is `incomplete` and the exit code is `3` when the files that were read would otherwise be `no-findings`. Review still exits `1`. Block still exits `2`.

## Directories

`dist/` is scanned. A payload in `dist/payload.md` is a finding.

`.git/` and `node_modules/` are not entered, at any depth. The text report prints:

```text
warning: skipped directory .git (directory not scanned)
warning: skipped directory node_modules (directory not scanned)
Scan incomplete: 2 directories were not scanned.
```

JSON adds `skippedDirectories` on the document and on the skill:

```json
"skippedDirectories": [
  { "path": ".git", "reason": "directory not scanned" },
  { "path": "node_modules", "reason": "directory not scanned" }
]
```

SARIF stores the same list on the run `properties`, plus `warning`: `Skipped directories were not scanned.`

That is an incomplete scan. Exit code `3` when the rest of the scan is `no-findings`. `--allow-skipped` keeps the warning, returns the finding verdict (`0`, `1`, or `2`), and the grade stays `incomplete`.

To acknowledge a directory, list it in `ignoreDirs` with a reason of at least 8 characters. The directory is still listed, with `explicit: true`, and it does not make the scan or the grade incomplete.

```json
{
  "ignoreDirs": [
    { "path": "node_modules", "reason": "packages are not skill instructions" },
    { "path": ".git", "reason": "git metadata is not a skill" }
  ]
}
```

A path with no slash matches that directory name anywhere in the skill. A path with a slash matches that relative path only. `ignoreDirs` applies to `.git` and `node_modules`. It does not hide `dist/`.

`ignoreGlobs` is a separate filter. A pattern you set there drops matching paths and does not add a finding. The built-in list is empty. Do not copy `**/dist/**` into it if you want `dist/` scanned.

## Exit codes

| Exit | Meaning                                                                                                           |
| ---- | ----------------------------------------------------------------------------------------------------------------- |
| 0    | No findings                                                                                                       |
| 1    | Review                                                                                                            |
| 2    | Block                                                                                                             |
| 3    | Incomplete. A file was skipped, or `.git` / `node_modules` was not entered, and the rest was not review or block. |
| 64   | Usage or config error                                                                                             |
| 70   | The command stopped: an internal error, a failed network request, or a rejected signature.                        |

`guard policy check` uses `1` when the sample call would be blocked and `0` when it would be allowed. `64` and `70` mean the same thing on every command.
