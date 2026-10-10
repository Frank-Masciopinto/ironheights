import type { IgnoreDir, SkippedDirectory } from './types.ts';

/** Directories the scan never enters. `dist` is not in this set. */
export const OPAQUE_DIRECTORY_NAMES: ReadonlySet<string> = new Set(['.git', 'node_modules']);

export const OPAQUE_DIRECTORY_REASON = 'directory not scanned';

/**
 * Record a `.git` or `node_modules` directory instead of descending into it.
 * `ignoreDirs` can name the directory (or its relative path) with a reason.
 * That acknowledgement is still listed, and it does not make the scan incomplete.
 */
export function directorySkip(
  relativePath: string,
  name: string,
  ignoreDirs: readonly IgnoreDir[],
): SkippedDirectory | undefined {
  if (!OPAQUE_DIRECTORY_NAMES.has(name)) return undefined;
  const explicit = findIgnoreDir(relativePath, name, ignoreDirs);
  if (!explicit) return { path: relativePath, reason: OPAQUE_DIRECTORY_REASON };
  return { path: relativePath, reason: explicit.reason, explicit: true };
}

export function findIgnoreDir(
  relativePath: string,
  name: string,
  ignoreDirs: readonly IgnoreDir[],
): IgnoreDir | undefined {
  const portable = normalizeDirPath(relativePath);
  for (const entry of ignoreDirs) {
    const wanted = normalizeDirPath(entry.path);
    if (wanted.length === 0) continue;
    if (wanted.includes('/')) {
      if (wanted === portable) return entry;
      continue;
    }
    if (wanted === name || wanted === portable) return entry;
  }
  return undefined;
}

function normalizeDirPath(value: string): string {
  return value.trim().replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/, '');
}
