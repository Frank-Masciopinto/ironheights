/**
 * Dependency closure of a skill folder (0.24.0): every resolved dependency with its own
 * integrity hash, read from the lockfiles in the folder. A range with no lockfile entry means
 * the installer would resolve it at install time, one level below the checked digest.
 * Static only: nothing is installed or fetched.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

export interface ClosureEntry {
  name: string;
  version: string | null;
  integrity: string | null;
  source: string;
}

export interface Closure {
  complete: boolean;
  entries: ClosureEntry[];
  /** Dependencies declared with a range or no hash, so the installer would re-resolve them. */
  unpinned: string[];
  files: string[];
}

async function read(p: string): Promise<string | null> {
  try {
    return await readFile(p, 'utf8');
  } catch {
    return null;
  }
}

export async function dependencyClosure(dir: string): Promise<Closure> {
  const entries: ClosureEntry[] = [];
  const unpinned: string[] = [];
  const files: string[] = [];
  const pkgRaw = await read(join(dir, 'package.json'));
  const lockRaw = await read(join(dir, 'package-lock.json'));
  const declared: string[] = [];
  if (pkgRaw) {
    files.push('package.json');
    try {
      const pkg = JSON.parse(pkgRaw) as Record<string, Record<string, string> | undefined>;
      for (const k of ['dependencies', 'optionalDependencies'])
        declared.push(...Object.keys(pkg[k] ?? {}));
    } catch {
      /* unreadable manifest: counted as unpinned below */
    }
  }
  const locked = new Set<string>();
  if (lockRaw) {
    files.push('package-lock.json');
    try {
      const lock = JSON.parse(lockRaw) as {
        packages?: Record<string, { version?: string; integrity?: string; dev?: boolean }>;
      };
      for (const [k, v] of Object.entries(lock.packages ?? {})) {
        if (!k || v.dev) continue;
        const name = k.replace(/^.*node_modules\//, '');
        locked.add(name);
        entries.push({
          name,
          version: v.version ?? null,
          integrity: v.integrity ?? null,
          source: 'package-lock.json',
        });
        if (!v.integrity) unpinned.push(`${name} (no integrity hash)`);
      }
    } catch {
      unpinned.push('package-lock.json (unreadable)');
    }
  }
  for (const d of declared) if (!locked.has(d)) unpinned.push(`${d} (range, not locked)`);
  const req = await read(join(dir, 'requirements.txt'));
  if (req) {
    files.push('requirements.txt');
    for (const raw of req.split('\n')) {
      const line = raw.replace(/#.*/, '').trim();
      if (!line || line.startsWith('-')) continue;
      const m = /^([A-Za-z0-9_.-]+)\s*(==\s*([^\s;\\]+))?/.exec(line);
      if (!m) continue;
      const hash = /--hash=(sha256:[0-9a-f]{64})/.exec(raw)?.[1] ?? null;
      entries.push({
        name: m[1] as string,
        version: m[3] ?? null,
        integrity: hash,
        source: 'requirements.txt',
      });
      if (!m[3] || !hash) unpinned.push(`${m[1]} (${m[3] ? 'no --hash' : 'range'})`);
    }
  }
  return { complete: unpinned.length === 0, entries, unpinned, files };
}
