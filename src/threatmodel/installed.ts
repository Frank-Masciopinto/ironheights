/**
 * Read-only load-time check (0.31.0): `threatmodel verify-installed`.
 *
 * Exits non-zero when an installed artifact's content hash differs from the hash the
 * model recorded. An optional size+mtime cache skips re-reading bytes only when every
 * file's size and mtime still match and no file was added or removed. A difference in
 * size or mtime always recomputes the content hash.
 *
 * Tradeoff: a hit trusts size and mtime. A writer who changes bytes and then restores
 * both is not detected on the hit path. `threatmodel check` always hashes content.
 */
import { lstat, readdir, readFile, writeFile } from 'node:fs/promises';
import { join, relative, resolve, sep } from 'node:path';
import { contentDigest } from '../mcp/receipts.ts';
import { classifyOverrides, hashVerdict, type ListedOverride } from './pins.ts';
import { toPosix, type ThreatModel } from './threatmodel.ts';

const SKIP_DIRS = new Set(['.git', 'node_modules']);

export const CACHE_TRADEOFF =
  'A size+mtime cache hit does not re-read file bytes. It is used only when every cached file is still present with the same size and mtime, and no file was added or removed. If size or mtime differs, the content hash is computed again. A change that restores both size and mtime is not detected on the hit path; threatmodel check always hashes content.';

export interface FileStat {
  size: number;
  mtimeMs: number;
}

export interface CacheSkill {
  contentHash: string;
  files: Record<string, FileStat>;
}

export interface InstallCache {
  version: 1;
  note: string;
  skills: Record<string, CacheSkill>;
}

export type CacheUse = 'off' | 'hit' | 'miss';

export interface InstalledRow {
  skill: string;
  path: string;
  status: 'match' | 'stale' | 'unpinned' | 'missing' | 'override';
  recorded: string | null;
  installed: string | null;
  cache: CacheUse;
  detail: string;
}

export interface VerifyInstalledReport {
  tool: string;
  version: string;
  cache: CacheUse;
  cacheTradeoff: string | null;
  results: InstalledRow[];
  overrides: ListedOverride[];
  exitCode: number;
}

export function cacheHit(
  cached: Record<string, FileStat> | undefined,
  current: Record<string, FileStat>,
): boolean {
  if (!cached) return false;
  const keys = Object.keys(current);
  const prev = Object.keys(cached);
  if (keys.length !== prev.length) return false;
  for (const key of keys) {
    const a = current[key];
    const b = cached[key];
    if (!a || !b) return false;
    if (a.size !== b.size || a.mtimeMs !== b.mtimeMs) return false;
  }
  return true;
}

export async function statSkill(root: string): Promise<Record<string, FileStat>> {
  const abs = resolve(root);
  const out: Record<string, FileStat> = {};
  const stack = [abs];
  while (stack.length) {
    const dir = stack.pop() as string;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const path = join(dir, e.name);
      const rel = relative(abs, path).split(sep).join('/');
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) stack.push(path);
        continue;
      }
      if (!e.isFile() && !e.isSymbolicLink()) continue;
      const info = await lstat(path);
      out[rel] = { size: info.size, mtimeMs: info.mtimeMs };
    }
  }
  return out;
}

async function readCache(path: string): Promise<InstallCache> {
  try {
    const parsed = JSON.parse(await readFile(path, 'utf8')) as InstallCache;
    if (parsed && parsed.version === 1 && parsed.skills) return parsed;
  } catch {
    /* a missing or unreadable cache is a miss, not a pass */
  }
  return { version: 1, note: CACHE_TRADEOFF, skills: {} };
}

export async function verifyInstalled(input: {
  model: ThreatModel;
  base: string;
  cachePath?: string;
  now?: Date;
  tool: string;
  version: string;
}): Promise<VerifyInstalledReport> {
  const now = input.now ?? new Date();
  const cache = input.cachePath ? await readCache(input.cachePath) : null;
  let wrote = false;
  const results: InstalledRow[] = [];
  const overrides: ListedOverride[] = [];
  let expiredOverride = false;
  for (const [id, entry] of Object.entries(input.model.skills)) {
    const key = toPosix(entry.path).replace(/^\.\//, '').replace(/\/+$/, '');
    const root = resolve(input.base, key);
    const ov = classifyOverrides(id, entry, now);
    if (ov.active) overrides.push(ov.active);
    for (const row of ov.expired) {
      overrides.push(row);
      expiredOverride = true;
    }
    if (!entry.checkedHash) {
      results.push({
        skill: id,
        path: key,
        status: 'unpinned',
        recorded: null,
        installed: null,
        cache: 'off',
        detail: 'no recorded hash',
      });
      continue;
    }
    let use: CacheUse = input.cachePath ? 'miss' : 'off';
    let installed: string | null = null;
    const stats = input.cachePath ? await statSkill(root) : null;
    const cached = cache?.skills[key];
    if (stats && cacheHit(cached?.files, stats) && cached?.contentHash) {
      use = 'hit';
      installed = cached.contentHash;
    } else {
      const digest = await contentDigest(root).catch(() => ({ digest: null }));
      installed = digest.digest;
      if (stats && cache && installed) {
        cache.skills[key] = { contentHash: installed, files: stats };
        wrote = true;
        use = 'miss';
      }
    }
    const verdict = hashVerdict(id, entry, installed, now);
    let status: InstalledRow['status'] = 'stale';
    if (verdict.status === 'match') status = 'match';
    else if (verdict.status === 'unpinned') status = 'unpinned';
    else if (verdict.status === 'missing') status = 'missing';
    else if (ov.active) status = 'override';
    results.push({
      skill: id,
      path: key,
      status,
      recorded: entry.checkedHash.replace(/^sha256:/i, '').toLowerCase(),
      installed,
      cache: use,
      detail:
        ov.active && verdict.status === 'stale'
          ? `${verdict.detail}; live unpin by ${ov.active.owner} until ${ov.active.expires}`
          : verdict.detail,
    });
  }
  if (cache && input.cachePath && wrote) {
    cache.note = CACHE_TRADEOFF;
    await writeFile(input.cachePath, JSON.stringify(cache, null, 2) + '\n');
  }
  const bad =
    expiredOverride || results.some((r) => r.status === 'stale' || r.status === 'missing');
  const anyCache = results.some((r) => r.cache !== 'off');
  return {
    tool: input.tool,
    version: input.version,
    cache: anyCache
      ? results.some((r) => r.cache === 'hit') && !results.some((r) => r.cache === 'miss')
        ? 'hit'
        : 'miss'
      : 'off',
    cacheTradeoff: input.cachePath ? CACHE_TRADEOFF : null,
    results,
    overrides,
    exitCode: bad ? 2 : 0,
  };
}
