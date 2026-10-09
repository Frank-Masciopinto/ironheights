import { createHash } from 'node:crypto';
import { lstat, readdir, readlink, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, join, relative, sep } from 'node:path';
import { createReadStream } from 'node:fs';
import { z } from 'zod';
import { UsageError } from '../core/errors.ts';
import type { Baseline, FileRecord } from '../core/types.ts';
import { writeAtomic } from '../util/atomic.ts';
import { TOOL_VERSION } from '../version.ts';

export const BaselineSchema = z
  .object({
    version: z.literal(1),
    createdAt: z.string(),
    toolVersion: z.string(),
    roots: z.array(z.string()),
    files: z.record(
      z.string(),
      z
        .object({
          sha256: z.string(),
          size: z.number().int().nonnegative(),
          mode: z.number().int().nonnegative(),
        })
        .strict(),
    ),
    treeHash: z.string(),
  })
  .strict();

export function baselinePath(home: string): string {
  return join(home, 'baseline.json');
}

export function toPortablePath(abs: string): string {
  const home = homedir();
  if (abs === home) return '~';
  if (abs.startsWith(home + sep)) return `~${abs.slice(home.length)}`;
  return abs;
}

export function fromPortablePath(portable: string): string {
  if (portable === '~') return homedir();
  if (portable.startsWith('~/')) return join(homedir(), portable.slice(2));
  return portable;
}

export async function createBaseline(roots: string[], now = new Date()): Promise<Baseline> {
  const files: Record<string, FileRecord> = {};
  const portableRoots: string[] = [];
  for (const root of roots) {
    let info;
    try {
      info = await lstat(root);
    } catch {
      continue;
    }
    portableRoots.push(toPortablePath(root));
    if (info.isSymbolicLink()) {
      files[toPortablePath(root)] = await recordLink(root, info.mode, info.size);
      continue;
    }
    if (info.isFile()) {
      files[toPortablePath(root)] = await recordFile(root, info.mode, info.size);
      continue;
    }
    if (info.isDirectory()) {
      await collectDir(root, root, files);
    }
  }
  return {
    version: 1,
    createdAt: now.toISOString(),
    toolVersion: TOOL_VERSION,
    roots: portableRoots,
    files,
    treeHash: computeTreeHash(files),
  };
}

export async function writeBaseline(filePath: string, baseline: Baseline): Promise<void> {
  await writeAtomic(filePath, `${JSON.stringify(baseline, null, 2)}\n`, 0o600);
}

export function parseBaseline(raw: string): Baseline {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new UsageError('baseline file is not valid JSON');
  }
  const result = BaselineSchema.safeParse(parsed);
  if (!result.success) throw new UsageError('baseline file does not match the expected schema');
  return result.data;
}

export function computeTreeHash(files: Record<string, FileRecord>): string {
  const lines = Object.keys(files)
    .sort()
    .map((key) => `${key}\0${files[key]?.sha256 ?? ''}`);
  return createHash('sha256').update(lines.join('\n')).digest('hex');
}

export function baselineIsTampered(baseline: Baseline): boolean {
  return computeTreeHash(baseline.files) !== baseline.treeHash;
}

async function collectDir(
  root: string,
  dir: string,
  files: Record<string, FileRecord>,
): Promise<void> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.name === '.git' || entry.name === 'node_modules') continue;
    const abs = join(dir, entry.name);
    const rel = relative(root, abs);
    if (rel.startsWith('..') || rel.split(sep).includes('..')) continue;
    const key = toPortablePath(abs);
    let info;
    try {
      info = await lstat(abs);
    } catch {
      continue;
    }
    if (info.isSymbolicLink()) {
      files[key] = await recordLink(abs, info.mode, info.size);
      continue;
    }
    if (info.isDirectory()) {
      await collectDir(root, abs, files);
      continue;
    }
    if (info.isFile()) files[key] = await recordFile(abs, info.mode, info.size);
  }
}

async function recordFile(abs: string, mode: number, size: number): Promise<FileRecord> {
  return { sha256: await sha256File(abs), size, mode: mode & 0o777 };
}

async function recordLink(abs: string, mode: number, size: number): Promise<FileRecord> {
  let target = '';
  try {
    target = await readlink(abs);
  } catch {
    target = '';
  }
  const linkStat = await stat(abs).catch(() => undefined);
  return {
    sha256: createHash('sha256').update(target).digest('hex'),
    size: linkStat?.size ?? size,
    mode: mode & 0o777,
  };
}

export function sha256File(abs: string): Promise<string> {
  return new Promise((resolveHash, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(abs);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolveHash(hash.digest('hex')));
  });
}

export function rootLabel(root: string): string {
  return basename(root);
}
