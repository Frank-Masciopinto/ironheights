/**
 * Guarded installer behind `ironheights install` (0.25.0).
 *
 * Unlike `safe-install`, which scans and then copies the staged folder, this installs only the
 * exact bytes that were checked: every file is hashed, the set must match the lock (or the
 * expected digest from `check_skill`), and the bytes written are the same buffers that were
 * hashed, so nothing can change between check and write. Dependencies are installed only from
 * the pinned closure (`npm ci --ignore-scripts`, `pip --require-hashes --no-deps`), and any
 * difference from the lock's closure refuses the install.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFile, cp, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { dependencyClosure, type ClosureEntry } from '../mcp/closure.ts';
import { contentDigest } from '../mcp/receipts.ts';
import { assertInside } from '../net/safe-path.ts';

export interface SkillLock {
  lockVersion: 1;
  skill: string;
  digest: string;
  files: Record<string, string>;
  closure: Array<Pick<ClosureEntry, 'name' | 'version' | 'integrity' | 'source'>>;
  createdAt?: string;
}

export interface InstallCheck {
  ok: boolean;
  digest: string | null;
  problems: string[];
  files: Record<string, string>;
  closure: ClosureEntry[];
}

const closureKey = (c: Pick<ClosureEntry, 'name' | 'version' | 'integrity'>) =>
  `${c.name}@${c.version ?? '?'}#${c.integrity ?? 'none'}`;

export async function buildLock(dir: string, skill: string, now = new Date()): Promise<SkillLock> {
  const d = await contentDigest(dir);
  const c = await dependencyClosure(dir);
  if (!d.digest) throw new Error(`no files in ${dir}`);
  return {
    lockVersion: 1,
    skill,
    digest: d.digest,
    files: d.files,
    closure: c.entries.map(({ name, version, integrity, source }) => ({
      name,
      version,
      integrity,
      source,
    })),
    createdAt: now.toISOString(),
  };
}

/** Compare a staged folder against a lock and/or an expected digest. */
export async function checkAgainstLock(
  staged: string,
  lock?: SkillLock,
  expectDigest?: string,
): Promise<InstallCheck> {
  const problems: string[] = [];
  const d = await contentDigest(staged);
  const c = await dependencyClosure(staged);
  for (const [p, h] of Object.entries(d.files))
    if (h === 'symlink' || h.startsWith('oversize:'))
      problems.push(`${p}: ${h === 'symlink' ? 'symlink' : 'file too large to hash'}`);
  if (!d.digest) problems.push('no files');
  if (expectDigest && d.digest !== expectDigest)
    problems.push(`digest ${d.digest ?? 'none'} does not match the checked digest ${expectDigest}`);
  if (lock) {
    if (lock.digest !== d.digest)
      problems.push(`digest ${d.digest ?? 'none'} does not match the lock ${lock.digest}`);
    for (const [p, h] of Object.entries(lock.files)) {
      if (!(p in d.files)) problems.push(`missing ${p}`);
      else if (d.files[p] !== h) problems.push(`changed ${p}`);
    }
    for (const p of Object.keys(d.files))
      if (!(p in lock.files)) problems.push(`extra ${p} (not in the lock)`);
    const want = new Set(lock.closure.map(closureKey));
    const got = new Set(c.entries.map(closureKey));
    for (const k of want) if (!got.has(k)) problems.push(`closure: ${k} missing or changed`);
    for (const k of got) if (!want.has(k)) problems.push(`closure: ${k} not in the lock`);
  }
  if (!c.complete) for (const u of c.unpinned) problems.push(`unpinned dependency ${u}`);
  return {
    ok: problems.length === 0,
    digest: d.digest,
    problems,
    files: d.files,
    closure: c.entries,
  };
}

export type DepsExec = (
  cmd: string,
  args: string[],
  cwd: string,
) => { status: number | null; stderr?: string };
const defaultDepsExec: DepsExec = (cmd, args, cwd) => {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 600_000 });
  return { status: r.status, stderr: r.stderr };
};

/** The exact commands that install the pinned closure and nothing else. */
export function depsCommands(files: string[]): Array<[string, string[]]> {
  const cmds: Array<[string, string[]]> = [];
  if (files.includes('package-lock.json'))
    cmds.push(['npm', ['ci', '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund']]);
  if (files.includes('requirements.txt'))
    cmds.push([
      'python3',
      [
        '-m',
        'pip',
        'install',
        '--require-hashes',
        '--no-deps',
        '--only-binary=:all:',
        '--target',
        '.deps',
        '-r',
        'requirements.txt',
      ],
    ]);
  return cmds;
}

export interface GuardedInstallOptions {
  staged: string;
  destParent: string;
  slug: string;
  check: InstallCheck;
  withDeps?: boolean;
  home: string;
  exec?: DepsExec;
  now?: Date;
}

/**
 * Write the verified bytes into destParent/slug. Every file is re-read and re-hashed right
 * before writing; the buffer written is the buffer hashed. An existing install is moved aside
 * and restored if anything fails.
 */
export async function guardedInstall(
  o: GuardedInstallOptions,
): Promise<{ dest: string; files: number; deps: string[] }> {
  if (!o.check.ok) throw new Error('refusing: the check did not pass');
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(o.slug)) throw new Error('refusing skill name');
  const parent = resolve(o.destParent);
  await mkdir(parent, { recursive: true });
  const dest = join(parent, o.slug);
  assertInside(dest, parent);
  const tmp = await mkdtemp(join(parent, `.${o.slug}.ih-install-`));
  let backup: string | null = null;
  try {
    for (const [rel, want] of Object.entries(o.check.files)) {
      const src = join(o.staged, rel);
      const out = join(tmp, rel);
      assertInside(out, tmp);
      const info = await lstat(src);
      if (!info.isFile()) throw new Error(`refusing: ${rel} is no longer a regular file`);
      const buf = await readFile(src);
      const got = createHash('sha256').update(buf).digest('hex');
      if (got !== want) throw new Error(`refusing: ${rel} changed after the check`);
      await mkdir(dirname(out), { recursive: true });
      await writeFile(out, buf, { mode: 0o644 });
    }
    const deps: string[] = [];
    if (o.withDeps) {
      const exec = o.exec ?? defaultDepsExec;
      for (const [cmd, args] of depsCommands(Object.keys(o.check.files))) {
        const r = exec(cmd, args, tmp);
        if (r.status !== 0)
          throw new Error(
            `refusing: ${cmd} ${args.join(' ')} failed${r.stderr ? `: ${r.stderr.trim().split('\n').pop()}` : ''}`,
          );
        deps.push(`${cmd} ${args.join(' ')}`);
      }
    }
    const exists = await lstat(dest).then(
      (s) => s,
      () => null,
    );
    if (exists?.isSymbolicLink()) throw new Error('refusing to replace a symlink');
    if (exists) {
      backup = join(
        o.home,
        'install-backups',
        `${(o.now ?? new Date()).toISOString().replace(/[:.]/g, '-')}-${o.slug}`,
      );
      await mkdir(dirname(backup), { recursive: true, mode: 0o700 });
      await cp(dest, backup, { recursive: true });
      await rm(dest, { recursive: true, force: true });
    }
    const { rename } = await import('node:fs/promises');
    await rename(tmp, dest);
    await mkdir(o.home, { recursive: true, mode: 0o700 });
    await appendFile(
      join(o.home, 'installs.jsonl'),
      JSON.stringify({
        at: (o.now ?? new Date()).toISOString(),
        slug: o.slug,
        dest,
        digest: o.check.digest,
        files: Object.keys(o.check.files).length,
        deps,
      }) + '\n',
    );
    return { dest, files: Object.keys(o.check.files).length, deps };
  } catch (e) {
    await rm(tmp, { recursive: true, force: true });
    if (backup) {
      const has = await lstat(dest).then(
        () => true,
        () => false,
      );
      if (!has) await cp(backup, dest, { recursive: true });
    }
    throw e;
  }
}

export async function stageLocal(dir: string): Promise<string> {
  const t = await mkdtemp(join(tmpdir(), 'ih-install-'));
  const s = join(t, 'skill');
  await cp(resolve(dir), s, { recursive: true, verbatimSymlinks: true });
  return s;
}
