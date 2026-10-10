import { lstat, mkdir, readdir, readFile, realpath, rename, rm } from 'node:fs/promises';
import { join, relative, resolve, sep } from 'node:path';
import { UsageError } from '../core/errors.ts';
import { stripLongPath } from '../util/paths.ts';
import { assertInside, pathContainsSymlink, writeRegularFileInside } from './safe-path.ts';

export interface InstallResult {
  dest: string;
  backup?: string;
}

/**
 * Copy a staged skill into destParent/slug. An existing directory is moved
 * aside first and restored if the copy fails. Symlinks are not copied and
 * are not replaced.
 */
export async function installStagedSkill(options: {
  stagedDir: string;
  destParent: string;
  slug: string;
  backupRoot: string;
  now?: Date;
  copyImpl?: (source: string, dest: string) => Promise<void>;
}): Promise<InstallResult> {
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(options.slug)) throw new UsageError('refusing skill name');
  const parent = await assertRealDirectory(options.destParent);
  const dest = join(parent, options.slug);
  assertInside(dest, parent);
  const stagedReal = await realpath(options.stagedDir);
  if (stagedReal === dest || dest.startsWith(`${stagedReal}/`)) {
    throw new UsageError('refusing to install a directory into itself');
  }
  let existing;
  try {
    existing = await lstat(dest);
  } catch (error) {
    if (!isEnoent(error)) throw error;
  }
  if (existing?.isSymbolicLink()) throw new UsageError('refusing to replace a symlink');
  let backup: string | undefined;
  if (existing) {
    await mkdir(options.backupRoot, { recursive: true, mode: 0o700 });
    const stamp = (options.now ?? new Date()).toISOString().replace(/[:.]/g, '-');
    backup = join(options.backupRoot, `${stamp}-${options.slug}`);
    await rename(dest, backup);
  }
  try {
    if (options.copyImpl) await options.copyImpl(stagedReal, dest);
    else await copyRegularTree(stagedReal, dest);
  } catch (error) {
    await rm(dest, { recursive: true, force: true });
    if (backup) await rename(backup, dest);
    throw error;
  }
  return { dest, ...(backup ? { backup } : {}) };
}

export async function copyRegularTree(source: string, dest: string): Promise<void> {
  const realSource = await realpath(source);
  await mkdir(dest, { recursive: true, mode: 0o700 });
  const realDest = await realpath(dest);
  if (
    realDest === realSource ||
    realDest.startsWith(`${realSource}/`) ||
    realSource.startsWith(`${realDest}/`)
  ) {
    throw new UsageError('refusing to copy a directory into itself');
  }
  await copyChildren(realSource, realDest, realSource, 0);
}

async function copyChildren(
  source: string,
  destRoot: string,
  sourceRoot: string,
  depth: number,
): Promise<void> {
  if (depth > 20) throw new UsageError('refusing skill file path deeper than 20');
  const entries = await readdir(source, { withFileTypes: true });
  for (const entry of entries) {
    const from = join(source, entry.name);
    const info = await lstat(from);
    if (info.isSymbolicLink()) throw new UsageError(`refusing symlink: ${entry.name}`);
    if (info.isDirectory()) {
      await copyChildren(from, destRoot, sourceRoot, depth + 1);
      continue;
    }
    if (!info.isFile()) throw new UsageError(`refusing special file: ${entry.name}`);
    const relativePath = relative(sourceRoot, from).split(sep).join('/');
    const bytes = new Uint8Array(await readFile(from));
    await writeRegularFileInside(destRoot, relativePath, bytes, 20);
  }
}

async function assertRealDirectory(parent: string): Promise<string> {
  const resolved = resolve(parent);
  await mkdir(resolved, { recursive: true, mode: 0o700 });
  let info;
  try {
    info = await lstat(resolved);
  } catch (error) {
    if (!isEnoent(error)) throw error;
    throw new UsageError('skills directory was not created');
  }
  if (info.isSymbolicLink()) throw new UsageError('refusing skills directory that is a symlink');
  if (await pathContainsSymlink(resolved)) {
    throw new UsageError('refusing skills directory that is reached through a symlink');
  }
  return stripLongPath(await realpath(resolved));
}

function isEnoent(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}
