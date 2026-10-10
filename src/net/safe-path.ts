import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath } from 'node:fs/promises';
import { isAbsolute, join, parse, relative, sep } from 'node:path';
import { UsageError } from '../core/errors.ts';
import { clip } from '../util/text.ts';

const NOFOLLOW = typeof constants.O_NOFOLLOW === 'number' ? constants.O_NOFOLLOW : 0;
const MAX_PATH = 512;
const MAX_SEGMENT = 255;
const CONTROLS = new RegExp(
  `[${String.fromCharCode(0)}-${String.fromCharCode(31)}${String.fromCharCode(127)}]`,
);

/**
 * True when a path component is a symlink or a Windows junction.
 * An 8.3 short name is not a symlink, so a realpath string that only
 * differs by that name is still the same directory.
 */
export async function pathContainsSymlink(absPath: string): Promise<boolean> {
  const { root } = parse(absPath);
  let current = root;
  const parts = absPath
    .slice(root.length)
    .split(sep)
    .filter((part) => part.length > 0);
  for (const part of parts) {
    current = join(current, part);
    const info = await lstat(current);
    if (info.isSymbolicLink()) return true;
  }
  return false;
}

/** Reject absolute paths, empty segments, and `..` before any write. */
export function safeRelativeParts(input: string, maxDepth: number): string[] {
  if (input.length === 0 || input.length > MAX_PATH || CONTROLS.test(input)) {
    throw new UsageError('refusing skill file path');
  }
  if (input.startsWith('/') || input.startsWith('\\') || /^[A-Za-z]:[\\/]/.test(input)) {
    throw new UsageError(`refusing absolute path: ${clip(input, 80)}`);
  }
  const parts = input.split(/[/\\]/);
  if (parts.length === 0 || parts.length - 1 > maxDepth) {
    throw new UsageError(`refusing skill file path deeper than ${maxDepth}`);
  }
  for (const part of parts) {
    if (
      part === '' ||
      part === '.' ||
      part === '..' ||
      part.length > MAX_SEGMENT ||
      part !== part.trim()
    ) {
      throw new UsageError(`refusing path traversal: ${clip(input, 80)}`);
    }
  }
  return parts;
}

export function assertInside(candidate: string, root: string): void {
  const rel = relative(root, candidate);
  if (rel.startsWith(`..${sep}`) || rel === '..' || isAbsolute(rel)) {
    throw new UsageError('refusing path that escapes the destination directory');
  }
}

/**
 * Write a new regular file under root. Symlinks are refused. The file is mode
 * 0600 and is not executable. Nothing is decompressed.
 */
export async function writeRegularFileInside(
  root: string,
  relativePath: string,
  bytes: Uint8Array,
  maxDepth: number,
): Promise<void> {
  const parts = safeRelativeParts(relativePath, maxDepth);
  const realRoot = await realpath(root);
  let current = realRoot;
  for (let index = 0; index < parts.length - 1; index += 1) {
    const part = parts[index];
    if (part === undefined) throw new UsageError('refusing skill file path');
    const next = join(current, part);
    let info;
    try {
      info = await lstat(next);
    } catch (error) {
      if (!isEnoent(error)) throw error;
      await mkdir(next, { mode: 0o700 });
      info = await lstat(next);
    }
    if (info.isSymbolicLink()) throw new UsageError(`refusing symlink: ${clip(relativePath, 80)}`);
    if (!info.isDirectory())
      throw new UsageError(`refusing non-directory: ${clip(relativePath, 80)}`);
    const realNext = await realpath(next);
    assertInside(realNext, realRoot);
    current = realNext;
  }
  const name = parts[parts.length - 1];
  if (name === undefined) throw new UsageError('refusing skill file path');
  const dest = join(current, name);
  let existing;
  try {
    existing = await lstat(dest);
  } catch (error) {
    if (!isEnoent(error)) throw error;
  }
  if (existing?.isSymbolicLink())
    throw new UsageError(`refusing symlink: ${clip(relativePath, 80)}`);
  if (existing) throw new UsageError(`refusing to overwrite: ${clip(relativePath, 80)}`);
  const handle = await open(
    dest,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW,
    0o600,
  );
  try {
    await handle.writeFile(bytes);
    await handle.chmod(0o600);
  } finally {
    await handle.close();
  }
  assertInside(await realpath(dest), realRoot);
}

function isEnoent(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}
