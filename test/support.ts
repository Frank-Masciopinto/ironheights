import { readFile, stat, symlink } from 'node:fs/promises';
import { emptyConfig } from '../src/core/config.ts';
import { classifyFile } from '../src/core/filetype.ts';
import type { ResolvedConfig, ScannedFile, ScanContext } from '../src/core/types.ts';

/** Create a symlink, or a directory junction when Windows denies file symlinks. Returns false when a file link cannot be created. */
export async function linkPath(target: string, link: string): Promise<boolean> {
  const info = await stat(target);
  const type = info.isDirectory() ? 'dir' : 'file';
  try {
    await symlink(target, link, type);
    return true;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    const denied = code === 'EPERM' || code === 'ENOTSUP' || code === 'EACCES';
    if (process.platform === 'win32' && denied && info.isDirectory()) {
      await symlink(target, link, 'junction');
      return true;
    }
    if (process.platform === 'win32' && denied) return false;
    throw error;
  }
}

export function context(
  config: ResolvedConfig = emptyConfig(),
  skillDirName = 'benign',
): ScanContext {
  return { config, root: '/tmp/skill', skillDirName, skillAllowDomains: [] };
}

export async function scannedFromFile(path: string, relativePath: string): Promise<ScannedFile> {
  const bytes = new Uint8Array(await readFile(path));
  const head = bytes.subarray(0, Math.min(bytes.length, 8192));
  const classified = classifyFile(relativePath, head);
  const binary = classified.kind === 'binary';
  return {
    relativePath,
    kind: classified.kind,
    archive: classified.archive,
    size: bytes.length,
    mode: 0o644,
    text: binary ? '' : new TextDecoder('utf-8', { fatal: false }).decode(bytes),
    head,
    symlinkOutside: false,
    symlinkLoop: false,
    hidden: relativePath.split('/').pop()?.startsWith('.') ?? false,
  };
}

export function scannedText(
  relativePath: string,
  text: string,
  kind?: ScannedFile['kind'],
): ScannedFile {
  const bytes = new TextEncoder().encode(text);
  const classified = classifyFile(relativePath, bytes);
  return {
    relativePath,
    kind: kind ?? classified.kind,
    archive: classified.archive,
    size: bytes.length,
    mode: 0o644,
    text,
    head: bytes.subarray(0, Math.min(bytes.length, 64)),
    symlinkOutside: false,
    symlinkLoop: false,
    hidden: false,
  };
}
