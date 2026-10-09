import { readFile } from 'node:fs/promises';
import { emptyConfig } from '../src/core/config.ts';
import { classifyFile } from '../src/core/filetype.ts';
import type { ResolvedConfig, ScannedFile, ScanContext } from '../src/core/types.ts';

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
