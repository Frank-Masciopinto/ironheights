import { lstat, open, readdir, realpath, stat } from 'node:fs/promises';
import { relative, resolve, sep } from 'node:path';
import { isInsideRoot, normalizeForCompare, stripLongPath } from '../util/paths.ts';
import picomatch from 'picomatch';
import { directorySkip, OPAQUE_DIRECTORY_NAMES } from './directories.ts';
import { classifyFile, decodeText } from './filetype.ts';
import type { IgnoreDir, Limits, ScannedFile, SkippedDirectory, SkippedFile } from './types.ts';

export interface WalkResult {
  files: ScannedFile[];
  skipped: SkippedFile[];
  skippedDirectories: SkippedDirectory[];
}

export async function walkSkill(
  root: string,
  limits: Limits,
  ignoreGlobs: string[],
  ignoreDirs: readonly IgnoreDir[] = [],
): Promise<WalkResult> {
  const realRoot = stripLongPath(await realpath(root));
  const ignore = ignoreGlobs.length === 0 ? () => false : picomatch(ignoreGlobs, { dot: true });
  const files: ScannedFile[] = [];
  const skipped: SkippedFile[] = [];
  const skippedDirectories: SkippedDirectory[] = [];
  let truncated = false;

  async function visit(dir: string, depth: number, seen: Set<string>): Promise<void> {
    if (truncated) return;
    if (depth > limits.maxDepth) {
      skipped.push({
        file: display(realRoot, dir),
        reason: `directory depth exceeds ${limits.maxDepth}`,
      });
      return;
    }
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      skipped.push({ file: display(realRoot, dir), reason: 'unreadable directory' });
      return;
    }
    for (const entry of entries) {
      if (truncated) return;
      const abs = resolve(dir, entry.name);
      const rel = relative(realRoot, abs);
      if (rel.startsWith('..') || rel.split(sep).includes('..')) {
        skipped.push({ file: sanitize(rel), reason: 'path escapes the scan root' });
        continue;
      }
      const portable = rel.split(sep).join('/');
      if (OPAQUE_DIRECTORY_NAMES.has(entry.name)) {
        let opaqueInfo;
        try {
          opaqueInfo = await lstat(abs);
        } catch {
          skipped.push({ file: portable, reason: 'unreadable file' });
          continue;
        }
        if (opaqueInfo.isDirectory() || opaqueInfo.isSymbolicLink()) {
          const recorded = directorySkip(portable, entry.name, ignoreDirs);
          if (recorded) skippedDirectories.push(recorded);
          continue;
        }
      }
      if (ignore(portable)) continue;
      if (files.length >= limits.maxFiles) {
        truncated = true;
        skipped.push({ file: portable, reason: `file limit of ${limits.maxFiles} reached` });
        return;
      }
      let info;
      try {
        info = await lstat(abs);
      } catch {
        skipped.push({ file: portable, reason: 'unreadable file' });
        continue;
      }
      if (info.isSymbolicLink()) {
        await visitLink(abs, portable, depth, seen);
        continue;
      }
      if (info.isDirectory()) {
        await visit(abs, depth + 1, seen);
        continue;
      }
      if (!info.isFile()) continue;
      await addFile(abs, portable, info.mode, info.size, {
        symlinkOutside: false,
        symlinkLoop: false,
      });
    }
  }

  async function visitLink(
    abs: string,
    portable: string,
    depth: number,
    seen: Set<string>,
  ): Promise<void> {
    let target: string;
    try {
      target = stripLongPath(await realpath(abs));
    } catch {
      skipped.push({ file: portable, reason: 'broken symlink' });
      return;
    }
    const outside = !isInsideRoot(realRoot, target);
    if (outside) {
      await addFile(abs, portable, (await lstat(abs)).mode, 0, {
        symlinkOutside: true,
        symlinkLoop: false,
        symlinkTarget: target,
        forceEmpty: true,
      });
      return;
    }
    const seenKey = normalizeForCompare(target);
    if (seen.has(seenKey)) {
      await addFile(abs, portable, (await lstat(abs)).mode, 0, {
        symlinkOutside: false,
        symlinkLoop: true,
        symlinkTarget: target,
        forceEmpty: true,
      });
      return;
    }
    seen.add(seenKey);
    let targetStat;
    try {
      targetStat = await stat(abs);
    } catch {
      skipped.push({ file: portable, reason: 'unreadable symlink target' });
      return;
    }
    if (targetStat.isDirectory()) {
      await visit(abs, depth + 1, seen);
      return;
    }
    if (targetStat.isFile()) {
      await addFile(abs, portable, targetStat.mode, targetStat.size, {
        symlinkOutside: false,
        symlinkLoop: false,
        symlinkTarget: target,
      });
    }
  }

  async function addFile(
    abs: string,
    portable: string,
    mode: number,
    size: number,
    link: {
      symlinkOutside: boolean;
      symlinkLoop: boolean;
      symlinkTarget?: string;
      forceEmpty?: boolean;
    },
  ): Promise<void> {
    if (size > limits.maxFileBytes) {
      skipped.push({ file: portable, reason: `file exceeds ${limits.maxFileBytes} bytes` });
      return;
    }
    const head = link.forceEmpty ? new Uint8Array() : await readHead(abs, size);
    if (!head) {
      skipped.push({ file: portable, reason: 'unreadable file' });
      return;
    }
    const classified = classifyFile(portable, head);
    const binary = classified.kind === 'binary';
    const bytes = link.forceEmpty || binary ? new Uint8Array() : await readAll(abs, size);
    if (!bytes) {
      skipped.push({ file: portable, reason: 'unreadable file' });
      return;
    }
    const text = link.forceEmpty || binary ? '' : decodeText(bytes);
    const base = portable.split('/').pop() ?? portable;
    files.push({
      relativePath: portable,
      kind: classified.kind,
      archive: classified.archive,
      size,
      mode: mode & 0o777,
      text,
      head,
      symlinkOutside: link.symlinkOutside,
      symlinkLoop: link.symlinkLoop,
      ...(link.symlinkTarget ? { symlinkTarget: link.symlinkTarget } : {}),
      hidden: base.startsWith('.') && base !== '.' && base !== '..',
    });
  }

  await visit(realRoot, 0, new Set([normalizeForCompare(realRoot)]));
  return { files, skipped, skippedDirectories };
}

async function readHead(abs: string, size: number): Promise<Uint8Array | undefined> {
  try {
    const handle = await open(abs, 'r');
    try {
      const length = Math.min(size, 8192);
      const buf = Buffer.alloc(length);
      await handle.read(buf, 0, length, 0);
      return buf.subarray(0, length);
    } finally {
      await handle.close();
    }
  } catch {
    return undefined;
  }
}

async function readAll(abs: string, size: number): Promise<Uint8Array | undefined> {
  try {
    const handle = await open(abs, 'r');
    try {
      const buf = Buffer.alloc(size);
      await handle.read(buf, 0, size, 0);
      return buf;
    } finally {
      await handle.close();
    }
  } catch {
    return undefined;
  }
}

function display(root: string, dir: string): string {
  const rel = relative(root, dir);
  return rel === '' ? '.' : rel.split(sep).join('/');
}

function sanitize(value: string): string {
  return value.replace(
    new RegExp(
      `[${String.fromCharCode(0)}-${String.fromCharCode(31)}${String.fromCharCode(127)}]`,
      'g',
    ),
    '',
  );
}
