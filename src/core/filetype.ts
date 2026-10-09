import type { FileKind } from './types.ts';

const MARKDOWN = new Set(['md', 'mdx', 'markdown']);
const SCRIPT = new Set([
  'js',
  'mjs',
  'cjs',
  'ts',
  'tsx',
  'jsx',
  'py',
  'sh',
  'bash',
  'zsh',
  'ps1',
  'rb',
  'pl',
  'php',
]);
const CONFIG = new Set(['json', 'json5', 'yml', 'yaml', 'toml', 'ini', 'env', 'conf']);
const EXEC_EXT = new Set(['exe', 'dll', 'msi', 'dmg', 'pkg', 'so', 'dylib', 'apk']);
const ARCHIVE_EXT = new Set(['zip', 'tar', 'gz', 'tgz', '7z', 'rar', 'bz2', 'xz', 'jar']);

export function extensionOf(fileName: string): string {
  const base = fileName.split(/[/\\]/).pop() ?? fileName;
  const lower = base.toLowerCase();
  if (lower.endsWith('.tar.gz')) return 'gz';
  const dot = lower.lastIndexOf('.');
  if (dot <= 0) return '';
  return lower.slice(dot + 1);
}

export function classifyFile(
  fileName: string,
  head: Uint8Array,
): { kind: FileKind; archive: boolean } {
  const ext = extensionOf(fileName);
  const archive = ARCHIVE_EXT.has(ext) || isArchiveMagic(head);
  const executable = EXEC_EXT.has(ext) || isExecutableMagic(head);
  if (executable || archive || looksBinary(head)) {
    return { kind: 'binary', archive };
  }
  if (MARKDOWN.has(ext)) return { kind: 'markdown', archive: false };
  if (SCRIPT.has(ext)) return { kind: 'script', archive: false };
  if (CONFIG.has(ext)) return { kind: 'config', archive: false };
  return { kind: 'text', archive: false };
}

export function isExecutableMagic(head: Uint8Array): boolean {
  if (
    head.length >= 4 &&
    head[0] === 0x7f &&
    head[1] === 0x45 &&
    head[2] === 0x4c &&
    head[3] === 0x46
  ) {
    return true;
  }
  if (head.length >= 2 && head[0] === 0x4d && head[1] === 0x5a) return true;
  if (head.length < 4) return false;
  const magic =
    ((head[0] ?? 0) << 24) | ((head[1] ?? 0) << 16) | ((head[2] ?? 0) << 8) | (head[3] ?? 0);
  return (
    magic === 0xfeedface ||
    magic === 0xfeedfacf ||
    magic === 0xcefaedfe ||
    magic === 0xcffaedfe ||
    magic === 0xcafebabe ||
    magic === 0xcafebabf
  );
}

export function isArchiveMagic(head: Uint8Array): boolean {
  if (
    head.length >= 4 &&
    head[0] === 0x50 &&
    head[1] === 0x4b &&
    (head[2] === 0x03 || head[2] === 0x05 || head[2] === 0x07)
  ) {
    return true;
  }
  if (head.length >= 2 && head[0] === 0x1f && head[1] === 0x8b) return true;
  if (
    head.length >= 6 &&
    head[0] === 0x37 &&
    head[1] === 0x7a &&
    head[2] === 0xbc &&
    head[3] === 0xaf &&
    head[4] === 0x27 &&
    head[5] === 0x1c
  ) {
    return true;
  }
  if (
    head.length >= 4 &&
    head[0] === 0x52 &&
    head[1] === 0x61 &&
    head[2] === 0x72 &&
    head[3] === 0x21
  )
    return true;
  if (head.length >= 3 && head[0] === 0x42 && head[1] === 0x5a && head[2] === 0x68) return true;
  return false;
}

export function zipEncrypted(head: Uint8Array): boolean {
  if (head.length < 8 || head[0] !== 0x50 || head[1] !== 0x4b) return false;
  const flags = (head[6] ?? 0) | ((head[7] ?? 0) << 8);
  return (flags & 0x1) === 0x1;
}

function looksBinary(head: Uint8Array): boolean {
  const sample = head.subarray(0, Math.min(head.length, 8000));
  for (const byte of sample) {
    if (byte === 0) return true;
  }
  return false;
}

export function decodeText(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}
