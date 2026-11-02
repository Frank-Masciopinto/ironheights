/**
 * Content digests for the bytes a check actually judged (0.31.0).
 *
 * The shape follows CycloneDX 1.6 hash objects (`alg` + `content`) and SLSA v1
 * resource descriptors (`digest.sha256`). The default scope is the whole skill
 * directory, docs included, and matches `contentDigest` so existing receipts stay
 * comparable. A second digest over executable files is computed only when the caller
 * opts in.
 */
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import { contentDigest } from './receipts.ts';

export type DigestScope = 'skill-directory' | 'executable';
export type FileRole = 'doc' | 'executable' | 'other';

/** CycloneDX 1.6 `hash` plus the SLSA v1 `digest` map, tagged with what it covers. */
export interface ContentDigest {
  alg: 'SHA-256';
  content: string;
  digest: { sha256: string };
  scope: DigestScope;
}

export interface JudgedFile {
  path: string;
  sha256: string;
  role: FileRole;
  /** False for a symlink or an oversize marker: the bytes were not read. */
  opened: boolean;
}

export interface JudgedManifest {
  scope: 'skill-directory';
  algorithm: 'SHA-256';
  files: JudgedFile[];
}

export interface SkillDigests {
  /** Same value `provenance.contentDigest` already carries. */
  directoryDigest: string | null;
  directory: ContentDigest | null;
  /** Present only when the caller opted into executable scope. */
  executable: ContentDigest | null;
  manifest: JudgedManifest;
  files: Record<string, string>;
}

const DOC_EXT = new Set(['.md', '.markdown', '.txt', '.rst', '.adoc', '.html', '.htm']);
const EXEC_EXT = new Set([
  '.js',
  '.mjs',
  '.cjs',
  '.ts',
  '.tsx',
  '.jsx',
  '.py',
  '.sh',
  '.bash',
  '.zsh',
  '.rb',
  '.pl',
  '.php',
  '.go',
  '.rs',
  '.ps1',
  '.bat',
  '.cmd',
  '.exe',
  '.bin',
  '.wasm',
  '.jar',
]);
const DOC_BASENAMES = new Set([
  'readme',
  'license',
  'licence',
  'changelog',
  'notice',
  'authors',
  'copying',
]);

const HEX = /^[0-9a-f]{64}$/;

export function digestObject(content: string, scope: DigestScope): ContentDigest {
  return { alg: 'SHA-256', content, digest: { sha256: content }, scope };
}

export function roleFor(rel: string, head?: Buffer): FileRole {
  const base = rel.split('/').pop() ?? rel;
  const ext = extname(base).toLowerCase();
  const stem = base.toLowerCase().replace(/\.[^.]+$/, '');
  if (EXEC_EXT.has(ext)) return 'executable';
  if (DOC_EXT.has(ext) || DOC_BASENAMES.has(base.toLowerCase()) || DOC_BASENAMES.has(stem))
    return 'doc';
  if (head && head.length >= 2 && head[0] === 0x23 && head[1] === 0x21) return 'executable';
  return 'other';
}

function hashEntries(entries: Array<[string, string]>): string {
  const h = createHash('sha256');
  for (const [path, sha] of entries) h.update(`${path}\0${sha}\n`);
  return h.digest('hex');
}

/**
 * Digest the skill directory. `executable: true` adds a second digest over executable
 * files only; callers that do not pass it do not receive that digest.
 */
export async function skillDigests(
  dir: string,
  opts: { executable?: boolean } = {},
): Promise<SkillDigests> {
  const snap = await contentDigest(dir);
  const files: JudgedFile[] = [];
  for (const [path, sha256] of Object.entries(snap.files).sort(([a], [b]) => a.localeCompare(b))) {
    const opened = HEX.test(sha256);
    let head: Buffer | undefined;
    const ext = extname(path).toLowerCase();
    if (opened && !EXEC_EXT.has(ext) && !DOC_EXT.has(ext)) {
      try {
        const buf = await readFile(resolve(dir, path));
        head = buf.subarray(0, 16);
      } catch {
        head = undefined;
      }
    }
    files.push({ path, sha256, role: roleFor(path, head), opened });
  }
  const directory = snap.digest ? digestObject(snap.digest, 'skill-directory') : null;
  let executable: ContentDigest | null = null;
  if (opts.executable) {
    const exec = files
      .filter((f) => f.role === 'executable' && f.opened)
      .map((f) => [f.path, f.sha256] as [string, string]);
    executable = digestObject(hashEntries(exec), 'executable');
  }
  return {
    directoryDigest: snap.digest,
    directory,
    executable,
    manifest: { scope: 'skill-directory', algorithm: 'SHA-256', files },
    files: snap.files,
  };
}
