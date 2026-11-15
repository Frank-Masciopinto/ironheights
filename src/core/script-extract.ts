import type { ScannedFile } from './types.ts';
import { extensionOf } from './filetype.ts';
import { referencedSkillFiles } from './skill-join.ts';

/** Extensions we treat as runnable script files. */
export const SCRIPT_EXTENSIONS = new Set([
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
  'bat',
  'cmd',
]);

const FENCE_OPEN = /^\s{0,3}(```|~~~)([^\n]*)\s*$/;

const LANGUAGE_ALIAS: Record<string, string> = {
  python: 'py',
  python3: 'py',
  py: 'py',
  bash: 'sh',
  sh: 'sh',
  zsh: 'sh',
  shell: 'sh',
  javascript: 'js',
  js: 'js',
  typescript: 'ts',
  ts: 'ts',
  powershell: 'ps1',
  ps1: 'ps1',
  pwsh: 'ps1',
  ruby: 'rb',
  rb: 'rb',
  perl: 'pl',
  php: 'php',
};

/** A fenced block in markdown, with 1-based start line of the body. */
export interface FencedBlock {
  info: string;
  language: string;
  body: string;
  startLine: number;
  endLine: number;
}

/** Fenced code blocks in a markdown/text file. */
function fenceIndent(raw: string): number {
  const m = /^[ \t]*/.exec(raw);
  return m ? m[0].length : 0;
}

export function fencedBlocks(text: string): FencedBlock[] {
  const lines = text.split(/\r?\n/);
  const out: FencedBlock[] = [];
  let cur: { marker: string; info: string; start: number; indent: number; lines: string[] } | null =
    null;
  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i] ?? '';
    const open = FENCE_OPEN.exec(raw);
    if (!open) {
      if (cur) cur.lines.push(raw);
      continue;
    }
    const marker = open[1] ?? '```';
    const info = (open[2] ?? '').trim();
    const indent = fenceIndent(raw);
    // A closer is the same marker, at the same indent, with no info string.
    // An indented ```bash inside a column-0 markdown fence is content, not a closer —
    // treating it as one desynchronizes the rest of the file and turns prose into a
    // "script body".
    if (cur) {
      if (
        raw.trim().startsWith(cur.marker) &&
        indent === cur.indent &&
        info === '' &&
        marker.length >= cur.marker.length
      ) {
        out.push({
          info: cur.info,
          language: languageOf(cur.info),
          body: cur.lines.join('\n'),
          startLine: cur.start,
          endLine: i,
        });
        cur = null;
      } else {
        cur.lines.push(raw);
      }
    } else {
      cur = { marker, info, start: i + 2, indent, lines: [] };
    }
  }
  return out;
}

function languageOf(info: string): string {
  const first = (info.split(/\s+/)[0] ?? '').toLowerCase().replace(/^[^a-z0-9]+/, '');
  const base = first.split(/[/{]/)[0] ?? '';
  return LANGUAGE_ALIAS[base] ?? (SCRIPT_EXTENSIONS.has(base) ? base : '');
}

const PATH_IN_INFO =
  /(?:^|\s|(?:title|file|filename|path)\s*=\s*["'])((?:[\w.+@-]+\/)+[\w.+@-]+\.[\w]{1,8})["']?/i;
const SCRIPT_PATH_TOKEN =
  /\b((?:[\w.+@-]+\/)+[\w.+@-]+\.(?:py|sh|bash|zsh|js|mjs|cjs|ts|tsx|jsx|ps1|rb|pl|php|bat|cmd))\b/i;
const PATH_COMMENT = /^\s*(?:#|\/\/|;)\s*((?:[\w.+@-]+\/)*[\w.+@-]+\.[\w]{1,8})\s*$/;

function scriptPath(candidate: string | undefined): string | undefined {
  if (!candidate) return undefined;
  const path = candidate.replace(/^\.\//, '').replace(/\\/g, '/');
  if (!path || path.includes('..') || path.startsWith('/') || path.includes(':')) return undefined;
  const ext = extensionOf(path);
  if (!SCRIPT_EXTENSIONS.has(ext)) return undefined;
  return path;
}

/**
 * Filename this fence is presented as, when the author names it (info string,
 * "save as scripts/foo.py" on the previous line, or a first-line comment).
 */
export function namedFencePath(
  block: FencedBlock,
  previousLines: readonly string[],
): string | undefined {
  const fromInfo = scriptPath(
    PATH_IN_INFO.exec(block.info)?.[1] ?? SCRIPT_PATH_TOKEN.exec(block.info)?.[1],
  );
  if (fromInfo) return fromInfo;
  // Previous lines only when they explicitly present the fence as a file
  // ("save as scripts/foo.py"), not when a nearby command merely mentions a path.
  const SAVE_AS =
    /(?:save(?:\s+this)?\s+as|write(?:\s+this)?\s+to|create(?:\s+(?:the\s+)?file)?|filename\s*:)\s+[`'"']?((?:[\w.+@-]+\/)+[\w.+@-]+\.(?:py|sh|bash|zsh|js|mjs|cjs|ts|tsx|jsx|ps1|rb|pl|php|bat|cmd))\b/i;
  for (let i = previousLines.length - 1; i >= Math.max(0, previousLines.length - 3); i -= 1) {
    const line = (previousLines[i] ?? '').trim();
    if (!line) continue;
    const fromPrev = scriptPath(SAVE_AS.exec(line)?.[1] ?? undefined);
    if (fromPrev) return fromPrev;
    break;
  }
  const first = block.body.split(/\r?\n/)[0] ?? '';
  return scriptPath(PATH_COMMENT.exec(first)?.[1]);
}

function virtualFile(relativePath: string, text: string): ScannedFile {
  const bytes = new TextEncoder().encode(text);
  return {
    relativePath,
    kind: 'script',
    archive: false,
    size: bytes.length,
    mode: 0o644,
    text,
    head: bytes.subarray(0, Math.min(bytes.length, 256)),
    symlinkOutside: false,
    symlinkLoop: false,
    hidden: false,
  };
}

/**
 * Turn named fenced script bodies in SKILL.md (and other markdown) into virtual
 * shipped script files, when the package does not already contain that path.
 * Existing on-disk files always win.
 */
export function extractNamedScripts(files: readonly ScannedFile[]): ScannedFile[] {
  const existing = new Set(files.map((file) => file.relativePath.replace(/^\.\//, '')));
  const out: ScannedFile[] = [];
  const used = new Set(existing);
  for (const file of files) {
    if (file.kind !== 'markdown' && file.kind !== 'text') continue;
    const lines = file.text.split(/\r?\n/);
    for (const block of fencedBlocks(file.text)) {
      if (!block.body.trim()) continue;
      const before = lines.slice(0, Math.max(0, block.startLine - 2));
      const path = namedFencePath(block, before);
      if (!path || used.has(path)) continue;
      used.add(path);
      out.push(virtualFile(path, block.body));
    }
  }
  return out;
}

/**
 * SKILL.md plus every shipped (or extracted) script, so a two-signal check can
 * see "run scripts/sync.py" next to the script body.
 */
export function joinSkillAndScripts(files: readonly ScannedFile[]): ScannedFile | undefined {
  const skill = files.find((file) => file.relativePath === 'SKILL.md');
  if (!skill) return undefined;
  // Only scripts SKILL.md actually names. Joining every script in the tree would
  // mix unrelated files (a docs example in one folder and a helper in another).
  const named = new Set(referencedSkillFiles(skill, files).map((file) => file.relativePath));
  const scripts = files.filter(
    (file) =>
      file !== skill &&
      named.has(file.relativePath) &&
      (file.kind === 'script' || SCRIPT_EXTENSIONS.has(extensionOf(file.relativePath))),
  );
  if (scripts.length === 0) return undefined;
  const chunks = [skill.text.replace(/\n$/, '')];
  for (const script of scripts) {
    chunks.push(`\n# --- ${script.relativePath} ---\n${script.text.replace(/\n$/, '')}`);
  }
  const text = chunks.join('\n');
  return { ...skill, text, size: text.length };
}
