import type { ScannedFile } from './types.ts';

/**
 * One skill document: SKILL.md plus the files it names.
 * Line numbers in `lines` are 1-based and line up with `file.text`.
 */
export interface JoinedSkill {
  file: ScannedFile;
  lines: Array<{ file: string; line: number }>;
}

const NAMED_FILE = /\b((?:[\w.+@-]+\/)+[\w.+@-]+\.[\w]{1,8})\b/g;

function skillMarkdown(files: readonly ScannedFile[]): ScannedFile | undefined {
  return files.find((file) => file.relativePath === 'SKILL.md');
}

/** Paths SKILL.md names that are actually in the package. */
export function referencedSkillFiles(
  skill: ScannedFile,
  files: readonly ScannedFile[],
): ScannedFile[] {
  const byPath = new Map(files.map((file) => [file.relativePath.replace(/^\.\//, ''), file]));
  const wanted = new Set<string>();
  for (const match of skill.text.matchAll(NAMED_FILE)) {
    const path = (match[1] ?? '').replace(/^\.\//, '');
    if (!path || path === 'SKILL.md') continue;
    if (byPath.has(path)) wanted.add(path);
  }
  return [...wanted].sort().map((path) => byPath.get(path) as ScannedFile);
}

/**
 * Join SKILL.md with the files it names. A two-signal rule can then match a
 * step in the skill and the step it points at under `references/`.
 * Files that are named but absent stay absent; they are not given empty text.
 */
export function joinSkillReferences(files: readonly ScannedFile[]): JoinedSkill | undefined {
  const skill = skillMarkdown(files);
  if (!skill) return undefined;
  const parts = [skill, ...referencedSkillFiles(skill, files)];
  const lines: Array<{ file: string; line: number }> = [];
  const chunks: string[] = [];
  parts.forEach((part, index) => {
    if (index > 0) {
      chunks.push('');
      lines.push({ file: part.relativePath, line: 1 });
    }
    const body = part.text.replace(/\r\n/g, '\n').replace(/\n$/, '');
    const bodyLines = body.length === 0 ? [''] : body.split('\n');
    bodyLines.forEach((line, lineIndex) => {
      chunks.push(line);
      lines.push({ file: part.relativePath, line: lineIndex + 1 });
    });
  });
  return {
    file: {
      ...skill,
      text: chunks.join('\n'),
      size: chunks.join('\n').length,
    },
    lines,
  };
}
