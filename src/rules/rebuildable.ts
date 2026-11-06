import { existsSync, readdirSync, statSync } from 'node:fs';
import { join, posix } from 'node:path';
import { isSkillFileName } from '../core/skill-file.ts';
import type { Finding, Rule, ScannedFile, ScanContext } from '../core/types.ts';
import { createFinding, pushUnique } from './helpers.ts';
import { scriptReferences } from './missing-file.ts';

/**
 * A skill the scanner treats as complete has to be rebuildable: a SKILL.md with
 * concrete steps, and every local script that SKILL.md runs present in the folder.
 * A placeholder gist or a rulebook stub is not a skill. A one-file extract is not
 * proof that a sibling path is missing from a published package, so a lone SKILL.md
 * keeps the IH-REF-001 note and does not become incomplete for that path.
 */

const META_STUB =
  /\b(?:placeholder gist|rulebook[- ]stub|meta[- ]rulebook|only meta-instructions|meta-instructions only|no concrete skill text|this gist is a placeholder)\b/i;

const CONCRETE =
  /```[^\n]*\n[^\n]{8,}|\b(?:summarize|format|convert|proofread|send|create|update|search|list|print) (?:the |a |an |every )?(?:user'?s? )?(?:invoice|file|document|notes|message|report|input)\b/i;

type GapKind = 'missing-skill-md' | 'missing-referenced-file' | 'meta-stub';

function gapMessage(kind: GapKind, detail: string): string {
  switch (kind) {
    case 'missing-skill-md':
      return `No SKILL.md in this folder (${detail}). A complete scan needs the skill file. This package is not rebuildable, so the verdict is incomplete.`;
    case 'missing-referenced-file':
      return `SKILL.md runs ${detail}, and that file is not in this package. The bytes were not scanned. This package is not rebuildable, so the verdict is incomplete.`;
    case 'meta-stub':
      return 'SKILL.md is only a placeholder or a rulebook stub. It has no concrete skill text. This package is not rebuildable, so the verdict is incomplete.';
    default: {
      const neverKind: never = kind;
      return neverKind;
    }
  }
}

const REMEDIATION =
  'Ship a SKILL.md that states the concrete steps, and include every local file those steps run. A placeholder gist, a rulebook stub, or a folder with no skill file is not a finished skill.';

export const meta005: Rule = {
  id: 'IH-META-005',
  title: 'Skill package is not rebuildable',
  category: 'meta',
  severity: 'info',
  priority: 'P1',
  description:
    'The folder is missing SKILL.md, SKILL.md runs a local script that a multi-file package does not contain, or SKILL.md is only a placeholder with no concrete steps. The verdict is incomplete, not a clean pass. This finding is context only: it does not block and it does not add review points. A lone SKILL.md that names a script is still the IH-REF-001 note, because a one-file extract cannot prove the sibling is missing from the published package.',
  remediation: REMEDIATION,
  appliesTo: ['any'],
  examples: {
    matches: [
      'A folder whose only file is README.md',
      'SKILL.md says this gist is a placeholder and gives no steps',
      'SKILL.md runs scripts/apply.py, and the package also has references/notes.md, but scripts/apply.py is absent',
    ],
    nonMatches: [
      "SKILL.md says: Summarize the user's notes. The optional guide is not shipped.",
      'SKILL.md runs scripts/apply.py and that file is in the package',
      'A lone SKILL.md that mentions scripts/example.py (IH-REF-001 note only)',
    ],
  },
  check(file, ctx) {
    return rebuildableFindings(meta005, file, ctx);
  },
};

function skillNames(root: string): string[] {
  try {
    return readdirSync(root).filter((name) => isSkillFileName(name));
  } catch {
    return [];
  }
}

function companionPresent(root: string): boolean {
  let entries;
  try {
    entries = readdirSync(root, { withFileTypes: true });
  } catch {
    return false;
  }
  return entries.some((entry) => {
    if (isSkillFileName(entry.name)) return false;
    if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === '.clawhub')
      return false;
    if (entry.name === '_meta.json') return false;
    return true;
  });
}

function isReporter(file: ScannedFile, root: string, hasSkill: boolean): boolean {
  if (hasSkill) return isSkillFileName(file.relativePath) && !file.relativePath.includes('/');
  if (file.relativePath.includes('/')) return false;
  let names: string[] = [];
  try {
    names = readdirSync(root)
      .filter((name) => {
        try {
          return statSync(join(root, name)).isFile();
        } catch {
          return false;
        }
      })
      .sort();
  } catch {
    return false;
  }
  return names[0] === file.relativePath;
}

function missingRunnable(text: string, root: string): string | undefined {
  for (const ref of scriptReferences(text)) {
    if (!ref.runnable) continue;
    const local = ref.path.replace(/^\.\//, '');
    if (existsSync(join(root, local))) continue;
    if (existsSync(join(root, posix.basename(local)))) continue;
    return local;
  }
  return undefined;
}

export function rebuildableFindings(rule: Rule, file: ScannedFile, ctx: ScanContext): Finding[] {
  if (ctx.root.startsWith('(')) return [];
  const findings: Finding[] = [];
  if (META_STUB.test(file.text) && !CONCRETE.test(file.text)) {
    const at = Math.max(0, file.text.search(META_STUB));
    pushUnique(
      findings,
      createFinding(rule, file, {
        line: lineNumberAt(file.text, at),
        evidence: evidenceLine(file.text, at),
        confidence: 'high',
        message: gapMessage('meta-stub', evidenceLine(file.text, at)),
        scoreExempt: true,
      }),
    );
    return findings;
  }
  const root = ctx.root;
  if (!directoryExists(root)) return findings;
  const names = skillNames(root);
  const hasSkill = names.length > 0;
  if (!isReporter(file, root, hasSkill)) return findings;
  let kind: GapKind | undefined;
  let detail = file.relativePath;
  if (!hasSkill) {
    kind = 'missing-skill-md';
  } else if (companionPresent(root)) {
    const missing = missingRunnable(file.text, root);
    if (missing) {
      kind = 'missing-referenced-file';
      detail = missing;
    }
  }
  if (!kind) return findings;
  const at = 0;
  const finding = createFinding(rule, file, {
    line: lineNumberAt(file.text, at),
    evidence: kind === 'missing-skill-md' ? file.relativePath : evidenceLine(file.text, at),
    confidence: 'high',
    message: gapMessage(kind, detail),
    scoreExempt: true,
  });
  pushUnique(findings, finding);
  return findings;
}

function directoryExists(root: string): boolean {
  try {
    return statSync(root).isDirectory();
  } catch {
    return false;
  }
}

function lineNumberAt(text: string, index: number): number {
  if (index <= 0) return 1;
  return text.slice(0, index).split(/\n/).length;
}

function evidenceLine(text: string, index: number): string {
  const start = Math.max(0, text.lastIndexOf('\n', index - 1) + 1);
  const end = text.indexOf('\n', index);
  return text.slice(start, end === -1 ? text.length : end).trim() || text.slice(0, 200);
}
