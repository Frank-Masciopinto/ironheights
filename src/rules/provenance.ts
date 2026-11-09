import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding, Rule, ScannedFile, ScanContext } from '../core/types.ts';
import { isSkillFileName } from '../core/skill-file.ts';
import { lockProblems } from '../provenance/local.ts';
import { createFinding, pushUnique } from './helpers.ts';

/**
 * A shipped ironheights.lock.json binds the bytes in the folder.
 * No lock means this check does not run: a one-file extract cannot prove a digest was promised.
 * A remote signed registry is not consulted.
 */

interface LockFile {
  files?: Record<string, string>;
}

function readLock(root: string): LockFile | undefined {
  const path = join(root, 'ironheights.lock.json');
  if (!existsSync(path)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { files: {} };
    const files = (parsed as LockFile).files;
    if (!files || typeof files !== 'object') return { files: {} };
    const clean: Record<string, string> = {};
    for (const [rel, hash] of Object.entries(files)) {
      if (typeof hash === 'string' && /^[0-9a-f]{64}$/i.test(hash) && !rel.includes('..'))
        clean[rel] = hash.toLowerCase();
    }
    return { files: clean };
  } catch {
    return { files: {} };
  }
}

export const prov001: Rule = {
  id: 'IH-PROV-001',
  title: 'Shipped lock does not match the files',
  category: 'integrity',
  severity: 'medium',
  priority: 'P1',
  description:
    'ironheights.lock.json lists a sha256 for a file in this folder, and that file is missing or its bytes differ. The lock is a local digest binding. A folder with no lock is not a finding: nothing was promised. This check does not call a registry and does not verify a publisher signature.',
  remediation:
    'Regenerate the lock from the files you intend to ship, or restore the files the lock names. Do not leave a lock that describes different bytes.',
  appliesTo: ['markdown'],
  examples: {
    matches: ['ironheights.lock.json says SKILL.md is abc… and the file differs'],
    nonMatches: [
      'A skill folder with no ironheights.lock.json',
      'A lock whose hashes match the files',
    ],
  },
  check(file: ScannedFile, ctx: ScanContext): Finding[] {
    if (!isSkillFileName(file.relativePath) || file.relativePath.includes('/')) return [];
    if (ctx.root.startsWith('(')) return [];
    const lock = readLock(ctx.root);
    if (!lock?.files || Object.keys(lock.files).length === 0) return [];
    const problems = lockProblems(ctx.root, lock.files);
    if (problems.length === 0) return [];
    const first = problems[0];
    if (!first) return [];
    const findings: Finding[] = [];
    pushUnique(
      findings,
      createFinding(prov001, file, {
        evidence: `${first.path} ${first.problem}`,
        message: `The shipped lock does not match ${first.path} (${first.problem}). ${problems.length} file${problems.length === 1 ? '' : 's'} differ.`,
        confidence: 'high',
        scoreExempt: true,
      }),
    );
    return findings;
  },
};
