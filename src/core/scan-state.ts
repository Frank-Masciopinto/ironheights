import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { z } from 'zod';
import { createBaseline } from '../integrity/baseline.ts';
import { parseSkillMarkdown } from '../openclaw/skill.ts';
import { writeAtomic } from '../util/atomic.ts';
import { formatGrade } from './grade.ts';
import { findSkillFile } from './skill-file.ts';
import type { Grade, SkillReport } from './types.ts';

/**
 * Scan state: the content hash and declared version of every skill at its last scan.
 * `scan --changed` and `watch` rescan a skill only when either one differs, so a skill
 * that updates itself (or is updated by ClawHub) is scanned again before it is used.
 */
const EntrySchema = z.object({
  treeHash: z.string(),
  version: z.string().optional(),
  scannedAt: z.string(),
  verdict: z.string(),
  grade: z.string(),
});

const StateSchema = z.object({
  version: z.literal(1),
  skills: z.record(z.string(), EntrySchema),
});

export type ScanStateEntry = z.infer<typeof EntrySchema>;
export type ScanState = z.infer<typeof StateSchema>;

export interface SkillFingerprint {
  root: string;
  treeHash: string;
  version?: string;
}

export interface ChangeCheck {
  fingerprint: SkillFingerprint;
  reason: 'new' | 'content' | 'version';
  previous?: ScanStateEntry;
}

export function scanStatePath(home: string): string {
  return join(home, 'scan-state.json');
}

export async function readScanState(filePath: string): Promise<ScanState> {
  let raw: string;
  try {
    raw = await readFile(filePath, 'utf8');
  } catch {
    return { version: 1, skills: {} };
  }
  try {
    const parsed = StateSchema.safeParse(JSON.parse(raw) as unknown);
    if (parsed.success) return parsed.data;
  } catch {
    // A corrupt state file means every skill counts as changed.
  }
  return { version: 1, skills: {} };
}

export async function writeScanState(filePath: string, state: ScanState): Promise<void> {
  await writeAtomic(filePath, `${JSON.stringify(state, null, 2)}\n`, 0o600);
}

export async function fingerprintSkill(root: string): Promise<SkillFingerprint> {
  const abs = resolve(root);
  const baseline = await createBaseline([abs]);
  const rootKey = baseline.roots[0] ?? '';
  // Hash relative paths so the fingerprint does not depend on where the skill lives.
  const lines = Object.keys(baseline.files)
    .sort()
    .map((key) => `${key.slice(rootKey.length)}\0${baseline.files[key]?.sha256 ?? ''}`);
  const treeHash = createHash('sha256').update(lines.join('\n')).digest('hex');
  let version: string | undefined;
  try {
    const path = await findSkillFile(abs);
    version = path ? parseSkillMarkdown(await readFile(path, 'utf8'))?.version : undefined;
  } catch {
    version = undefined;
  }
  return { root: abs, treeHash, ...(version ? { version } : {}) };
}

export function changeReason(
  fingerprint: SkillFingerprint,
  previous: ScanStateEntry | undefined,
): ChangeCheck['reason'] | undefined {
  if (!previous) return 'new';
  if ((previous.version ?? '') !== (fingerprint.version ?? '')) return 'version';
  if (previous.treeHash !== fingerprint.treeHash) return 'content';
  return undefined;
}

export async function findChangedSkills(
  roots: string[],
  state: ScanState,
): Promise<{ changed: ChangeCheck[]; unchanged: SkillFingerprint[] }> {
  const changed: ChangeCheck[] = [];
  const unchanged: SkillFingerprint[] = [];
  for (const root of roots) {
    const fingerprint = await fingerprintSkill(root);
    const previous = state.skills[fingerprint.root];
    const reason = changeReason(fingerprint, previous);
    if (reason) changed.push({ fingerprint, reason, ...(previous ? { previous } : {}) });
    else unchanged.push(fingerprint);
  }
  return { changed, unchanged };
}

export function recordScans(
  state: ScanState,
  fingerprints: SkillFingerprint[],
  reports: SkillReport[],
  grades: Map<string, Grade>,
  now: Date,
): ScanState {
  const next: ScanState = { version: 1, skills: { ...state.skills } };
  for (const fingerprint of fingerprints) {
    const report = reports.find((skill) => resolve(skill.root) === fingerprint.root);
    if (!report) continue;
    const grade = grades.get(fingerprint.root);
    next.skills[fingerprint.root] = {
      treeHash: fingerprint.treeHash,
      ...(fingerprint.version ? { version: fingerprint.version } : {}),
      scannedAt: now.toISOString(),
      verdict: report.verdict,
      grade: grade ? formatGrade(grade) : 'unknown',
    };
  }
  return next;
}
