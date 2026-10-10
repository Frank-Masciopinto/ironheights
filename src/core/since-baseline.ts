import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { UsageError } from './errors.ts';
import type { Finding, SkillReport, SinceBaselineOmitted, Thresholds } from './types.ts';
import type { ScanMode } from './grade.ts';
import {
  baselineIsTampered,
  hashRecord,
  parseBaseline,
  toPortablePath,
} from '../integrity/baseline.ts';
import type { Baseline } from './types.ts';
import { blockingSkipCount, scoreFindings, verdictFor } from './verdict.ts';

export interface SinceBaselineOptions {
  thresholds: Thresholds;
  allowSkipped: boolean;
  scanMode: ScanMode;
}

/**
 * Drop findings that were already present.
 * An integrity baseline treats a finding as pre-existing when the file bytes
 * still match. A previous `--json` result matches rule id, file, and evidence
 * and ignores line numbers. The grade still uses `gradeRisk` from the full set.
 */
export async function applySinceBaseline(
  skills: SkillReport[],
  sourcePath: string,
  options: SinceBaselineOptions,
): Promise<SkillReport[]> {
  const compared = await loadComparison(sourcePath, options.scanMode);
  const next: SkillReport[] = [];
  for (const skill of skills) {
    const omitted: SinceBaselineOmitted[] = [];
    const fresh: Finding[] = [];
    for (const finding of skill.findings) {
      const preExisting = await isPreExisting(skill, finding, compared);
      if (preExisting) {
        omitted.push({
          ruleId: finding.ruleId,
          severity: finding.severity,
          file: finding.file,
          ...(finding.line !== undefined ? { line: finding.line } : {}),
          evidence: finding.evidence,
        });
      } else {
        fresh.push(finding);
      }
    }
    const score = scoreFindings(fresh);
    next.push({
      ...skill,
      findings: fresh,
      score,
      verdict: verdictFor(fresh, options.thresholds, {
        filesSkipped: blockingSkipCount(skill),
        allowSkipped: options.allowSkipped,
      }),
      gradeRisk: skill.gradeRisk ?? skill.score,
      sinceBaseline: {
        comparedWith: sourcePath,
        kind: compared.kind,
        omitted,
      },
    });
  }
  return next;
}

type Compared =
  | { kind: 'integrity'; baseline: Baseline }
  | { kind: 'scan-result'; fingerprints: Set<string> };

async function loadComparison(sourcePath: string, scanMode: ScanMode): Promise<Compared> {
  let raw: string;
  try {
    raw = await readFile(sourcePath, 'utf8');
  } catch {
    throw new UsageError(`cannot read baseline: ${sourcePath}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new UsageError('baseline file is not valid JSON');
  }
  const kind = classify(parsed);
  if (kind === 'integrity') {
    if (scanMode === 'text') {
      throw new UsageError(
        'an integrity baseline cannot filter a text scan; pass a previous JSON result',
      );
    }
    const baseline = parseBaseline(raw);
    if (baselineIsTampered(baseline)) {
      throw new UsageError('baseline file does not match its treeHash; refusing to hide findings');
    }
    return { kind: 'integrity', baseline };
  }
  if (kind === 'scan-result') {
    return { kind: 'scan-result', fingerprints: fingerprintsOf(parsed) };
  }
  throw new UsageError(
    'baseline must be an integrity baseline.json or a previous ironheights JSON result',
  );
}

function classify(parsed: unknown): 'integrity' | 'scan-result' | 'unknown' {
  if (!parsed || typeof parsed !== 'object') return 'unknown';
  const value = parsed as Record<string, unknown>;
  if (
    value.version === 1 &&
    typeof value.treeHash === 'string' &&
    value.files !== null &&
    typeof value.files === 'object'
  ) {
    return 'integrity';
  }
  if (typeof value.schemaVersion === 'number' && Array.isArray(value.skills)) return 'scan-result';
  return 'unknown';
}

function fingerprintsOf(parsed: unknown): Set<string> {
  const skills = (parsed as { skills: unknown[] }).skills;
  const set = new Set<string>();
  for (const skill of skills) {
    if (!skill || typeof skill !== 'object') continue;
    const name =
      typeof (skill as { skillName?: unknown }).skillName === 'string'
        ? (skill as { skillName: string }).skillName
        : '';
    const findings = (skill as { findings?: unknown }).findings;
    if (!Array.isArray(findings)) continue;
    for (const finding of findings) {
      if (!finding || typeof finding !== 'object') continue;
      const ruleId = (finding as { ruleId?: unknown }).ruleId;
      const file = (finding as { file?: unknown }).file;
      const evidence = (finding as { evidence?: unknown }).evidence;
      if (typeof ruleId !== 'string' || typeof file !== 'string' || typeof evidence !== 'string') {
        continue;
      }
      set.add(fingerprint(name, ruleId, file, evidence));
    }
  }
  return set;
}

async function isPreExisting(
  skill: SkillReport,
  finding: Finding,
  compared: Compared,
): Promise<boolean> {
  if (compared.kind === 'scan-result') {
    return compared.fingerprints.has(
      fingerprint(skill.skillName, finding.ruleId, finding.file, finding.evidence),
    );
  }
  const abs = resolve(skill.root, finding.file);
  const recorded = compared.baseline.files[toPortablePath(abs)];
  if (!recorded) return false;
  const current = await hashRecord(abs);
  if (!current) return false;
  return current.sha256 === recorded.sha256;
}

function fingerprint(skillName: string, ruleId: string, file: string, evidence: string): string {
  return `${skillName}\0${ruleId}\0${file}\0${evidence}`;
}
