import type { Grade, SkillReport, Verdict } from './types.ts';
import { clip } from '../util/text.ts';
import { REPOSITORY_URL, SAFETY_REMINDER, TOOL_VERSION } from '../version.ts';
import { blockingSkipCount } from './verdict.ts';

export type ScanMode = 'directory' | 'text';

export const TEXT_SCAN_LIMIT =
  'Limited text scan: the same skill-file rules, applied to one piece of text. This does not review a skill directory, binaries, or metadata, and it does not execute the text.';

/**
 * Trust score is 100 minus the risk score, never below 0.
 * A 90–100, B 80–89, C 70–79, D 60–69, F 0–59.
 * Any skipped file, or a `.git` / `node_modules` directory that was not
 * explicitly ignored, forces `incomplete` and omits the number.
 */
export function gradeFor(riskScore: number, filesSkipped: number): Grade {
  if (filesSkipped > 0) {
    return { letter: 'incomplete', disclaimer: SAFETY_REMINDER };
  }
  const score = Math.max(0, 100 - Math.min(Math.max(riskScore, 0), 100));
  const letter = letterFor(score);
  return { letter, score, disclaimer: SAFETY_REMINDER };
}

export function gradeFromSkills(skills: SkillReport[]): Grade {
  const skipped = skills.reduce((sum, skill) => sum + blockingSkipCount(skill), 0);
  if (skipped > 0) return gradeFor(0, skipped);
  // An empty folder (or no skills at all) earns no grade: an A would claim a review that never happened.
  const scanned = skills.reduce((sum, skill) => sum + skill.filesScanned, 0);
  if (scanned === 0) return { letter: 'nothing-scanned', disclaimer: SAFETY_REMINDER };
  const risk = skills.reduce((max, skill) => Math.max(max, skill.gradeRisk ?? skill.score), 0);
  const grade = gradeFor(risk, 0);
  const deps = skills.reduce((sum, skill) => sum + (skill.unscannedDependencies?.length ?? 0), 0);
  return deps > 0 ? { ...grade, unscannedDependencies: deps } : grade;
}

export function incompleteScanLine(files: number, directories: number): string {
  const parts: string[] = [];
  if (files > 0) parts.push(`${files} ${files === 1 ? 'file was' : 'files were'}`);
  if (directories > 0) {
    parts.push(`${directories} ${directories === 1 ? 'directory was' : 'directories were'}`);
  }
  if (parts.length === 0) return 'Scan incomplete.';
  return `Scan incomplete: ${parts.join(' and ')} not scanned.`;
}

export function formatGrade(grade: Grade): string {
  if (grade.letter === 'nothing-scanned') return 'nothing scanned';
  if (grade.letter === 'incomplete' || grade.score === undefined) return 'incomplete';
  const base = `${grade.letter} (${grade.score}/100)`;
  const deps = grade.unscannedDependencies ?? 0;
  if (deps === 0) return base;
  return `${base}, skill files only: ${deps} ${deps === 1 ? 'dependency' : 'dependencies'} unscanned`;
}

export function skillLabel(skills: SkillReport[], scanMode: ScanMode): string {
  if (scanMode === 'text') return 'text';
  if (skills.length === 0) return 'no skills';
  if (skills.length === 1) return skills[0]?.skillName ?? 'skill';
  return `${skills.length} skills`;
}

export interface SummaryInput {
  skills: SkillReport[];
  verdict: Verdict;
  grade: Grade;
  scanMode: ScanMode;
}

export function renderSummary(input: SummaryInput): string {
  const findings = input.skills.reduce((sum, skill) => sum + skill.findings.length, 0);
  const suppressed = input.skills.reduce((sum, skill) => sum + (skill.suppressed?.length ?? 0), 0);
  const omitted = input.skills.reduce(
    (sum, skill) => sum + (skill.sinceBaseline?.omitted.length ?? 0),
    0,
  );
  const noun = findings === 1 ? 'finding' : 'findings';
  const parts = [
    `ironheights ${TOOL_VERSION}`,
    clip(skillLabel(input.skills, input.scanMode), 80),
    `grade ${formatGrade(input.grade)}`,
    `verdict ${input.verdict}`,
    `${findings} ${noun}`,
  ];
  if (suppressed > 0) parts.push(`${suppressed} suppressed`);
  if (omitted > 0) parts.push(`${omitted} pre-existing`);
  return parts.join(' | ');
}

export function renderBadge(input: SummaryInput): string {
  return `[ironheights ${TOOL_VERSION}: grade ${formatGrade(input.grade)}, verdict ${input.verdict}](${REPOSITORY_URL}) — ${SAFETY_REMINDER}`;
}

function letterFor(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}
