import {
  formatGrade,
  gradeFromSkills,
  renderBadge,
  renderSummary,
  TEXT_SCAN_LIMIT,
} from '../../core/grade.ts';
import type { ScanMode } from '../../core/grade.ts';
import type { Finding, SkillReport, Verdict } from '../../core/types.ts';
import { compareSeverity } from '../../core/verdict.ts';
import { clip } from '../../util/text.ts';
import { paint } from '../../util/terminal.ts';
import { NO_FINDINGS_LABEL, SAFETY_REMINDER } from '../../version.ts';

const SEVERITY_COLOR: Record<Finding['severity'], string> = {
  critical: '31',
  high: '31',
  medium: '33',
  low: '36',
  info: '2',
};

export function renderHuman(
  skills: SkillReport[],
  verdict: Verdict,
  color: boolean,
  scanMode: ScanMode = 'directory',
): string {
  const lines: string[] = [];
  if (scanMode === 'text') lines.push(TEXT_SCAN_LIMIT, '');
  if (skills.length === 0) {
    lines.push(NO_FINDINGS_LABEL, '');
  }
  for (const skill of skills) {
    lines.push(clip(skill.skillName, 120));
    if (skill.findings.length === 0 && skill.verdict !== 'incomplete') {
      lines.push(`  ${skill.sinceBaseline ? 'No new findings' : NO_FINDINGS_LABEL}`);
    } else if (skill.findings.length > 0) {
      const grouped = [...skill.findings].sort((a, b) => compareSeverity(a.severity, b.severity));
      for (const finding of grouped) {
        lines.push(...findingLines(finding, color));
      }
    }
    appendList(
      lines,
      'Suppressed',
      (skill.suppressed ?? []).map((item) => `${item.ruleId} ${where(item)} reason=${item.reason}`),
    );
    appendList(
      lines,
      'Suppression refused',
      (skill.suppressionRefused ?? []).map(
        (item) => `${item.ruleId} ${where(item)} ${item.detail}`,
      ),
    );
    appendList(lines, 'Suppression ignored', skill.suppressionWarnings ?? []);
    if (skill.sinceBaseline) {
      lines.push(`  Omitted as pre-existing: ${skill.sinceBaseline.omitted.length}`);
      for (const item of skill.sinceBaseline.omitted) {
        lines.push(`    ${item.ruleId} ${where(item)}`);
      }
    }
    for (const skipped of skill.filesSkipped) {
      const warning = `warning: skipped ${skipped.file} (${skipped.reason})`;
      lines.push(`  ${paint(color, '33', warning)}`);
    }
    if (skill.verdict === 'incomplete') {
      lines.push(`  ${incompleteSummary(skill.filesSkipped.length)}`);
    }
    lines.push('');
  }
  const grade = gradeFromSkills(skills);
  const summaryInput = { skills, verdict, grade, scanMode };
  lines.push(`Verdict: ${verdict}`);
  lines.push(`Grade: ${formatGrade(grade)}`);
  lines.push(SAFETY_REMINDER);
  lines.push(renderSummary(summaryInput));
  lines.push(`Badge: ${renderBadge(summaryInput)}`);
  return lines.join('\n');
}

function findingLines(finding: Finding, color: boolean): string[] {
  const label = paint(color, SEVERITY_COLOR[finding.severity], `[${finding.severity}]`);
  return [
    `  ${label} ${finding.ruleId} ${where(finding)}`,
    `    ${clip(finding.evidence)}`,
    `    ${finding.remediation}`,
  ];
}

function where(item: { file: string; line?: number }): string {
  return item.line ? `${item.file}:${item.line}` : item.file;
}

function appendList(lines: string[], title: string, items: string[]): void {
  if (items.length === 0) return;
  lines.push(`  ${title}: ${items.length}`);
  for (const item of items) lines.push(`    ${item}`);
}

function incompleteSummary(count: number): string {
  const noun = count === 1 ? 'file was' : 'files were';
  return `Scan incomplete: ${count} ${noun} not scanned.`;
}
