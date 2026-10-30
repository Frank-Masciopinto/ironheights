import { openCreUrl, referencesFor, standardsLine } from '../../rules/references.ts';
import {
  formatGrade,
  gradeFromSkills,
  incompleteScanLine,
  renderBadge,
  renderSummary,
  TEXT_SCAN_LIMIT,
} from '../../core/grade.ts';
import type { ScanMode } from '../../core/grade.ts';
import { acceptanceLabel } from '../../core/suppress.ts';
import type { AdvisoryFeedNote, Finding, SkillReport, Verdict } from '../../core/types.ts';
import { blockingDirectoryCount, compareSeverity } from '../../core/verdict.ts';
import { LLM_RULE_ID } from '../../llm/constants.ts';
import type { LlmReviewReport } from '../../llm/review.ts';
import { clip } from '../../util/text.ts';
import { describeDependency } from '../../core/dependencies.ts';
import { paint } from '../../util/terminal.ts';
import { NO_FINDINGS_LABEL, SAFETY_REMINDER } from '../../version.ts';
import { llmStatusLines } from './llm-status.ts';

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
  advisory?: AdvisoryFeedNote,
  llmReview?: LlmReviewReport,
): string {
  const lines: string[] = [];
  if (scanMode === 'text') lines.push(TEXT_SCAN_LIMIT, '');
  if (skills.length === 0) {
    lines.push(NO_FINDINGS_LABEL, '');
  }
  for (const skill of skills) {
    lines.push(clip(skill.skillName, 120));
    if (skill.knownSecurityTool) {
      lines.push(`  Note: ${clip(skill.knownSecurityTool.note, 400)}`);
    }
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
    appendList(
      lines,
      'Stale suppression',
      (skill.staleSuppressions ?? []).map((item) => {
        const wherePath = item.path ?? '*';
        return `${item.ruleId} ${wherePath} evidence=${item.evidence} reason=${item.reason}`;
      }),
    );
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
    for (const dir of skill.skippedDirectories ?? []) {
      if (dir.explicit) {
        lines.push(`  ignored directory ${dir.path} (${dir.reason})`);
        continue;
      }
      const warning = `warning: skipped directory ${dir.path} (${dir.reason})`;
      lines.push(`  ${paint(color, '33', warning)}`);
    }
    for (const dep of skill.unscannedDependencies ?? []) {
      lines.push(
        `  ${paint(color, '33', 'dependency unscanned:')} ${clip(describeDependency(dep), 300)}`,
      );
    }
    if (skill.registryCheck) {
      const check = skill.registryCheck;
      lines.push(
        `  registry check: ${check.checked} checked, ${check.missing} missing, ${check.notChecked} not checked`,
      );
      for (const note of check.notes.slice(0, 10)) lines.push(`    ${clip(note, 200)}`);
    }
    if (skill.verdict === 'incomplete') {
      lines.push(
        `  ${incompleteScanLine(skill.filesSkipped.length, blockingDirectoryCount(skill))}`,
      );
    }
    lines.push('');
  }
  const grade = gradeFromSkills(skills);
  const summaryInput = { skills, verdict, grade, scanMode };
  if (advisory) {
    lines.push(`Advisory feed: ${advisory.entries} entries, generated ${advisory.generatedAt}.`);
  }
  const known = [
    ...new Set(
      skills.flatMap((skill) => (skill.knownSecurityTool ? [skill.knownSecurityTool.name] : [])),
    ),
  ];
  if (known.length > 0) {
    lines.push(
      `Security tools among these skills (name match only): ${known.slice(0, 6).join(', ')}. Run \`ironheights coexist\` to check they work together.`,
    );
  }
  lines.push(`Verdict: ${verdict}`);
  lines.push(`Grade: ${formatGrade(grade)}`);
  lines.push(...llmStatusLines(skills, llmReview));
  lines.push(SAFETY_REMINDER);
  lines.push(renderSummary(summaryInput));
  lines.push(`Badge: ${renderBadge(summaryInput)}`);
  return lines.join('\n');
}

function findingLines(finding: Finding, color: boolean): string[] {
  const label = paint(color, SEVERITY_COLOR[finding.severity], `[${finding.severity}]`);
  const lines = [`  ${label} ${finding.ruleId} ${where(finding)}`, `    ${clip(finding.evidence)}`];
  if (finding.acceptance) lines.push(`    ${acceptanceLabel(finding.acceptance)}`);
  if (finding.ruleId === LLM_RULE_ID) lines.push(`    ${finding.message}`);
  lines.push(`    ${finding.remediation}`);
  const standards = standardsLine(finding.ruleId);
  const cre = referencesFor(finding.ruleId).openCre[0];
  if (standards) lines.push(`    ${standards}${cre ? ` → ${openCreUrl(cre)}` : ''}`);
  if (finding.note) lines.push(`    note: ${clip(finding.note, 300)}`);
  return lines;
}

function where(item: { file: string; line?: number }): string {
  return item.line ? `${item.file}:${item.line}` : item.file;
}

function appendList(lines: string[], title: string, items: string[]): void {
  if (items.length === 0) return;
  lines.push(`  ${title}: ${items.length}`);
  for (const item of items) lines.push(`    ${item}`);
}
