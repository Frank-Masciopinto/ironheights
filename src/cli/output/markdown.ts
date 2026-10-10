import {
  formatGrade,
  gradeFromSkills,
  renderSummary,
  TEXT_SCAN_LIMIT,
} from '../../core/grade.ts';
import type { ScanMode } from '../../core/grade.ts';
import type { AdvisoryFeedNote, SkillReport, Verdict } from '../../core/types.ts';
import type { LlmReviewReport } from '../../llm/review.ts';
import { referenceTags } from '../../rules/references.ts';
import { NO_FINDINGS_LABEL, SAFETY_REMINDER } from '../../version.ts';
import { llmStatusLines } from './llm-status.ts';

export function renderMarkdown(
  skills: SkillReport[],
  verdict: Verdict,
  scanMode: ScanMode = 'directory',
  advisory?: AdvisoryFeedNote,
  llmReview?: LlmReviewReport,
): string {
  const grade = gradeFromSkills(skills);
  const lines = ['# Ironheights scan', ''];
  if (scanMode === 'text') lines.push(TEXT_SCAN_LIMIT, '');
  lines.push(
    `Verdict: **${verdict}**`,
    '',
    `Grade: **${formatGrade(grade)}**`,
    '',
    SAFETY_REMINDER,
    '',
  );
  lines.push(renderSummary({ skills, verdict, grade, scanMode }), '');
  if (advisory) {
    lines.push(
      `Advisory feed: ${advisory.entries} entries, generated ${advisory.generatedAt}.`,
      '',
    );
  }
  for (const skill of skills) {
    lines.push(
      `## ${skill.skillName}`,
      '',
      `Root: \`${skill.root}\``,
      '',
      `Score: ${skill.score}`,
      '',
    );
    if (skill.findings.length === 0 && skill.verdict !== 'incomplete') {
      lines.push(skill.sinceBaseline ? 'No new findings' : NO_FINDINGS_LABEL, '');
    }
    for (const finding of skill.findings) {
      const where = finding.line ? `${finding.file}:${finding.line}` : finding.file;
      const tags = referenceTags(finding.ruleId);
      const suffix = tags.length > 0 ? ` (${tags.join(', ')})` : '';
      lines.push(`- **${finding.severity}** \`${finding.ruleId}\` ${where}${suffix}`);
      lines.push(`  - ${finding.message}`);
      lines.push(`  - Evidence: \`${finding.evidence.replace(/`/g, "'")}\``);
      lines.push(`  - ${finding.remediation}`);
    }
    for (const item of skill.suppressed ?? []) {
      const where = item.line ? `${item.file}:${item.line}` : item.file;
      lines.push(`- suppressed \`${item.ruleId}\` ${where} reason=${item.reason}`);
    }
    for (const item of skill.suppressionRefused ?? []) {
      const where = item.line ? `${item.file}:${item.line}` : item.file;
      lines.push(`- suppression refused \`${item.ruleId}\` ${where}: ${item.detail}`);
    }
    for (const warning of skill.suppressionWarnings ?? []) {
      lines.push(`- suppression ignored: ${warning}`);
    }
    for (const item of skill.sinceBaseline?.omitted ?? []) {
      const where = item.line ? `${item.file}:${item.line}` : item.file;
      lines.push(`- pre-existing \`${item.ruleId}\` ${where}`);
    }
    for (const skipped of skill.filesSkipped) {
      lines.push(`- warning: skipped \`${skipped.file}\` (${skipped.reason})`);
    }
    if (skill.verdict === 'incomplete') {
      const count = skill.filesSkipped.length;
      const noun = count === 1 ? 'file was' : 'files were';
      lines.push('', `Scan incomplete: ${count} ${noun} not scanned.`);
    }
    lines.push('');
  }
  for (const line of llmStatusLines(skills, llmReview)) lines.push(line, '');
  return lines.join('\n');
}
