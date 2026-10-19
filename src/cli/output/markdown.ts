import { describeDependency } from '../../core/dependencies.ts';
import {
  formatGrade,
  gradeFromSkills,
  incompleteScanLine,
  renderSummary,
  TEXT_SCAN_LIMIT,
} from '../../core/grade.ts';
import type { ScanMode } from '../../core/grade.ts';
import type { AdvisoryFeedNote, SkillReport, Verdict } from '../../core/types.ts';
import { acceptanceLabel } from '../../core/suppress.ts';
import { blockingDirectoryCount } from '../../core/verdict.ts';
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
    if (skill.knownSecurityTool) lines.push(`Note: ${skill.knownSecurityTool.note}`, '');
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
      if (finding.acceptance) lines.push(`  - ${acceptanceLabel(finding.acceptance)}`);
      lines.push(`  - ${finding.remediation}`);
      if (finding.note) lines.push(`  - Note: ${finding.note}`);
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
    for (const item of skill.staleSuppressions ?? []) {
      const where = item.path ?? '*';
      lines.push(
        `- stale suppression \`${item.ruleId}\` ${where} evidence=${item.evidence} reason=${item.reason}`,
      );
    }
    for (const item of skill.sinceBaseline?.omitted ?? []) {
      const where = item.line ? `${item.file}:${item.line}` : item.file;
      lines.push(`- pre-existing \`${item.ruleId}\` ${where}`);
    }
    for (const dep of skill.unscannedDependencies ?? []) {
      lines.push(`- dependency unscanned: ${describeDependency(dep)}`);
    }
    for (const skipped of skill.filesSkipped) {
      lines.push(`- warning: skipped \`${skipped.file}\` (${skipped.reason})`);
    }
    for (const dir of skill.skippedDirectories ?? []) {
      if (dir.explicit) {
        lines.push(`- ignored directory \`${dir.path}\` (${dir.reason})`);
        continue;
      }
      lines.push(`- warning: skipped directory \`${dir.path}\` (${dir.reason})`);
    }
    if (skill.verdict === 'incomplete') {
      lines.push('', incompleteScanLine(skill.filesSkipped.length, blockingDirectoryCount(skill)));
    }
    lines.push('');
  }
  for (const line of llmStatusLines(skills, llmReview)) lines.push(line, '');
  return lines.join('\n');
}
