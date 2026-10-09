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

export function renderHuman(skills: SkillReport[], verdict: Verdict, color: boolean): string {
  const lines: string[] = [];
  if (skills.length === 0) {
    lines.push(NO_FINDINGS_LABEL, '', `Verdict: ${verdict}`, SAFETY_REMINDER);
    return lines.join('\n');
  }
  for (const skill of skills) {
    lines.push(clip(skill.skillName, 120));
    if (skill.findings.length === 0) {
      lines.push(`  ${NO_FINDINGS_LABEL}`);
    } else {
      const grouped = [...skill.findings].sort((a, b) => compareSeverity(a.severity, b.severity));
      for (const finding of grouped) {
        const where = finding.line ? `${finding.file}:${finding.line}` : finding.file;
        const label = paint(color, SEVERITY_COLOR[finding.severity], `[${finding.severity}]`);
        lines.push(`  ${label} ${finding.ruleId} ${where}`);
        lines.push(`    ${clip(finding.evidence)}`);
        lines.push(`    ${finding.remediation}`);
      }
    }
    if (skill.filesSkipped.length > 0) {
      lines.push(`  skipped: ${skill.filesSkipped.length}`);
    }
    lines.push('');
  }
  lines.push(`Verdict: ${verdict}`, SAFETY_REMINDER);
  return lines.join('\n');
}
