import type { SkillReport, Verdict } from '../../core/types.ts';
import { NO_FINDINGS_LABEL, SAFETY_REMINDER } from '../../version.ts';

export function renderMarkdown(skills: SkillReport[], verdict: Verdict): string {
  const lines = ['# Ironheights scan', '', `Verdict: **${verdict}**`, ''];
  for (const skill of skills) {
    lines.push(
      `## ${skill.skillName}`,
      '',
      `Root: \`${skill.root}\``,
      '',
      `Score: ${skill.score}`,
      '',
    );
    if (skill.findings.length === 0) {
      lines.push(NO_FINDINGS_LABEL, '');
      continue;
    }
    for (const finding of skill.findings) {
      const where = finding.line ? `${finding.file}:${finding.line}` : finding.file;
      lines.push(`- **${finding.severity}** \`${finding.ruleId}\` ${where}`);
      lines.push(`  - ${finding.message}`);
      lines.push(`  - Evidence: \`${finding.evidence.replace(/`/g, "'")}\``);
      lines.push(`  - ${finding.remediation}`);
    }
    lines.push('');
  }
  lines.push(SAFETY_REMINDER, '');
  return lines.join('\n');
}
