import type { Rule } from '../core/types.ts';
import { allRules } from './index.ts';

export function renderRulesDocument(rules: Rule[] = allRules()): string {
  const lines: string[] = [
    '# Detection rules',
    '',
    'Generated from rule metadata. Do not edit by hand. Run `npm run docs:rules` to refresh this file.',
    '',
  ];
  for (const rule of rules) {
    lines.push(`## ${rule.id} — ${rule.title}`, '');
    lines.push(`- Severity: ${rule.severity}`);
    lines.push(`- Category: ${rule.category}`);
    lines.push(`- Priority: ${rule.priority}`);
    lines.push(`- Applies to: ${rule.appliesTo.join(', ')}`, '');
    lines.push(rule.description, '');
    lines.push(`Remediation: ${rule.remediation}`, '');
    lines.push('Matches:');
    for (const example of rule.examples.matches) lines.push(`- \`${example.replace(/`/g, "'")}\``);
    lines.push('', 'Does not match:');
    for (const example of rule.examples.nonMatches)
      lines.push(`- \`${example.replace(/`/g, "'")}\``);
    lines.push('');
  }
  return `${lines.join('\n')}\n`;
}
