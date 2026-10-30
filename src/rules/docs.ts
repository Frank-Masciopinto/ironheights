import type { Rule, RuleReferences } from '../core/types.ts';
import { allRules } from './index.ts';
import { OPENCRE_NAMES, openCreUrl, referencesFor } from './references.ts';

export function renderRulesDocument(rules: Rule[] = allRules()): string {
  const lines: string[] = [
    '# Detection rules',
    '',
    'Generated from rule metadata. Do not edit by hand. Run `npm run docs:rules` to refresh this file.',
    '',
    'OWASP LLM ids are from the OWASP Top 10 for LLM Applications 2025 (`LLMnn:2025`).',
    'OWASP Agentic ids are from the OWASP Top 10 for Agentic Applications 2026 (`ASInn:2026`).',
    'MITRE ATLAS ids are technique ids. `none` means no defensible mapping was recorded.',
    'OpenCRE ids are Common Requirement Enumeration ids from https://www.opencre.org, checked against its public API. Each links to the OpenCRE page with the fix guidance from mapped standards.',
    '',
  ];
  for (const rule of rules) {
    lines.push(`## ${rule.id} — ${rule.title}`, '');
    lines.push(`- Severity: ${rule.severity}`);
    lines.push(`- Category: ${rule.category}`);
    lines.push(`- Priority: ${rule.priority}`);
    lines.push(`- Applies to: ${rule.appliesTo.join(', ')}`);
    const refs = referencesFor(rule.id);
    lines.push(`- OWASP LLM: ${formatRefs(refs.owaspLlm)}`);
    lines.push(`- OWASP Agentic: ${formatRefs(refs.owaspAgentic)}`);
    lines.push(`- MITRE ATLAS: ${formatRefs(refs.mitreAtlas)}`);
    lines.push(
      `- OpenCRE: ${
        refs.openCre.length === 0
          ? 'none'
          : refs.openCre
              .map((id) => `[${id} ${OPENCRE_NAMES[id] ?? ''}](${openCreUrl(id)})`)
              .join(', ')
      }`,
      '',
    );
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

function formatRefs(ids: RuleReferences['owaspLlm']): string {
  return ids.length === 0 ? 'none' : ids.join(', ');
}
