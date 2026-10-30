// Writes rule metadata (id, title, severity, OWASP, OpenCRE) as JSON for the public site API.
import { writeFileSync } from 'node:fs';
import { allRules } from '../src/rules/index.ts';
import { OPENCRE_NAMES, openCreUrl, referencesFor, rulePageUrl } from '../src/rules/references.ts';
import { TOOL_VERSION } from '../src/version.ts';

const rules = allRules().map((rule) => {
  const refs = referencesFor(rule.id);
  return {
    id: rule.id,
    title: rule.title,
    severity: rule.severity,
    category: rule.category,
    appliesTo: rule.appliesTo,
    owaspLlm: refs.owaspLlm,
    owaspAgentic: refs.owaspAgentic,
    mitreAtlas: refs.mitreAtlas,
    openCre: refs.openCre.map((id) => ({ id, name: OPENCRE_NAMES[id] ?? '', url: openCreUrl(id) })),
    url: rulePageUrl(rule.id),
  };
});
const out = process.argv[2] ?? 'rules.json';
writeFileSync(
  out,
  JSON.stringify(
    { tool: 'ironheights', version: TOOL_VERSION, license: 'Apache-2.0', rules },
    null,
    2,
  ) + '\n',
);
console.log(`wrote ${rules.length} rules to ${out}`);
