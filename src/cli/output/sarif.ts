import type { Finding, SkillReport } from '../../core/types.ts';
import { allRules } from '../../rules/index.ts';
import { TOOL_NAME, TOOL_VERSION } from '../../version.ts';

export function renderSarif(skills: SkillReport[]): string {
  const findings = skills.flatMap((skill) => skill.findings);
  const used = new Set(findings.map((finding) => finding.ruleId));
  const rules = allRules()
    .filter((rule) => used.has(rule.id))
    .map((rule) => ({
      id: rule.id,
      shortDescription: { text: rule.title },
      fullDescription: { text: rule.description },
      help: { text: rule.remediation },
      defaultConfiguration: { level: sarifLevel(rule.severity) },
      properties: { category: rule.category, priority: rule.priority, tags: [rule.category] },
    }));
  const results = findings.map((finding) => ({
    ruleId: finding.ruleId,
    level: sarifLevel(finding.severity),
    message: { text: finding.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: finding.file, uriBaseId: '%SRCROOT%' },
          region: {
            startLine: finding.line ?? 1,
            startColumn: finding.column ?? 1,
          },
        },
      },
    ],
    properties: {
      confidence: finding.confidence,
      evidence: finding.evidence,
      remediation: finding.remediation,
    },
  }));
  const doc = {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri: 'https://github.com/ironheights/ironheights',
            rules,
          },
        },
        results,
      },
    ],
  };
  return `${JSON.stringify(doc, null, 2)}\n`;
}

function sarifLevel(severity: Finding['severity']): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
    default: {
      const neverSeverity: never = severity;
      return neverSeverity;
    }
  }
}
