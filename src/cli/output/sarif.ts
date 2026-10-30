import { gradeFromSkills } from '../../core/grade.ts';
import type { ScanMode } from '../../core/grade.ts';
import { acceptanceLabel } from '../../core/suppress.ts';
import type { Finding, SkillReport, SkippedDirectory } from '../../core/types.ts';
import { blockingDirectoryCount } from '../../core/verdict.ts';
import { LLM_RULE_ID } from '../../llm/constants.ts';
import { allRules } from '../../rules/index.ts';
import {
  referenceLinks,
  referencesFor,
  referenceTags,
  rulePageUrl,
} from '../../rules/references.ts';
import { REPOSITORY_URL, SAFETY_REMINDER, TOOL_NAME, TOOL_VERSION } from '../../version.ts';

export function renderSarif(skills: SkillReport[], scanMode: ScanMode = 'directory'): string {
  const findings = skills.flatMap((skill) => skill.findings);
  const used = new Set(findings.map((finding) => finding.ruleId));
  const grade = gradeFromSkills(skills);
  const rules = allRules()
    .filter((rule) => used.has(rule.id))
    .map((rule) => {
      const refs = referencesFor(rule.id);
      return {
        id: rule.id,
        shortDescription: { text: rule.title },
        fullDescription: { text: rule.description },
        help: { text: rule.remediation },
        defaultConfiguration: { level: sarifLevel(rule.severity) },
        properties: {
          category: rule.category,
          priority: rule.priority,
          tags: [rule.category, ...referenceTags(rule.id)],
          owaspLlm: refs.owaspLlm,
          owaspAgentic: refs.owaspAgentic,
          mitreAtlas: refs.mitreAtlas,
          openCre: refs.openCre,
        },
        helpUri: rulePageUrl(rule.id),
      };
    });
  const results = findings.map((finding) => {
    const refs = referencesFor(finding.ruleId);
    return {
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
        tags: referenceTags(finding.ruleId),
        owaspLlm: refs.owaspLlm,
        owaspAgentic: refs.owaspAgentic,
        mitreAtlas: refs.mitreAtlas,
        openCre: refs.openCre,
        links: referenceLinks(finding.ruleId),
        ...(finding.ruleId === LLM_RULE_ID ? { advisory: true } : {}),
        ...(finding.acceptance ? { acceptance: acceptanceLabel(finding.acceptance) } : {}),
      },
    };
  });
  const suppressedCount = skills.reduce((sum, skill) => sum + (skill.suppressed?.length ?? 0), 0);
  const staleSuppressions = skills.flatMap((skill) => skill.staleSuppressions ?? []);
  const skippedDirectories = skills.flatMap((skill) => skill.skippedDirectories ?? []);
  const blockingDirectories = skills.reduce((sum, skill) => sum + blockingDirectoryCount(skill), 0);
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
            informationUri: REPOSITORY_URL,
            rules,
          },
        },
        results,
        properties: {
          skippedFileCount: skills.reduce((sum, skill) => sum + skill.filesSkipped.length, 0),
          ...sarifDirectories(skippedDirectories, blockingDirectories),
          suppressedCount,
          ...(staleSuppressions.length > 0 ? { staleSuppressions } : {}),
          gradeLetter: grade.letter,
          ...(grade.score !== undefined ? { gradeScore: grade.score } : {}),
          disclaimer: SAFETY_REMINDER,
          scanMode,
        },
      },
    ],
  };
  return `${JSON.stringify(doc, null, 2)}\n`;
}

function sarifDirectories(
  directories: SkippedDirectory[],
  blockingDirectories: number,
): { skippedDirectories: SkippedDirectory[]; warning?: string } | Record<string, never> {
  if (directories.length === 0) return {};
  return {
    skippedDirectories: directories.map((dir) => ({
      path: dir.path,
      reason: dir.reason,
      ...(dir.explicit ? { explicit: true } : {}),
    })),
    ...(blockingDirectories > 0 ? { warning: 'Skipped directories were not scanned.' } : {}),
  };
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
