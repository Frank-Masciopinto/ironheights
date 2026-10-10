import { gradeFromSkills, renderBadge, renderSummary } from '../../core/grade.ts';
import type { ScanMode } from '../../core/grade.ts';
import type {
  AdvisoryFeedNote,
  Finding,
  JsonSkillReport,
  ScanOutput,
  SkillReport,
  Verdict,
} from '../../core/types.ts';
import { referencesFor } from '../../rules/references.ts';
import { SCHEMA_VERSION, TOOL_NAME, TOOL_VERSION } from '../../version.ts';

export interface RenderContext {
  scanMode?: ScanMode;
  limitNote?: string;
  advisory?: AdvisoryFeedNote;
}

export function renderJson(
  skills: SkillReport[],
  verdict: Verdict,
  scannedAt: string,
  context: RenderContext = {},
): string {
  const scanMode = context.scanMode ?? 'directory';
  const grade = gradeFromSkills(skills);
  const summaryInput = { skills, verdict, grade, scanMode };
  const since = sinceBaselineSummary(skills);
  const payload: ScanOutput = {
    schemaVersion: SCHEMA_VERSION,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    scannedAt,
    verdict,
    skippedFileCount: skills.reduce((sum, skill) => sum + skill.filesSkipped.length, 0),
    grade,
    scanMode,
    summary: renderSummary(summaryInput),
    badge: renderBadge(summaryInput),
    ...(context.limitNote ? { scanLimit: context.limitNote } : {}),
    ...(since ? { sinceBaseline: since } : {}),
    skills: skills.map(stableSkill),
    ...(context.advisory ? { advisoryFeed: context.advisory } : {}),
  };
  return `${JSON.stringify(payload, null, 2)}\n`;
}

function stableSkill(skill: SkillReport): JsonSkillReport {
  const suppressed = skill.suppressed ?? [];
  const refused = skill.suppressionRefused ?? [];
  return {
    skillName: skill.skillName,
    root: skill.root,
    filesScanned: skill.filesScanned,
    filesSkipped: skill.filesSkipped,
    skippedFileCount: skill.filesSkipped.length,
    findings: skill.findings.map(stableFinding),
    suppressed,
    suppressedCount: suppressed.length,
    suppressionRefused: refused,
    suppressionRefusedCount: refused.length,
    ...(skill.suppressionWarnings && skill.suppressionWarnings.length > 0
      ? { suppressionWarnings: skill.suppressionWarnings }
      : {}),
    ...(skill.sinceBaseline
      ? {
          sinceBaseline: {
            comparedWith: skill.sinceBaseline.comparedWith,
            kind: skill.sinceBaseline.kind,
            omittedCount: skill.sinceBaseline.omitted.length,
            omitted: skill.sinceBaseline.omitted,
          },
        }
      : {}),
    score: skill.score,
    verdict: skill.verdict,
  };
}

function stableFinding(
  finding: Finding,
): Finding & { references?: ReturnType<typeof referencesFor> } {
  const references = referencesFor(finding.ruleId);
  const known =
    references.owaspLlm.length + references.owaspAgentic.length + references.mitreAtlas.length;
  return {
    ruleId: finding.ruleId,
    severity: finding.severity,
    confidence: finding.confidence,
    file: finding.file,
    ...(finding.line !== undefined ? { line: finding.line } : {}),
    ...(finding.column !== undefined ? { column: finding.column } : {}),
    evidence: finding.evidence,
    message: finding.message,
    remediation: finding.remediation,
    ...(known > 0 || finding.ruleId.startsWith('IH-') ? { references } : {}),
  };
}

function sinceBaselineSummary(skills: SkillReport[]): ScanOutput['sinceBaseline'] | undefined {
  const note = skills.find((skill) => skill.sinceBaseline)?.sinceBaseline;
  if (!note) return undefined;
  return {
    path: note.comparedWith,
    kind: note.kind,
    omittedCount: skills.reduce(
      (sum, skill) => sum + (skill.sinceBaseline?.omitted.length ?? 0),
      0,
    ),
  };
}
