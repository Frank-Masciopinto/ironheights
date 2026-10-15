import { gradeFromSkills, renderBadge, renderSummary } from '../../core/grade.ts';
import type { ScanMode } from '../../core/grade.ts';
import type {
  AdvisoryFeedNote,
  Finding,
  JsonSkillReport,
  ScanOutput,
  SkippedDirectory,
  SkillReport,
  Verdict,
} from '../../core/types.ts';
import type { LlmReviewReport } from '../../llm/review.ts';
import { referencesFor } from '../../rules/references.ts';
import { SCHEMA_VERSION, TOOL_NAME, TOOL_VERSION } from '../../version.ts';

export interface RenderContext {
  scanMode?: ScanMode;
  limitNote?: string;
  advisory?: AdvisoryFeedNote;
  llmReview?: LlmReviewReport;
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
  const payload: ScanOutput & { llmReview?: LlmReviewReport } = {
    schemaVersion: SCHEMA_VERSION,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    scannedAt,
    verdict,
    skippedFileCount: skills.reduce((sum, skill) => sum + skill.filesSkipped.length, 0),
    ...directoryField(collectDirectories(skills)),
    grade,
    scanMode,
    summary: renderSummary(summaryInput),
    badge: renderBadge(summaryInput),
    ...(context.limitNote ? { scanLimit: context.limitNote } : {}),
    ...(since ? { sinceBaseline: since } : {}),
    ...(context.llmReview ? { llmReview: context.llmReview } : {}),
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
    ...directoryField(skill.skippedDirectories ?? []),
    skippedFileCount: skill.filesSkipped.length,
    findings: skill.findings.map(stableFinding),
    suppressed,
    suppressedCount: suppressed.length,
    suppressionRefused: refused,
    suppressionRefusedCount: refused.length,
    ...(skill.suppressionWarnings && skill.suppressionWarnings.length > 0
      ? { suppressionWarnings: skill.suppressionWarnings }
      : {}),
    ...(skill.staleSuppressions && skill.staleSuppressions.length > 0
      ? { staleSuppressions: skill.staleSuppressions }
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
    ...(skill.knownSecurityTool ? { knownSecurityTool: skill.knownSecurityTool } : {}),
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
    ...(finding.note ? { note: finding.note } : {}),
    ...(finding.acceptance ? { acceptance: finding.acceptance } : {}),
    ...(known > 0 || finding.ruleId.startsWith('IH-') ? { references } : {}),
  };
}

function collectDirectories(skills: SkillReport[]): SkippedDirectory[] {
  return skills.flatMap((skill) => skill.skippedDirectories ?? []);
}

function directoryField(
  directories: SkippedDirectory[],
): { skippedDirectories: SkippedDirectory[] } | Record<string, never> {
  if (directories.length === 0) return {};
  return {
    skippedDirectories: directories.map((dir) => ({
      path: dir.path,
      reason: dir.reason,
      ...(dir.explicit ? { explicit: true } : {}),
    })),
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
