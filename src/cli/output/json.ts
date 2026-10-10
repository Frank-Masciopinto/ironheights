import type { ScanOutput, SkillReport, Verdict } from '../../core/types.ts';
import { SCHEMA_VERSION, TOOL_NAME, TOOL_VERSION } from '../../version.ts';

export function renderJson(skills: SkillReport[], verdict: Verdict, scannedAt: string): string {
  const payload: ScanOutput = {
    schemaVersion: SCHEMA_VERSION,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    scannedAt,
    verdict,
    skippedFileCount: skills.reduce((sum, skill) => sum + skill.filesSkipped.length, 0),
    skills: skills.map(stableSkill),
  };
  return `${JSON.stringify(payload, null, 2)}\n`;
}

function stableSkill(skill: SkillReport): SkillReport & { skippedFileCount: number } {
  return {
    skillName: skill.skillName,
    root: skill.root,
    filesScanned: skill.filesScanned,
    filesSkipped: skill.filesSkipped,
    skippedFileCount: skill.filesSkipped.length,
    findings: skill.findings.map((finding) => ({
      ruleId: finding.ruleId,
      severity: finding.severity,
      confidence: finding.confidence,
      file: finding.file,
      ...(finding.line !== undefined ? { line: finding.line } : {}),
      ...(finding.column !== undefined ? { column: finding.column } : {}),
      evidence: finding.evidence,
      message: finding.message,
      remediation: finding.remediation,
    })),
    score: skill.score,
    verdict: skill.verdict,
  };
}
