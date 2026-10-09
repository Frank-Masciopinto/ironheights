import type { Confidence, Finding, Rule, ScannedFile, Severity } from '../core/types.ts';
import { clip } from '../util/text.ts';

export function createFinding(
  rule: Rule,
  file: ScannedFile,
  details: {
    line?: number;
    column?: number;
    evidence: string;
    message: string;
    confidence: Confidence;
    severity?: Severity;
  },
): Finding {
  return {
    ruleId: rule.id,
    severity: details.severity ?? rule.severity,
    confidence: details.confidence,
    file: clip(file.relativePath, 300),
    ...(details.line !== undefined ? { line: details.line } : {}),
    ...(details.column !== undefined ? { column: details.column } : {}),
    evidence: clip(details.evidence),
    message: details.message,
    remediation: rule.remediation,
  };
}

export function pushUnique(findings: Finding[], finding: Finding): void {
  const exists = findings.some(
    (item) =>
      item.ruleId === finding.ruleId &&
      item.file === finding.file &&
      item.line === finding.line &&
      item.evidence === finding.evidence,
  );
  if (!exists) findings.push(finding);
}
