import type { Confidence, Finding, SkillReport } from '../core/types.ts';
import { clip } from '../util/text.ts';
import { LLM_REMEDIATION, LLM_RULE_ID } from './constants.ts';
import type { ReviewNote } from './schema.ts';
import { neutralizeMarkers, sanitizeUntrusted } from './sanitize.ts';

/**
 * Advisory notes are info-level IH-LLM-001 findings appended after the
 * deterministic verdict and score are already fixed.
 */
export function attachAdvisoryFindings(skill: SkillReport, advisory: Finding[]): SkillReport {
  if (advisory.length === 0) return skill;
  const verdict = skill.verdict;
  const score = skill.score;
  return {
    ...skill,
    findings: [...skill.findings, ...advisory.map(lockFinding)],
    verdict,
    score,
  };
}

export function notesToFindings(notes: ReviewNote[], files: readonly string[]): Finding[] {
  const findings: Finding[] = [];
  for (const note of notes) {
    const requested = note.file?.trim() ?? '';
    if (requested.length > 0 && !files.includes(requested)) continue;
    const file = requested.length > 0 ? requested : (files[0] ?? '(llm-review)');
    const summary = cleanField(note.summary);
    const concern = cleanField(note.concern);
    if (summary.length === 0 || concern.length === 0) continue;
    findings.push(advisoryFinding(file, note.confidence, summary, concern));
  }
  return findings;
}

function advisoryFinding(
  file: string,
  confidence: Confidence,
  summary: string,
  concern: string,
): Finding {
  return {
    ruleId: LLM_RULE_ID,
    severity: 'info',
    confidence,
    file,
    evidence: clip(summary),
    message: clip(
      `Advisory llm-review. Model confidence: ${confidence}. This confidence is the model's claim, not a measurement. ${concern}`,
      500,
    ),
    remediation: LLM_REMEDIATION,
  };
}

function lockFinding(finding: Finding): Finding {
  return {
    ...finding,
    ruleId: LLM_RULE_ID,
    severity: 'info',
  };
}

function cleanField(value: string): string {
  return neutralizeMarkers(sanitizeUntrusted(value)).replace(/\s+/g, ' ').trim();
}
