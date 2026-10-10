import type { SkillReport } from '../../core/types.ts';
import { LLM_RULE_ID } from '../../llm/constants.ts';
import type { LlmReviewReport } from '../../llm/review.ts';

export function llmStatusLines(
  skills: SkillReport[],
  report: LlmReviewReport | undefined,
): string[] {
  if (!report) return [];
  const lines: string[] = [];
  if (report.status === 'skipped' || report.status === 'partial') {
    const skipped = report.reviews.filter((review) => review.status === 'skipped' && review.reason);
    if (skipped.length === 0) {
      lines.push('LLM review skipped: no skill to review. Deterministic result unchanged.');
    }
    for (const review of skipped) {
      lines.push(
        `LLM review skipped (${review.skillName}): ${review.reason}. Deterministic result unchanged.`,
      );
    }
  }
  const noted = skills.some((skill) =>
    skill.findings.some((finding) => finding.ruleId === LLM_RULE_ID),
  );
  if (noted) {
    lines.push(
      'LLM notes (IH-LLM-001) are advisory and can be wrong. They do not change the verdict.',
    );
  } else if (report.status === 'ok') {
    lines.push(
      'LLM review returned no additional notes. An empty model review is not a clearance.',
    );
  }
  return lines;
}
