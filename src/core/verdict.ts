import type { Severity, Verdict } from './types.ts';
import type { Finding } from './types.ts';

export const SEVERITY_POINTS: Record<Severity, number> = {
  critical: 100,
  high: 40,
  medium: 15,
  low: 5,
  info: 0,
};

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function scoreFindings(findings: Finding[]): number {
  return findings.reduce((sum, finding) => sum + SEVERITY_POINTS[finding.severity], 0);
}

export function verdictFor(
  findings: Finding[],
  thresholds: { block: number; review: number },
): Verdict {
  const score = scoreFindings(findings);
  if (findings.some((finding) => finding.severity === 'critical') || score >= thresholds.block) {
    return 'block';
  }
  if (
    findings.some((finding) => finding.severity === 'high' || finding.severity === 'medium') ||
    score >= thresholds.review
  ) {
    return 'review';
  }
  return 'no-findings';
}

export function worstVerdict(verdicts: Verdict[]): Verdict {
  if (verdicts.includes('block')) return 'block';
  if (verdicts.includes('review')) return 'review';
  return 'no-findings';
}

export function exitCodeFor(verdict: Verdict, findings: Finding[], failOn?: Severity): number {
  if (failOn) {
    const floor = SEVERITY_RANK[failOn];
    const hit = findings.some((finding) => SEVERITY_RANK[finding.severity] >= floor);
    if (!hit) return 0;
  }
  switch (verdict) {
    case 'block':
      return 2;
    case 'review':
      return 1;
    case 'no-findings':
      return 0;
    default: {
      const neverVerdict: never = verdict;
      return neverVerdict;
    }
  }
}

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_RANK[b] - SEVERITY_RANK[a];
}
