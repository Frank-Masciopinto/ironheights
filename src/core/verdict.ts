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
  options?: { filesSkipped?: number; allowSkipped?: boolean },
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
  if (!options?.allowSkipped && (options?.filesSkipped ?? 0) > 0) return 'incomplete';
  return 'no-findings';
}

export function worstVerdict(verdicts: Verdict[]): Verdict {
  if (verdicts.includes('block')) return 'block';
  if (verdicts.includes('review')) return 'review';
  if (verdicts.includes('incomplete')) return 'incomplete';
  return 'no-findings';
}

export function exitCodeFor(
  verdict: Verdict,
  findings: Finding[],
  failOn?: Severity,
  options?: { filesSkipped?: number; allowSkipped?: boolean },
): number {
  let code = codeForVerdict(verdict);
  if (failOn && verdict !== 'incomplete') {
    const floor = SEVERITY_RANK[failOn];
    const hit = findings.some((finding) => SEVERITY_RANK[finding.severity] >= floor);
    if (!hit) code = 0;
  }
  if (!options?.allowSkipped && (options?.filesSkipped ?? 0) > 0 && code === 0) return 3;
  return code;
}

function codeForVerdict(verdict: Verdict): number {
  switch (verdict) {
    case 'block':
      return 2;
    case 'review':
      return 1;
    case 'incomplete':
      return 3;
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
