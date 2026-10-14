import type { Severity, SkippedDirectory, Verdict } from './types.ts';
import type { Finding } from './types.ts';

/** `.git` and `node_modules` directories that were not named in `ignoreDirs`. */
export function blockingDirectoryCount(skill: {
  skippedDirectories?: readonly SkippedDirectory[];
}): number {
  return (skill.skippedDirectories ?? []).filter((dir) => dir.explicit !== true).length;
}

/** Skipped files plus `.git` / `node_modules` directories that were not explicitly ignored. */
export function blockingSkipCount(skill: {
  filesSkipped: readonly unknown[];
  skippedDirectories?: readonly SkippedDirectory[];
}): number {
  return skill.filesSkipped.length + blockingDirectoryCount(skill);
}

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

/** Grade points for a first-party review item (remote instructions from the skill's own host). */
export const FIRST_PARTY_POINTS = 10;

/**
 * Risk points for the letter grade.
 *
 * - Identical evidence for the same rule (the same line copied into two files) counts once.
 * - Repeat hits of one rule in the same file are grouped: the first counts in full, each
 *   further hit counts half, and the group is capped at twice its worst hit.
 * - A first-party finding (see `Finding.firstParty`) counts as a review item, at most
 *   `FIRST_PARTY_POINTS`, so a legitimate self-updating skill is not graded like malware.
 *
 * Critical findings still score 100, so anything critical stays F.
 */
export function gradeRiskFor(findings: Finding[]): number {
  const seen = new Set<string>();
  const groups = new Map<string, number[]>();
  for (const finding of findings) {
    const evidence = finding.evidence.trim().replace(/\s+/g, ' ').toLowerCase();
    const dedupe = `${finding.ruleId}|${evidence}`;
    if (evidence !== '' && seen.has(dedupe)) continue;
    seen.add(dedupe);
    let points = SEVERITY_POINTS[finding.severity];
    if (finding.firstParty && finding.severity !== 'critical') {
      points = Math.min(points, FIRST_PARTY_POINTS);
    }
    // First-party hits share one host, so they group per rule across files. This keeps the
    // grade independent of which file a duplicated line was kept from.
    const key = finding.firstParty
      ? `${finding.ruleId}|first-party`
      : `${finding.ruleId}|${finding.file}`;
    const list = groups.get(key) ?? [];
    list.push(points);
    groups.set(key, list);
  }
  let total = 0;
  for (const list of groups.values()) {
    list.sort((a, b) => b - a);
    const worst = list[0] ?? 0;
    const sum = list.reduce((acc, points, index) => acc + (index === 0 ? points : points / 2), 0);
    total += Math.min(sum, worst * 2);
  }
  return Math.round(total);
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
