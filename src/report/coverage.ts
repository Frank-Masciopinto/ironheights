/**
 * Gap-aware posture grading (0.27.0). Coverage comes first; a grade is printed only when the
 * record is whole. Ideas from Moltbook bots: refuse to grade over missed runs, grade carries
 * the rule-set version, fixed cohort trends, dropped-from-scan skills named, unknown count as
 * the first line, declared vs granted vs used access, explained vs resolved drift.
 */
export interface Run {
  /** Night (YYYY-MM-DD) the scheduled check covers. */
  night: string;
  ran: boolean;
  rulesetHash?: string;
  /** Per-skill grade from that run. */
  grades?: Record<string, string>;
}

export interface CoverageInput {
  runs: Run[];
  /** Skills present in the inventory (scanned or not). */
  inventory: string[];
  /** ISO times when the skill list changed (installs, updates, removals). */
  skillChanges?: string[];
  /** Skills present in an earlier run that are no longer scanned. */
  previousSkills?: string[];
  /** Max empty nights allowed before refusing a grade (default 1). */
  maxGapNights?: number;
  currentRulesetHash?: string;
}

const GRADE_POINTS: Record<string, number> = { A: 4, B: 3, C: 2, D: 1, F: 0 };

export interface CoverageReport {
  headline: string;
  checked: number;
  total: number;
  unknown: string[];
  missedNights: string[];
  gapsAfterUpdates: string[];
  graded: boolean;
  refusal?: string;
  grade?: string;
  rulesetHash?: string;
  rulesetStale: boolean;
  leftScanning: string[];
  cohort: string[];
  cohortTrend: Array<{ night: string; grade: string | 'not-run' }>;
}

function avgGrade(grades: string[]): string {
  if (!grades.length) return 'none';
  const p = grades.reduce((s, g) => s + (GRADE_POINTS[g] ?? 0), 0) / grades.length;
  return p >= 3.5 ? 'A' : p >= 2.5 ? 'B' : p >= 1.5 ? 'C' : p >= 0.5 ? 'D' : 'F';
}

export function coverageReport(input: CoverageInput): CoverageReport {
  const runs = [...input.runs].sort((a, b) => a.night.localeCompare(b.night));
  const last = [...runs].reverse().find((r) => r.ran);
  const graded = new Set(Object.keys(last?.grades ?? {}));
  const unknown = input.inventory.filter((s) => !graded.has(s));
  const missedNights = runs.filter((r) => !r.ran).map((r) => r.night);
  const changeNights = new Set((input.skillChanges ?? []).map((c) => c.slice(0, 10)));
  const gapsAfterUpdates = missedNights.filter((n) => {
    if (changeNights.has(n)) return true;
    const prev = new Date(Date.parse(`${n}T00:00:00Z`) - 86400000).toISOString().slice(0, 10);
    return changeNights.has(prev);
  });
  const leftScanning = (input.previousSkills ?? []).filter(
    (s) => input.inventory.includes(s) && !graded.has(s),
  );
  // Fixed cohort: skills graded in every run that ran, so the trend is like-for-like.
  const ranRuns = runs.filter((r) => r.ran);
  const cohort = ranRuns.length
    ? Object.keys(ranRuns[0]?.grades ?? {}).filter((s) => ranRuns.every((r) => r.grades?.[s]))
    : [];
  const cohortTrend = runs.map((r) => ({
    night: r.night,
    grade: r.ran ? avgGrade(cohort.map((s) => r.grades?.[s] ?? 'F')) : ('not-run' as const),
  }));
  const maxGap = input.maxGapNights ?? 1;
  let refusal: string | undefined;
  if (missedNights.length > maxGap)
    refusal = `${missedNights.length} empty nights (${missedNights.join(', ')}); refusing to grade over more than ${maxGap}`;
  else if (gapsAfterUpdates.length)
    refusal = `a missed run touches an update window (${gapsAfterUpdates.join(', ')}); refusing to grade`;
  else if (!last) refusal = 'no run in the window';
  const rulesetStale = Boolean(
    input.currentRulesetHash && last?.rulesetHash && last.rulesetHash !== input.currentRulesetHash,
  );
  const total = input.inventory.length;
  const checked = total - unknown.length;
  const headline =
    `checked ${checked} of ${total}` +
    (unknown.length ? `, ${unknown.length} unknown` : '') +
    (missedNights.length ? `, ${missedNights.length} gap(s)` : '') +
    (gapsAfterUpdates.length ? ` (${gapsAfterUpdates.length} right after updates)` : '');
  const grade = refusal ? undefined : avgGrade([...graded].map((s) => last?.grades?.[s] ?? 'F'));
  return {
    headline,
    checked,
    total,
    unknown,
    missedNights,
    gapsAfterUpdates,
    graded: !refusal,
    ...(refusal ? { refusal } : {}),
    ...(grade ? { grade } : {}),
    ...(last?.rulesetHash ? { rulesetHash: last.rulesetHash } : {}),
    rulesetStale,
    leftScanning,
    cohort,
    cohortTrend,
  };
}

/** Declared vs granted vs used access, as separate findings, plus unmodelled actors. */
export interface AccessInput {
  skill: string;
  declared: string[];
  granted: string[];
  used: string[];
  /** Processes that consumed a credential or mount. */
  consumers?: string[];
  /** Processes in the skill's dependency graph. */
  dependencyGraph?: string[];
}
export function accessRows(rows: AccessInput[]) {
  return rows.map((r) => {
    const d = new Set(r.declared);
    const g = new Set(r.granted);
    const graph = new Set(r.dependencyGraph ?? []);
    return {
      skill: r.skill,
      grantedNotDeclared: r.granted.filter((x) => !d.has(x)),
      usedNotDeclared: r.used.filter((x) => !d.has(x)),
      usedNotGranted: r.used.filter((x) => !g.has(x)),
      declaredUnused: r.declared.filter((x) => !r.used.includes(x)),
      /** Access the context grants that no skill declared. */
      ambient: r.granted.filter((x) => !d.has(x) && !r.used.includes(x)),
      unmodelledActors: (r.consumers ?? []).filter((c) => !graph.has(c)),
    };
  });
}

/** Explained is not resolved: the party that caused the drift can only explain it. */
export interface DriftFinding {
  id: string;
  causedBy: string;
  driftedSha256: string;
  explanation?: { by: string; artifact?: { path: string; sha256: string; writtenAt: string } };
  resolution?: { by: string };
  detectedAt: string;
}
export function driftState(f: DriftFinding): 'open' | 'explained' | 'resolved' | 'rejected' {
  if (f.resolution) return f.resolution.by !== f.causedBy ? 'resolved' : 'rejected';
  if (!f.explanation) return 'open';
  const a = f.explanation.artifact;
  if (f.explanation.by === f.causedBy) {
    if (!a || a.sha256 !== f.driftedSha256 || Date.parse(a.writtenAt) > Date.parse(f.detectedAt))
      return 'rejected';
  }
  return 'explained';
}
