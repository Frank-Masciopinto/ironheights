/**
 * Fleet posture: ignore debt and per-machine rows (0.28.0, ideas from Moltbook bots).
 *
 * - An ignore is bound to the hash of the finding it hides and dies when the finding changes.
 * - "Ignore debt" (age of the oldest live ignore) sits next to the grade, with both grades.
 * - One row per machine; the fleet grade is a conjunction, never an average: any running copy
 *   that was not checked, or whose executed file hash differs from the checked one, holds it back.
 */
export interface Finding {
  id: string;
  sha256: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}
export interface Ignore {
  findingId: string;
  findingSha256: string;
  createdAt: string;
  expiresAt?: string;
  by?: string;
}

const GRADES = ['A', 'B', 'C', 'D', 'F'] as const;
type Grade = (typeof GRADES)[number];
const gradeOf = (f: Finding[]): Grade =>
  f.some((x) => x.severity === 'critical')
    ? 'F'
    : f.some((x) => x.severity === 'high')
      ? 'D'
      : f.filter((x) => x.severity === 'medium').length > 2
        ? 'C'
        : f.length
          ? 'B'
          : 'A';

export function ignoreDebt(findings: Finding[], ignores: Ignore[], now: Date = new Date()) {
  const live = ignores.filter(
    (i) =>
      (!i.expiresAt || Date.parse(i.expiresAt) > now.getTime()) &&
      findings.some((f) => f.id === i.findingId && f.sha256 === i.findingSha256),
  );
  const dead = ignores
    .filter((i) => !live.includes(i))
    .map((i) => ({
      findingId: i.findingId,
      reason:
        i.expiresAt && Date.parse(i.expiresAt) <= now.getTime()
          ? 'expired'
          : findings.some((f) => f.id === i.findingId)
            ? 'finding changed'
            : 'finding gone',
    }));
  const visible = findings.filter((f) => !live.some((i) => i.findingId === f.id));
  const withIgnores = gradeOf(visible);
  const without = gradeOf(findings);
  const oldest = live.reduce<number | undefined>(
    (m, i) => (m === undefined || Date.parse(i.createdAt) < m ? Date.parse(i.createdAt) : m),
    undefined,
  );
  const debtDays = oldest === undefined ? 0 : Math.floor((now.getTime() - oldest) / 86_400_000);
  const gap = GRADES.indexOf(without) - GRADES.indexOf(withIgnores);
  return {
    grade: withIgnores,
    gradeWithoutIgnores: without,
    ignoreDebtDays: debtDays,
    liveIgnores: live.length,
    deadIgnores: dead,
    notify: gap > 1,
    headline: `grade ${withIgnores} (${without} without ignores), ignore debt ${debtDays}d over ${live.length} ignore(s)`,
  };
}

export interface RunningCopy {
  machine: string;
  skill: string;
  /** Hash of the file actually executed (resolved entrypoint), as reported by the loader. */
  executedSha256?: string;
  checkedSha256?: string;
  checkedOnHost?: boolean;
  lastRan?: string;
}

export interface MachineRow {
  machine: string;
  copies: number;
  unchecked: string[];
  hashMismatch: string[];
  clean: boolean;
}

export function machineRows(copies: RunningCopy[], inventory: string[] = []) {
  const machines = [...new Set([...inventory, ...copies.map((c) => c.machine)])].sort();
  const rows: MachineRow[] = machines.map((m) => {
    const mine = copies.filter((c) => c.machine === m);
    const unchecked = mine.filter((c) => !c.checkedSha256 || !c.checkedOnHost).map((c) => c.skill);
    const hashMismatch = mine
      .filter(
        (c) =>
          c.checkedSha256 &&
          (!c.executedSha256 || c.executedSha256.toLowerCase() !== c.checkedSha256.toLowerCase()),
      )
      .map((c) => c.skill);
    return {
      machine: m,
      copies: mine.length,
      unchecked,
      hashMismatch,
      clean: mine.length > 0 && !unchecked.length && !hashMismatch.length,
    };
  });
  const noRows = rows.filter((r) => r.copies === 0).map((r) => r.machine);
  return {
    rows,
    unscannedMachines: noRows,
    fleetClean: rows.length > 0 && rows.every((r) => r.clean),
    claim: rows.every((r) => r.clean)
      ? 'every executing copy was checked on its host'
      : 'not clean: at least one running copy is unchecked, mismatched or on a machine with no row',
  };
}
