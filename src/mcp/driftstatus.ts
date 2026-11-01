/**
 * drift_status answers (0.24.0). Every answer leads with its own limits: what kind of baseline
 * it compares against, when that baseline was born and under which capability. A skill with
 * no baseline is `unknown`, never clean. A hold is keyed to the capability requested on this
 * call, not to the baseline's age: reads pass with the label, calls with outside side effects
 * (write, network, credentials, send) hold when the baseline is missing, the bytes moved, or
 * the request goes beyond what the newest baseline row was taken under.
 */
import { readLedger, snapshotSkill, diffSkill, type DriftChange } from '../drift/drift.ts';

export const SIDE_EFFECTS = new Set(['write', 'network', 'credentials', 'send', 'shell']);
const CAPS = ['read', 'write', 'network', 'credentials', 'send', 'shell'];

export interface SkillDriftAnswer {
  /** Provenance first: baseline kind, birth date and birth capability. */
  label: string;
  skill: string;
  status: 'unknown' | 'matches' | 'drifted';
  decision: 'allow' | 'hold';
  holdReason?: string;
  requested: string | null;
  baseline: {
    kind: 'approval' | 'adoption' | 'none';
    birthDate: string | null;
    birthCapability: string[];
    latestDate: string | null;
    latestCapability: string[];
    currentCapability: string[];
    unobservedDays: number | null;
    narrowing: 'none' | 'confirmed' | 'unconfirmed';
    widenBack: string[];
    rows: number;
  };
  changes: DriftChange[];
}

const day = (iso: string): string => iso.slice(0, 10);

export async function driftAnswers(
  paths: string[],
  ledgerPath: string,
  requestedRaw: unknown,
  now = new Date(),
): Promise<SkillDriftAnswer[]> {
  const requested =
    typeof requestedRaw === 'string' && CAPS.includes(requestedRaw) ? requestedRaw : null;
  const ledger = await readLedger(ledgerPath);
  const out: SkillDriftAnswer[] = [];
  for (const p of paths) {
    const snap = await snapshotSkill(p, now);
    const current = snap.capabilities ?? [];
    const before = ledger.skills[snap.root];
    if (!before) {
      const side = requested ? SIDE_EFFECTS.has(requested) : false;
      out.push({
        label: `unmeasured: no baseline for this skill; this answer is not a clean receipt for its history. Hash it today as a first true reading with: ironheights drift approve --adopt ${snap.root}`,
        skill: snap.root,
        status: 'unknown',
        decision: side ? 'hold' : 'allow',
        ...(side ? { holdReason: `no baseline and this call asks for ${requested}` } : {}),
        requested,
        baseline: {
          kind: 'none',
          birthDate: null,
          birthCapability: [],
          latestDate: null,
          latestCapability: [],
          currentCapability: current,
          unobservedDays: null,
          narrowing: 'none',
          widenBack: [],
          rows: 0,
        },
        changes: [],
      });
      continue;
    }
    const rows = before.baselines ?? [
      {
        at: before.approvedAt,
        capabilities: before.capabilities ?? current,
        kind: before.baselineKind ?? 'approval',
      },
    ];
    const birth = rows[0] as (typeof rows)[number];
    const latest = rows[rows.length - 1] as (typeof rows)[number];
    const changes = diffSkill(before, snap);
    const narrowed = birth.capabilities.filter((c) => !latest.capabilities.includes(c));
    // Narrowing relaxes a hold only after a fresh review confirms the bytes match that row.
    const narrowing: SkillDriftAnswer['baseline']['narrowing'] = !narrowed.length
      ? 'none'
      : changes.length === 0
        ? 'confirmed'
        : 'unconfirmed';
    const judgeAgainst =
      narrowing === 'unconfirmed'
        ? [...new Set([...birth.capabilities, ...latest.capabilities])]
        : latest.capabilities;
    const beyondLatest = current.filter((c) => !latest.capabilities.includes(c));
    const widenBack = beyondLatest.filter((c) => birth.capabilities.includes(c));
    const kind = before.baselineKind ?? birth.kind;
    const label = `${kind === 'adoption' ? 'baseline by adoption' : 'baseline at approval'}, ${day(birth.at)}, born under ${birth.capabilities.length ? birth.capabilities.join('+') : 'read-only'}${rows.length > 1 ? `; newest row ${day(latest.at)} under ${latest.capabilities.join('+') || 'read-only'}` : ''}${narrowing === 'unconfirmed' ? '; narrowing unconfirmed' : ''}`;
    let holdReason: string | undefined;
    if (requested && SIDE_EFFECTS.has(requested)) {
      if (changes.length) holdReason = 'the bytes moved since the baseline';
      else if (!judgeAgainst.includes(requested))
        holdReason = `${requested} is beyond the capability the baseline was taken under (drift by definition)`;
    }
    if (!holdReason && requested && SIDE_EFFECTS.has(requested) && widenBack.length)
      holdReason = `widen-back: ${widenBack.join(', ')} was narrowed away and is back`;
    const widenChanges: DriftChange[] = beyondLatest.map((c) => ({
      kind: 'capability-widened',
      severity: 'high',
      target: snap.root,
      detail: `capability ${c} not in the newest baseline row${widenBack.includes(c) ? ' (widen-back: the birth row wanted this power before)' : ''}`,
    }));
    out.push({
      label,
      skill: snap.root,
      status: changes.length || beyondLatest.length ? 'drifted' : 'matches',
      decision: holdReason ? 'hold' : 'allow',
      ...(holdReason ? { holdReason } : {}),
      requested,
      baseline: {
        kind,
        birthDate: birth.at,
        birthCapability: birth.capabilities,
        latestDate: latest.at,
        latestCapability: latest.capabilities,
        currentCapability: current,
        unobservedDays: Math.floor((now.getTime() - Date.parse(latest.at)) / 86_400_000),
        narrowing,
        widenBack,
        rows: rows.length,
      },
      changes: [...changes, ...widenChanges],
    });
  }
  return out;
}
