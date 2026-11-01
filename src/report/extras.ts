/**
 * Posture report additions in 0.24.0 (suggested by Moltbook bots; credits in CHANGELOG):
 * grade stamps that expire on age or change, refusal rows, loss-path lanes, a per-skill fix
 * lifecycle that only closes on runtime evidence, leftovers of removed skills, environment
 * stamps that keep trends apart, reversal rate from MCP receipts, and a change log between
 * runs. Inputs are local files; nothing leaves the machine.
 */
import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { hostname } from 'node:os';
import { join, resolve } from 'node:path';
import { contentDigest } from '../mcp/receipts.ts';

export type Consequence = 'credential-or-exec' | 'write-or-egress' | 'read-only';

export interface GradeStamp {
  grade: string;
  gradedAt: string;
  gradedAgainstVersion: string;
  /** sha256 over the skill files that were graded. Any change invalidates the grade. */
  contentHash: string | null;
  consequence: Consequence;
  /** Hard cutoff: after this the grade is greyed, whatever its colour. */
  validUntil: string;
  /** Plain words: "true as of ..., recheck before approving anything after ...". */
  validity: string;
  /** What the grade was computed from: the rules and the reach evidence behind it. */
  evidence: string[];
}

export function consequenceOf(reach: string): Consequence {
  if (reach === 'exec' || reach === 'secrets') return 'credential-or-exec';
  if (reach === 'outside-write' || reach === 'undeclared-network' || reach === 'declared-network')
    return 'write-or-egress';
  return 'read-only';
}

const FACTOR: Record<Consequence, number> = {
  'credential-or-exec': 0.25,
  'write-or-egress': 0.5,
  'read-only': 1,
};

export async function gradeStamp(
  root: string,
  grade: string,
  reach: string,
  version: string,
  now: Date,
  validDays: number,
  evidence: string[] = [],
): Promise<GradeStamp> {
  const d = await contentDigest(root).catch(() => ({ digest: null }));
  const consequence = consequenceOf(reach);
  const ms = Math.max(3_600_000, validDays * FACTOR[consequence] * 86_400_000);
  const until = new Date(now.getTime() + ms);
  return {
    grade,
    gradedAt: now.toISOString(),
    gradedAgainstVersion: version,
    contentHash: d.digest,
    consequence,
    validUntil: until.toISOString(),
    evidence,
    validity: `true as of ${now.toISOString().slice(0, 16)}Z; recheck before approving anything after ${until.toISOString().slice(0, 16)}Z`,
  };
}

/* ---------------- refusals ---------------- */

export const NEXT_ACTIONS = [
  'retry-unchanged',
  'retry-mutated',
  'switch-tool',
  'switch-approved-source',
  'route-around',
  'stop',
] as const;
type NextAction = (typeof NEXT_ACTIONS)[number];

export interface RefusalEvent {
  at: string;
  skill?: string;
  tool?: string;
  denied: boolean;
  reason?: string;
  next?: { at?: string; action?: string; intent?: string; trace?: string };
}

export interface RefusalRow {
  denials: number;
  successes: number;
  /** Post-denial outcomes over a closed set; anything else counts as unexplained. */
  after: Record<NextAction | 'unexplained', number>;
  routeAroundRate: number | null;
  /** Two or more mutated retries in a row after denials. */
  escalatingMutations: number;
  rows: Array<{
    at: string;
    skill: string | null;
    tool: string | null;
    denial: string;
    next: string;
    gap: string;
    intent: string | null;
    rank: 'intent' | 'trace' | 'gap-only';
  }>;
}

export async function readJsonl<T>(path: string): Promise<T[]> {
  let raw = '';
  try {
    raw = await readFile(path, 'utf8');
  } catch {
    return [];
  }
  return raw
    .split('\n')
    .filter((l) => l.trim())
    .flatMap((l) => {
      try {
        return [JSON.parse(l) as T];
      } catch {
        return [];
      }
    });
}

export function refusalRow(events: RefusalEvent[]): RefusalRow {
  const after = Object.fromEntries(
    [...NEXT_ACTIONS, 'unexplained'].map((k) => [k, 0]),
  ) as RefusalRow['after'];
  const rows: RefusalRow['rows'] = [];
  let streak = 0;
  let escalating = 0;
  let denials = 0;
  for (const e of [...events].sort((a, b) => a.at.localeCompare(b.at))) {
    if (!e.denied) continue;
    denials += 1;
    const action = (NEXT_ACTIONS as readonly string[]).includes(e.next?.action ?? '')
      ? (e.next?.action as NextAction)
      : 'unexplained';
    after[action] += 1;
    streak = action === 'retry-mutated' ? streak + 1 : 0;
    if (streak === 2) escalating += 1;
    const gapS =
      e.next?.at && Number.isFinite(Date.parse(e.next.at))
        ? Math.max(0, Math.round((Date.parse(e.next.at) - Date.parse(e.at)) / 1000))
        : null;
    const intent = e.next?.intent ?? null;
    rows.push({
      at: e.at,
      skill: e.skill ?? null,
      tool: e.tool ?? null,
      denial: e.reason ?? 'denied',
      next: action,
      gap:
        gapS === null
          ? 'gap: unknown (unexplained)'
          : intent || e.next?.trace
            ? `gap: ${gapS}s`
            : `gap: ${gapS}s (unexplained)`,
      intent,
      rank: intent ? 'intent' : e.next?.trace ? 'trace' : 'gap-only',
    });
  }
  return {
    denials,
    successes: events.filter((e) => !e.denied).length,
    after,
    routeAroundRate: denials ? Math.round((after['route-around'] / denials) * 1000) / 1000 : null,
    escalatingMutations: escalating,
    rows,
  };
}

/* ---------------- lifecycle ---------------- */

export type Lifecycle =
  | 'open'
  | 'fix-available-not-applied'
  | 'applied-not-loaded'
  | 'applied-unattested'
  | 'closed';

async function installedVersion(root: string): Promise<string | null> {
  try {
    const md = await readFile(join(root, 'SKILL.md'), 'utf8');
    const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(md);
    const v = fm ? /^version:\s*['"]?([^'"\s]+)/m.exec(fm[1] as string) : null;
    if (v) return v[1] as string;
  } catch {
    /* none */
  }
  try {
    const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')) as {
      version?: string;
    };
    return pkg.version ?? null;
  } catch {
    return null;
  }
}

const cmpVer = (a: string, b: string): number => {
  const pa = a.split(/[.-]/).map((x) => Number.parseInt(x, 10) || 0);
  const pb = b.split(/[.-]/).map((x) => Number.parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d;
  }
  return 0;
};

/**
 * Derived at read time, never stored. The installed version comes from the artifact, not a
 * registry. A finding closes only when the runtime attests it loaded these exact bytes.
 */
export async function lifecycleOf(
  root: string,
  findings: number,
  hadFindingsBefore: boolean,
  contentHash: string | null,
  fixedIn: string | undefined,
  loaded: string | undefined,
): Promise<{ state: Lifecycle | null; installedVersion: string | null; gap: string }> {
  const installed = await installedVersion(root);
  if (findings > 0) {
    if (fixedIn && (!installed || cmpVer(fixedIn, installed) > 0))
      return {
        state: 'fix-available-not-applied',
        installedVersion: installed,
        gap: `fix in ${fixedIn}, installed ${installed ?? 'unknown'}`,
      };
    return { state: 'open', installedVersion: installed, gap: 'no fix recorded' };
  }
  if (!hadFindingsBefore && !loaded) return { state: null, installedVersion: installed, gap: '' };
  if (!loaded)
    return {
      state: 'applied-unattested',
      installedVersion: installed,
      gap: 'clean on disk; no runtime attestation of the loaded version',
    };
  if (loaded !== contentHash)
    return {
      state: 'applied-not-loaded',
      installedVersion: installed,
      gap: 'the running agent loaded different bytes than the ones on disk',
    };
  return { state: 'closed', installedVersion: installed, gap: '' };
}

/* ---------------- leftovers ---------------- */

export interface ArtifactRecord {
  kind: 'hook' | 'token' | 'cron' | 'file' | 'dir' | string;
  skill: string;
  path?: string;
  live?: boolean;
  expiresAt?: string;
  declared?: boolean;
  /** Skill that consumes a stored credential. */
  consumer?: string;
}

export interface LeftoverRow {
  skill: string;
  kind: string;
  path: string | null;
  severity: 'high' | 'medium' | 'info';
  capsGrade: boolean;
  detail: string;
  provenance: string;
}

export async function leftovers(
  artifacts: ArtifactRecord[],
  installed: Set<string>,
  repos: string[],
  now: Date,
): Promise<LeftoverRow[]> {
  const out: LeftoverRow[] = [];
  for (const a of artifacts) {
    const owner = a.consumer ?? a.skill;
    const present = installed.has(owner);
    const live =
      a.live !== false &&
      (a.kind === 'hook' || a.kind === 'token' || a.kind === 'cron') &&
      (!a.expiresAt || Date.parse(a.expiresAt) > now.getTime());
    if (!present) {
      out.push({
        skill: a.skill,
        kind: a.kind,
        path: a.path ?? null,
        severity: live ? 'high' : 'info',
        capsGrade: live,
        detail: live
          ? `left behind by ${a.skill}, which is no longer installed; ${a.kind === 'token' ? 'the credential still resolves to no consumer' : `the ${a.kind} is still live`}`
          : `harmless leftover of ${a.skill} (${a.kind}); remove it when convenient`,
        provenance: 'creation ledger',
      });
    } else if (a.declared === false) {
      out.push({
        skill: a.skill,
        kind: a.kind,
        path: a.path ?? null,
        severity: 'medium',
        capsGrade: false,
        detail: `${a.skill} created a ${a.kind} it never declared; uninstall would leave it behind`,
        provenance: 'creation ledger',
      });
    }
  }
  // Hooks registered in agent settings that point at a skill folder that is gone.
  for (const repo of repos) {
    for (const f of [
      '.claude/settings.json',
      '.claude/settings.local.json',
      '.cursor/hooks.json',
    ]) {
      let raw = '';
      try {
        raw = await readFile(join(repo, f), 'utf8');
      } catch {
        continue;
      }
      const cmds = [...raw.matchAll(/"command"\s*:\s*"([^"]+)"/g)].map((m) => m[1] as string);
      for (const c of cmds) {
        const m = /((?:\.claude|\.cursor|\.agents)?\/?skills\/[A-Za-z0-9_.-]+)/.exec(c);
        if (!m) continue;
        const dir = resolve(repo, (m[1] as string).replace(/^\//, ''));
        const ok = await stat(dir).then(
          () => true,
          () => false,
        );
        if (!ok)
          out.push({
            skill: (m[1] as string).split('/').pop() as string,
            kind: 'hook',
            path: `${f}: ${c.slice(0, 120)}`,
            severity: 'high',
            capsGrade: true,
            detail: `live hook in ${f} runs a command from ${m[1]}, which no longer exists`,
            provenance: 'hook registry',
          });
      }
    }
  }
  return out;
}

/* ---------------- environment ---------------- */

export interface EnvironmentStamp {
  id: string;
  imageDigest: string | null;
  skillsPaths: string[];
  /** sha256 over the content digests of every inspected skill (bind mounts included). */
  inspectedDigest: string;
}

export function environmentStamp(
  opts: { envId?: string; imageDigest?: string; env?: NodeJS.ProcessEnv },
  skillsPaths: string[],
  contentHashes: string[],
): EnvironmentStamp {
  const env = opts.env ?? process.env;
  const id =
    opts.envId ??
    env.IRONHEIGHTS_ENV_ID ??
    `host-${createHash('sha256').update(hostname()).digest('hex').slice(0, 12)}`;
  return {
    id,
    imageDigest: opts.imageDigest ?? env.IRONHEIGHTS_IMAGE_DIGEST ?? null,
    skillsPaths: [...new Set(skillsPaths)].sort(),
    inspectedDigest: createHash('sha256')
      .update([...contentHashes].sort().join('\n'))
      .digest('hex'),
  };
}

/* ---------------- reversal rate ---------------- */

export interface ReversalStats {
  window: number;
  shortlists: number;
  withAlternative: number;
  reversals: number;
  rate: number | null;
  shortlistSizes: number[];
  lateChecks: number;
  medianCheckMinusDecisionMs: number | null;
  /** Check time minus decision time stayed positive: the check is not informing picks. */
  failedControl: boolean;
  label: string;
}

export function reversalStats(
  receipts: Array<Record<string, unknown>>,
  window = 20,
): ReversalStats {
  const lists = receipts.filter((r) => r.event === 'shortlist').slice(-window);
  const checks = receipts
    .filter((r) => r.event === 'check' || r.event === 'late-check')
    .slice(-window);
  const sizes = lists.map((r) =>
    Number((r.shortlist as Record<string, unknown> | undefined)?.size ?? 0),
  );
  const live = lists.filter(
    (r) => Number((r.shortlist as Record<string, unknown> | undefined)?.size ?? 0) >= 2,
  );
  const reversals = live.filter(
    (r) => (r.shortlist as Record<string, unknown> | undefined)?.changesPick === true,
  ).length;
  const deltas = checks
    .map((r) => (r.timing as Record<string, unknown> | undefined)?.checkMinusDecisionMs)
    .filter((x): x is number => typeof x === 'number')
    .sort((a, b) => a - b);
  const median = deltas.length ? (deltas[Math.floor(deltas.length / 2)] as number) : null;
  const late = checks.filter((r) => r.event === 'late-check').length;
  const failedControl = deltas.length >= 3 && deltas.every((d) => d > 0);
  const rate = live.length ? Math.round((reversals / live.length) * 1000) / 1000 : null;
  const label = !live.length
    ? `no shortlists with 2+ candidates in the last ${window} checks: nothing to reverse`
    : reversals === 0
      ? `0 reversals in the last ${live.length} shortlist(s) with a live alternative: late, not clean (checks may arrive after the decision)`
      : `${reversals} of ${live.length} shortlist(s) changed the pick in the last ${window}`;
  return {
    window,
    shortlists: lists.length,
    withAlternative: live.length,
    reversals,
    rate,
    shortlistSizes: sizes,
    lateChecks: late,
    medianCheckMinusDecisionMs: median,
    failedControl,
    label,
  };
}
