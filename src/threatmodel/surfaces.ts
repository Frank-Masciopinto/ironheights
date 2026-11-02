/**
 * Execution surfaces, concurrency and call budgets (0.28.0, ideas from Moltbook bots).
 *
 * A surface is where a skill runs, whose credential it runs under and how often it runs.
 * Changing any of those three without editing the threat model fails the PR.
 */
import { readdir, readFile } from 'node:fs/promises';
import { join, relative } from 'node:path';

export interface Surface {
  /** Stable id, e.g. "workflow:.github/workflows/nightly.yml#scan". */
  id: string;
  credential?: string;
  schedule?: string;
  location?: string;
  /** Declared max concurrent copies (threat model side). */
  maxConcurrent?: number;
  /** Shared write paths this surface writes to. */
  writes?: string[];
  locked?: boolean;
}

export interface SurfaceFinding {
  code: string;
  severity: 'fail' | 'warn';
  message: string;
}

/** Fail when a PR changes whose credential, how often or where, unless the model file changed too. */
export function surfaceChanges(
  base: Surface[],
  head: Surface[],
  threatModelChanged: boolean,
): SurfaceFinding[] {
  if (threatModelChanged) return [];
  const out: SurfaceFinding[] = [];
  const b = new Map(base.map((s) => [s.id, s]));
  for (const h of head) {
    const o = b.get(h.id);
    if (!o) {
      out.push({
        code: 'surface-added',
        severity: 'fail',
        message: `new surface ${h.id} without a threat-model change in the same PR`,
      });
      continue;
    }
    for (const [k, label] of [
      ['credential', 'whose credential'],
      ['schedule', 'how often'],
      ['location', 'where'],
    ] as const)
      if ((o[k] ?? '') !== (h[k] ?? ''))
        out.push({
          code: `surface-${k}-changed`,
          severity: 'fail',
          message: `${h.id}: ${label} changed (${o[k] ?? '-'} -> ${h[k] ?? '-'}) without a threat-model change in the same PR`,
        });
  }
  return out;
}

/** Derive surfaces from the repo itself: workflows (schedule + secrets), crontabs, container files. */
export async function deriveSurfaces(root: string): Promise<Surface[]> {
  const out: Surface[] = [];
  const wf = join(root, '.github', 'workflows');
  for (const f of await readdir(wf).catch(() => [] as string[])) {
    if (!/\.ya?ml$/.test(f)) continue;
    const text = await readFile(join(wf, f), 'utf8');
    const cron = [...text.matchAll(/cron:\s*['"]?([^'"\n]+)['"]?/g)].map((m) =>
      (m[1] ?? '').trim(),
    );
    const secrets = [...new Set([...text.matchAll(/secrets\.([A-Z0-9_]+)/g)].map((m) => m[1]))];
    const runsOn = /runs-on:\s*([^\n]+)/.exec(text)?.[1]?.trim();
    out.push({
      id: `workflow:.github/workflows/${f}`,
      ...(secrets.length ? { credential: secrets.sort().join(',') } : {}),
      ...(cron.length ? { schedule: cron.join(';') } : {}),
      ...(runsOn ? { location: runsOn } : {}),
    });
  }
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (depth > 3) return;
    for (const e of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
      if (e.name === 'node_modules' || e.name === '.git') continue;
      const p = join(dir, e.name);
      if (e.isDirectory()) await walk(p, depth + 1);
      else if (/^(crontab|.*\.cron)$/.test(e.name)) {
        const lines = (await readFile(p, 'utf8'))
          .split('\n')
          .filter((l) => l.trim() && !l.startsWith('#'));
        lines.forEach((l, i) =>
          out.push({
            id: `cron:${relative(root, p)}#${i + 1}`,
            schedule: l.split(/\s+/).slice(0, 5).join(' '),
          }),
        );
      } else if (/^(Dockerfile.*|Containerfile|.*\.dockerfile)$/.test(e.name))
        out.push({ id: `container:${relative(root, p)}`, location: 'container' });
    }
  };
  await walk(root, 0);
  return out;
}

/** Every derived surface must appear in the model; model entries with no derived surface are stale. */
export function reconcileSurfaces(derived: Surface[], model: Surface[]): SurfaceFinding[] {
  const ids = new Set(model.map((m) => m.id));
  const dids = new Set(derived.map((d) => d.id));
  return [
    ...derived
      .filter((d) => !ids.has(d.id))
      .map((d) => ({
        code: 'surface-missing-from-model',
        severity: 'fail' as const,
        message: `${d.id} runs in this repo but the threat model does not list it`,
      })),
    ...model
      .filter((m) => !dids.has(m.id) && !m.id.startsWith('external:'))
      .map((m) => ({
        code: 'surface-stale-in-model',
        severity: 'warn' as const,
        message: `${m.id} is in the threat model but nothing in the repo runs it (prefix external: for surfaces outside the repo)`,
      })),
  ];
}

/** Scheduler run ledger: written by the scheduler, a second pen next to the repo file. */
export interface ConcurrencyLedger {
  surface: string;
  maxConcurrentObserved: number;
  window: string;
}

export function concurrencyFindings(
  model: Surface[],
  ledger: ConcurrencyLedger[],
): SurfaceFinding[] {
  const out: SurfaceFinding[] = [];
  for (const s of model) {
    if (s.writes?.length && s.maxConcurrent === undefined)
      out.push({
        code: 'concurrency-undeclared',
        severity: 'fail',
        message: `${s.id} writes ${s.writes.join(', ')} but declares no max concurrent copies`,
      });
    if (s.writes?.length && (s.maxConcurrent ?? 1) > 1 && !s.locked)
      out.push({
        code: 'shared-write-unlocked',
        severity: 'warn',
        message: `${s.id}: ${s.maxConcurrent} copies may write ${s.writes.join(', ')} without a lock; use a per-run directory so a double fire is visible`,
      });
    const l = ledger.find((x) => x.surface === s.id);
    if (!l) {
      if (s.maxConcurrent !== undefined)
        out.push({
          code: 'concurrency-unobserved',
          severity: 'warn',
          message: `${s.id}: no scheduler ledger row; declared max ${s.maxConcurrent} is unverified`,
        });
      continue;
    }
    if (s.maxConcurrent !== undefined && l.maxConcurrentObserved > s.maxConcurrent)
      out.push({
        code: 'concurrency-exceeded',
        severity: 'fail',
        message: `${s.id}: scheduler saw ${l.maxConcurrentObserved} concurrent copies in ${l.window}, model declares ${s.maxConcurrent}`,
      });
  }
  return out;
}

/** Call budget: contract budgets fail the PR, guideline budgets alert at runtime. */
export interface Budget {
  surface: string;
  host: string;
  kind: 'contract' | 'guideline';
  maxCallsPerTask?: number;
  maxPayloadBytes?: number;
  /** Retry wrapper cap; removing it is a contract change. */
  retryCap?: number;
}
export interface MeasuredRun {
  surface: string;
  host: string;
  callsPerTask: number;
  largestPayloadBytes: number;
  runId?: string;
}

export function budgetFindings(
  budgets: Budget[],
  measured: MeasuredRun[],
  baseBudgets: Budget[] = [],
): SurfaceFinding[] {
  const out: SurfaceFinding[] = [];
  for (const b of budgets) {
    const sev = b.kind === 'contract' ? ('fail' as const) : ('warn' as const);
    const m = measured.find((x) => x.surface === b.surface && x.host === b.host);
    const prev = baseBudgets.find((x) => x.surface === b.surface && x.host === b.host);
    if (prev?.retryCap !== undefined && b.retryCap === undefined)
      out.push({
        code: 'budget-cap-removed',
        severity: 'fail',
        message: `${b.surface} -> ${b.host}: retry cap removed`,
      });
    if (!m) {
      out.push({
        code: 'budget-unmeasured',
        severity: 'warn',
        message: `${b.surface} -> ${b.host}: no last-run measurement; the ${b.kind} budget is unchecked`,
      });
      continue;
    }
    if (b.maxCallsPerTask !== undefined && m.callsPerTask > b.maxCallsPerTask)
      out.push({
        code: 'budget-calls-exceeded',
        severity: sev,
        message: `${b.surface} -> ${b.host}: last run made ${m.callsPerTask} calls per task, ${b.kind} budget ${b.maxCallsPerTask}${m.runId ? ` (run ${m.runId})` : ''}`,
      });
    if (b.maxPayloadBytes !== undefined && m.largestPayloadBytes > b.maxPayloadBytes)
      out.push({
        code: 'budget-payload-exceeded',
        severity: sev,
        message: `${b.surface} -> ${b.host}: largest payload ${m.largestPayloadBytes} B, ${b.kind} budget ${b.maxPayloadBytes} B`,
      });
  }
  for (const p of baseBudgets)
    if (p.kind === 'contract' && !budgets.some((b) => b.surface === p.surface && b.host === p.host))
      out.push({
        code: 'budget-contract-removed',
        severity: 'fail',
        message: `${p.surface} -> ${p.host}: contract budget removed`,
      });
  return out;
}
