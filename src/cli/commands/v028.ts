import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { UsageError } from '../../core/errors.ts';
import {
  budgetFindings,
  concurrencyFindings,
  deriveSurfaces,
  reconcileSurfaces,
  surfaceChanges,
  type Budget,
  type ConcurrencyLedger,
  type MeasuredRun,
  type Surface,
  type SurfaceFinding,
} from '../../threatmodel/surfaces.ts';
import {
  ignoreDebt,
  machineRows,
  type Finding,
  type Ignore,
  type RunningCopy,
} from '../../report/fleetposture.ts';
import { auditRunReceipts, writeRunReceipt, type RunReceipt } from '../../premium/runreceipt.ts';

type Out = (l: string) => void;
const stdout: Out = (l) => process.stdout.write(l + '\n');
async function readJson<T>(file: string | undefined, flag: string): Promise<T> {
  if (!file) throw new UsageError(`${flag} <file> is required`);
  try {
    return JSON.parse(await readFile(resolve(file), 'utf8')) as T;
  } catch (e) {
    throw new UsageError(`${flag}: cannot read JSON from ${file}: ${(e as Error).message}`);
  }
}

/** `ironheights surfaces --input surfaces.json [--repo .]`: execution surfaces, concurrency, budgets. */
export async function runSurfaces(f: {
  input?: string;
  repo?: string;
  json?: boolean;
  out?: Out;
}): Promise<number> {
  const out = f.out ?? stdout;
  const i = await readJson<{
    base?: Surface[];
    head?: Surface[];
    threatModelChanged?: boolean;
    model?: Surface[];
    ledger?: ConcurrencyLedger[];
    budgets?: Budget[];
    baseBudgets?: Budget[];
    measured?: MeasuredRun[];
  }>(f.input, '--input');
  const derived = f.repo ? await deriveSurfaces(resolve(f.repo)) : [];
  const findings: SurfaceFinding[] = [
    ...(i.base && i.head ? surfaceChanges(i.base, i.head, Boolean(i.threatModelChanged)) : []),
    ...(f.repo ? reconcileSurfaces(derived, i.model ?? []) : []),
    ...(i.model ? concurrencyFindings(i.model, i.ledger ?? []) : []),
    ...(i.budgets ? budgetFindings(i.budgets, i.measured ?? [], i.baseBudgets ?? []) : []),
  ];
  if (f.json) out(JSON.stringify({ derived, findings }, null, 2));
  else if (!findings.length) out('surfaces: no undeclared surface, concurrency or budget change');
  else for (const x of findings) out(`${x.severity.toUpperCase()} ${x.code}: ${x.message}`);
  return findings.some((x) => x.severity === 'fail') ? 2 : 0;
}

/** `ironheights fleet-posture --input fleet.json`: ignore debt and per-machine rows. */
export async function runFleetPosture(f: {
  input?: string;
  json?: boolean;
  now?: Date;
  out?: Out;
}): Promise<number> {
  const out = f.out ?? stdout;
  const i = await readJson<{
    findings?: Finding[];
    ignores?: Ignore[];
    copies?: RunningCopy[];
    machines?: string[];
  }>(f.input, '--input');
  const debt = ignoreDebt(i.findings ?? [], i.ignores ?? [], f.now);
  const fleet = machineRows(i.copies ?? [], i.machines ?? []);
  if (f.json) out(JSON.stringify({ ...debt, ...fleet }, null, 2));
  else {
    out(debt.headline);
    if (debt.notify) out('NOTICE: ignores move the grade by more than one letter; review them');
    for (const d of debt.deadIgnores)
      out(`ignore on ${d.findingId} no longer applies: ${d.reason}`);
    for (const r of fleet.rows)
      out(
        `${r.machine}: ${r.copies} copy(ies) ${r.clean ? 'clean' : `NOT clean${r.unchecked.length ? `; unchecked ${r.unchecked.join(',')}` : ''}${r.hashMismatch.length ? `; executed hash differs ${r.hashMismatch.join(',')}` : ''}${r.copies === 0 ? '; no row (unscanned)' : ''}`}`,
      );
    out(fleet.claim);
  }
  return fleet.fleetClean ? 0 : 2;
}

/** `ironheights run-receipt write --input r.json` | `ironheights run-receipt audit`. */
export async function runRunReceipt(f: {
  action: string;
  input?: string;
  json?: boolean;
  env?: NodeJS.ProcessEnv;
  out?: Out;
}): Promise<number> {
  const out = f.out ?? stdout;
  const env = f.env ?? process.env;
  if (f.action === 'write') {
    const r = await readJson<RunReceipt>(f.input, '--input');
    try {
      const rec = await writeRunReceipt(r, env);
      out(
        f.json
          ? JSON.stringify(rec)
          : `receipt #${rec.seq}: ${r.skill} on ${r.machine}/${r.copyId}`,
      );
      return 0;
    } catch (e) {
      throw new UsageError((e as Error).message);
    }
  }
  if (f.action === 'audit') {
    const a = await auditRunReceipts(env);
    if (f.json) out(JSON.stringify(a, null, 2));
    else {
      out(
        `chain ${a.chain.ok ? 'intact' : `BROKEN: ${a.chain.problem}`}; ${a.rows.length} receipt(s) over ${a.copies} running copy(ies); ${a.unapproved} without an approver of the loaded hash`,
      );
      for (const r of a.rows)
        out(
          `#${r.seq} ${r.machine}/${r.copyId} ${r.skill} ${r.loadedSha256.slice(0, 12)} trigger=${r.trigger} ${r.approved ? `approved by ${r.approver}` : 'NOT approved for this hash'}`,
        );
    }
    return a.chain.ok && a.unapproved === 0 ? 0 : 2;
  }
  throw new UsageError(`run-receipt: unknown action ${f.action} (write, audit)`);
}
