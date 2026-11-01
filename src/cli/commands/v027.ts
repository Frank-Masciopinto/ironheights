import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { UsageError } from '../../core/errors.ts';
import {
  accessRows,
  coverageReport,
  driftState,
  type AccessInput,
  type CoverageInput,
  type DriftFinding,
} from '../../report/coverage.ts';
import {
  diffAuthority,
  removalLeftovers,
  sharedPathReaders,
  unreachedKnobs,
  type AuthorityFinding,
} from '../../threatmodel/authority.ts';
import { appendRecord, auditRecords, type InstallRecord } from '../../premium/installrecord.ts';

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

/** `ironheights coverage --input runs.json`: coverage first, grade only when whole. */
export async function runCoverage(f: {
  input?: string;
  json?: boolean;
  out?: Out;
}): Promise<number> {
  const out = f.out ?? stdout;
  const input = await readJson<CoverageInput & { access?: AccessInput[]; drift?: DriftFinding[] }>(
    f.input,
    '--input',
  );
  const rep = coverageReport(input);
  const access = accessRows(input.access ?? []);
  const drift = (input.drift ?? []).map((d) => ({ id: d.id, state: driftState(d) }));
  if (f.json) out(JSON.stringify({ ...rep, access, drift }, null, 2));
  else {
    out(rep.headline);
    out(
      rep.graded
        ? `grade ${rep.grade} (rules ${rep.rulesetHash ?? 'unknown'}${rep.rulesetStale ? ', STALE: rules changed since' : ''})`
        : `not graded: ${rep.refusal}`,
    );
    if (rep.leftScanning.length)
      out(`left scanning (possible hidden vectors): ${rep.leftScanning.join(', ')}`);
    out(
      `fixed cohort (${rep.cohort.length}): ${rep.cohortTrend.map((t) => `${t.night}=${t.grade}`).join(' ')}`,
    );
    for (const a of access)
      if (a.usedNotDeclared.length || a.ambient.length || a.unmodelledActors.length)
        out(
          `${a.skill}: used-not-declared ${a.usedNotDeclared.join(',') || '-'}; ambient ${a.ambient.join(',') || '-'}; unmodelled actors ${a.unmodelledActors.join(',') || '-'}`,
        );
    for (const d of drift) out(`drift ${d.id}: ${d.state}`);
  }
  return rep.graded && !rep.rulesetStale ? 0 : 2;
}

/** `ironheights authority --input authority.json`: runner authority, knobs, leftovers, shared paths. */
export async function runAuthority(f: {
  input?: string;
  json?: boolean;
  out?: Out;
}): Promise<number> {
  const out = f.out ?? stdout;
  const i = await readJson<{
    baseline?: Parameters<typeof diffAuthority>[0];
    current?: Parameters<typeof diffAuthority>[1];
    knobs?: { before: string[]; after: string[]; reachLines: Record<string, string> };
    removal?: {
      leftovers: Parameters<typeof removalLeftovers>[0];
      provenGone: Parameters<typeof removalLeftovers>[1];
    };
    sharedPaths?: {
      writers: Parameters<typeof sharedPathReaders>[0];
      newReaders: Parameters<typeof sharedPathReaders>[1];
      overrides?: Parameters<typeof sharedPathReaders>[2];
    };
  }>(f.input, '--input');
  const findings: AuthorityFinding[] = [
    ...diffAuthority(i.baseline ?? [], i.current ?? []),
    ...(i.knobs ? unreachedKnobs(i.knobs.before, i.knobs.after, i.knobs.reachLines) : []),
    ...(i.removal ? removalLeftovers(i.removal.leftovers, i.removal.provenGone) : []),
    ...(i.sharedPaths
      ? sharedPathReaders(i.sharedPaths.writers, i.sharedPaths.newReaders, i.sharedPaths.overrides)
      : []),
  ];
  if (f.json) out(JSON.stringify({ findings }, null, 2));
  else if (!findings.length) out('authority: no growth, no leftovers');
  else for (const x of findings) out(`${x.severity.toUpperCase()} ${x.code}: ${x.message}`);
  return findings.some((x) => x.severity === 'fail') ? 2 : 0;
}

/** `ironheights record approve --input rec.json` | `ironheights record audit`. */
export async function runRecord(f: {
  action: string;
  input?: string;
  json?: boolean;
  env?: NodeJS.ProcessEnv;
  out?: Out;
}): Promise<number> {
  const out = f.out ?? stdout;
  const env = f.env ?? process.env;
  if (f.action === 'approve') {
    const rec = await readJson<InstallRecord>(f.input, '--input');
    try {
      const r = await appendRecord(rec, env);
      out(
        f.json
          ? JSON.stringify(r)
          : `recorded #${r.seq}: ${rec.approver} approved ${rec.skill}@${rec.version}`,
      );
      return 0;
    } catch (e) {
      throw new UsageError((e as Error).message);
    }
  }
  if (f.action === 'audit') {
    const a = await auditRecords(env);
    if (f.json) out(JSON.stringify(a, null, 2));
    else {
      out(
        `chain ${a.chain.ok ? 'intact' : `BROKEN: ${a.chain.problem}`}; ${a.rows.length} record(s), ${Math.round(a.acceptedRate * 100)}% auditor-accepted`,
      );
      for (const r of a.rows)
        out(
          `#${r.seq} ${r.skill}@${r.version} by ${r.approver || '-'}: ${r.accepted ? 'accepted' : [!r.hashMatches && 'hash differs', r.inherited && 'inherited', r.scopeExpired && 'scope expired', !r.approverPresent && 'no approver'].filter(Boolean).join(', ') || 'chain broken'}`,
        );
    }
    return a.chain.ok && a.rows.every((r) => r.accepted) ? 0 : 2;
  }
  throw new UsageError(`record: unknown action ${f.action} (approve, audit)`);
}
