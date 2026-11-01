/**
 * 0.26.0 Pro-track commands, open and opt-in: `receipts` (retained signed logs and receipts)
 * and `attest` (signed "verified by Ironheights" attestation plus badge).
 */
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { UsageError } from '../../core/errors.ts';
import { verifyActivityLog } from '../../runtime/activity.ts';
import {
  badgeSvg,
  buildAttestation,
  verifyAttestation,
  type Attestation,
} from '../../premium/attest.ts';
import {
  receiptsPath,
  retentionDays,
  RetentionStore,
  type RetentionBundle,
} from '../../premium/retention.ts';
import { executeScan } from './scan.ts';

type Out = (l: string) => void;
const stdout: Out = (l) => process.stdout.write(l + '\n');

export interface ReceiptsFlags {
  action: string;
  json?: boolean;
  from?: string;
  activity?: string;
  out?: string;
  bundle?: string;
  since?: string;
  skill?: string;
  kind?: string;
  retentionDays?: number;
  env?: NodeJS.ProcessEnv;
  now?: () => Date;
  out_?: Out;
}

export async function runReceipts(f: ReceiptsFlags): Promise<number> {
  const env = f.env ?? process.env;
  const out = f.out_ ?? stdout;
  const store = await RetentionStore.open(env, f.now);
  switch (f.action) {
    case 'ingest': {
      const r = await store.ingestReceipts(resolve(f.from ?? receiptsPath(env)));
      if (f.activity) await store.ingestActivityLog(resolve(f.activity));
      const pruned = await store.prune(retentionDays(f.retentionDays, env));
      if (f.json) out(JSON.stringify({ ...r, activity: Boolean(f.activity), pruned }));
      else
        out(
          `retained ${r.added} new receipt(s), ${r.skipped} already kept or unreadable` +
            (f.activity ? '; activity log reference retained' : '') +
            (pruned.length ? `; pruned ${pruned.join(', ')}` : ''),
        );
      return 0;
    }
    case 'list': {
      const since = f.since ? Date.parse(f.since) : undefined;
      if (f.since && Number.isNaN(since)) throw new UsageError(`--since: not a date: ${f.since}`);
      const rows = (await store.records()).filter(
        (r) =>
          (since === undefined || Date.parse(r.at) >= since) &&
          (!f.skill || r.skill === f.skill) &&
          (!f.kind || r.kind === f.kind),
      );
      if (f.json) out(JSON.stringify(rows, null, 2));
      else if (!rows.length) out('no retained records');
      else
        for (const r of rows) {
          const d = r.data as Record<string, unknown>;
          out(
            `${r.at}  ${r.kind.padEnd(15)} ${r.skill ?? '-'}  ${String(d.decision ?? d.verdict ?? d.segment ?? d.file ?? '')}  ${String(d.checkId ?? '')}`.trimEnd(),
          );
        }
      return 0;
    }
    case 'export': {
      const b = await store.exportBundle();
      const text = JSON.stringify(b, null, 2) + '\n';
      if (f.out) {
        await writeFile(resolve(f.out), text);
        out(`exported ${Object.keys(b.segments).length} segment(s) to ${f.out}`);
      } else out(text.trimEnd());
      return 0;
    }
    case 'verify': {
      if (f.bundle) return verifyBundle(resolve(f.bundle), f.json, out);
      const v = await store.verify();
      if (f.json) out(JSON.stringify(v));
      else
        out(
          v.ok
            ? `retained store verified: ${v.records} record(s) in ${v.segments} segment(s)`
            : `retained store FAILED: ${v.problems.join('; ')}`,
        );
      return v.ok ? 0 : 2;
    }
    case 'prune': {
      const days = retentionDays(f.retentionDays, env);
      const removed = await store.prune(days);
      out(
        removed.length
          ? `pruned ${removed.join(', ')} (older than ${days} days)`
          : 'nothing to prune',
      );
      return 0;
    }
    default:
      throw new UsageError(
        `receipts: unknown action ${f.action} (ingest, list, export, verify, prune)`,
      );
  }
}

async function verifyBundle(file: string, json: boolean | undefined, out: Out): Promise<number> {
  const b = JSON.parse(await readFile(file, 'utf8')) as RetentionBundle;
  if (b.format !== 'ironheights-retained/1')
    throw new UsageError('not an Ironheights retention bundle');
  const tmp = await mkdtemp(join(tmpdir(), 'ih-bundle-'));
  const problems: string[] = [];
  let records = 0;
  try {
    for (const [name, text] of Object.entries(b.segments)) {
      const p = join(tmp, basename(name));
      await writeFile(p, text);
      const v = await verifyActivityLog(p, b.publicKey);
      records += v.records.length;
      if (!v.ok) problems.push(`${name}: ${v.problem}`);
    }
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
  const ok = problems.length === 0;
  if (json) out(JSON.stringify({ ok, records, problems, keyId: b.keyId }));
  else
    out(
      ok
        ? `bundle verified: ${records} record(s), key ${b.keyId}`
        : `bundle FAILED: ${problems.join('; ')}`,
    );
  return ok ? 0 : 2;
}

export interface AttestFlags {
  skill: string;
  out?: string;
  badge?: string;
  verify?: string;
  publicKey?: string;
  validDays?: number;
  config?: string;
  json?: boolean;
  env?: NodeJS.ProcessEnv;
  now?: Date;
  out_?: Out;
}

export async function runAttest(f: AttestFlags): Promise<number> {
  const env = f.env ?? process.env;
  const out = f.out_ ?? stdout;
  const dir = resolve(f.skill);
  if (f.verify) {
    const a = JSON.parse(await readFile(resolve(f.verify), 'utf8')) as Attestation;
    const trusted = f.publicKey ? await readFile(resolve(f.publicKey), 'utf8') : undefined;
    const c = await verifyAttestation(a, {
      dir,
      ...(trusted ? { trustedPublicKey: trusted } : {}),
      ...(f.now ? { now: f.now } : {}),
    });
    out(
      f.json
        ? JSON.stringify(c)
        : `${c.ok ? (c.verified ? 'VERIFIED' : 'SIGNED, NOT VERIFIED') : 'FAILED'}: ${c.reason}`,
    );
    return c.ok && c.verified ? 0 : 2;
  }
  const scan = await executeScan({
    paths: [dir],
    stdout: () => undefined,
    quiet: true,
    json: false,
    allowSkipped: false,
    noColor: true,
    env,
    ...(f.config ? { config: f.config } : {}),
  });
  const findings = scan.skills.reduce((n, s) => n + s.findings.length, 0);
  const store = await RetentionStore.open(env, f.now ? () => f.now as Date : undefined);
  const a = await buildAttestation({
    dir,
    name: scan.skills[0]?.skillName ?? basename(dir),
    verdict: scan.verdict,
    findings,
    key: store.key,
    ...(f.now ? { now: f.now } : {}),
    ...(f.validDays ? { validDays: f.validDays } : {}),
  });
  // Default next to the caller, never inside the skill: writing there would change its digest.
  const outFile = resolve(f.out ?? `${basename(dir)}.attestation.json`);
  const badgeFile = resolve(f.badge ?? outFile.replace(/\.json$/, '') + '.svg');
  await writeFile(outFile, JSON.stringify(a, null, 2) + '\n');
  await writeFile(badgeFile, badgeSvg(a.statement));
  await store.append('attestation', { ...a.statement, file: outFile }, a.statement.subject.name);
  if (f.json) out(JSON.stringify({ attestation: outFile, badge: badgeFile, ...a.statement }));
  else
    out(
      `${a.statement.verified ? 'verified' : `not verified (verdict ${a.statement.verdict})`}: ${a.statement.subject.name} ${a.statement.subject.contentDigest.slice(0, 12)}\nattestation ${outFile}\nbadge ${badgeFile}`,
    );
  return a.statement.verified ? 0 : 1;
}
