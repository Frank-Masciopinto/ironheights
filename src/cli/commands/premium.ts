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
import { mkdir, stat } from 'node:fs/promises';
import { dirname } from 'node:path';
import { ConfigSchema, ironheightsHome } from '../../core/config.ts';
import { GuardPolicySchema } from '../../guard/load.ts';
import { GUARD_POLICY_NAME } from '../../guard/types.ts';
import { emitAlert, verifyAlert } from '../../premium/alerts.ts';
import {
  buildInventory,
  inventoryBot,
  parseTarget,
  signInventory,
  verifyInventory,
  type FleetBot,
  type SignedInventory,
} from '../../premium/fleet.ts';
import { TEMPLATES } from '../../premium/policy.ts';
import { createPublicKey, sign, verify } from 'node:crypto';
import { parseSkillRef } from '../../net/clawhub.ts';
import { rulesetHash } from '../../mcp/receipts.ts';
import { isDir } from '../../runtime/sandbox.ts';
import { TOOL_VERSION } from '../../version.ts';
import { stable, type AttestationSource } from '../../premium/attest.ts';
import { computeReputation, signReputation } from '../../premium/reputation.ts';
import { stageSkill } from './fetch.ts';
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
      if (f.bundle) return verifyBundle(resolve(f.bundle), f.json, out, env);
      const v = await store.verify();
      if (f.json) out(JSON.stringify(v));
      else
        out(
          v.ok
            ? `retained store verified: ${v.records} record(s) in ${v.segments} segment(s)`
            : `retained store FAILED: ${v.problems.join('; ')}`,
        );
      if (!v.ok)
        await emitAlert(
          'verify-failed',
          'retained store failed verification',
          { problems: v.problems },
          { env },
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

async function verifyBundle(
  file: string,
  json: boolean | undefined,
  out: Out,
  env: NodeJS.ProcessEnv,
): Promise<number> {
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
  if (!ok)
    await emitAlert(
      'verify-failed',
      'retention bundle failed verification',
      { file, problems },
      { env },
    );
  return ok ? 0 : 2;
}

export interface AttestFlags {
  skill?: string;
  out?: string;
  badge?: string;
  verify?: string;
  publicKey?: string;
  validDays?: number;
  config?: string;
  json?: boolean;
  /** Batch: a file listing skills (one per line, or a JSON array). */
  batch?: string;
  outDir?: string;
  env?: NodeJS.ProcessEnv;
  now?: Date;
  fetchImpl?: typeof fetch;
  out_?: Out;
}

interface Subject {
  dir: string;
  source?: AttestationSource;
  label: string;
  cleanup: () => Promise<void>;
}

/** A local folder, or a ClawHub ref fetched read-only into a temp folder (nothing installed). */
async function resolveSubject(
  skill: string,
  f: AttestFlags,
  env: NodeJS.ProcessEnv,
): Promise<Subject> {
  if (await isDir(skill))
    return { dir: resolve(skill), label: basename(resolve(skill)), cleanup: async () => undefined };
  const ref = parseSkillRef(skill);
  const tmp = await mkdtemp(join(tmpdir(), 'ih-attest-'));
  const staged = await stageSkill({
    skill,
    quiet: true,
    env,
    out: join(tmp, 'skill'),
    ...(f.config ? { config: f.config } : {}),
    ...(f.fetchImpl ? { fetchImpl: f.fetchImpl } : {}),
  });
  const source: AttestationSource = {
    registry: 'clawhub',
    ref: `${ref.owner}/${ref.slug}@${staged.version}`,
    owner: ref.owner,
    slug: ref.slug,
    version: staged.version,
  };
  return {
    dir: staged.dir,
    source,
    label: `${ref.owner}-${ref.slug}@${staged.version}`,
    cleanup: () => rm(tmp, { recursive: true, force: true }),
  };
}

async function attestOne(
  skill: string,
  f: AttestFlags,
  env: NodeJS.ProcessEnv,
  store: RetentionStore,
  outFileFor: (label: string) => string,
): Promise<{ attestation: Attestation; file: string; badge: string }> {
  const subj = await resolveSubject(skill, f, env);
  try {
    const scan = await executeScan({
      paths: [subj.dir],
      stdout: () => undefined,
      quiet: true,
      json: false,
      allowSkipped: false,
      noColor: true,
      env,
      ...(f.config ? { config: f.config } : {}),
    });
    const a = await buildAttestation({
      dir: subj.dir,
      name: scan.skills[0]?.skillName ?? subj.label,
      verdict: scan.verdict,
      findings: scan.skills.reduce((n, s) => n + s.findings.length, 0),
      key: store.key,
      ...(f.now ? { now: f.now } : {}),
      ...(f.validDays ? { validDays: f.validDays } : {}),
      ...(subj.source ? { source: subj.source } : {}),
    });
    const file = outFileFor(subj.label);
    const badge = resolve(f.badge && !f.batch ? f.badge : file.replace(/\.json$/, '') + '.svg');
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, JSON.stringify(a, null, 2) + '\n');
    await writeFile(badge, badgeSvg(a.statement));
    await store.append('attestation', { ...a.statement, file }, a.statement.subject.name);
    return { attestation: a, file, badge };
  } finally {
    await subj.cleanup();
  }
}

export async function runAttest(f: AttestFlags): Promise<number> {
  const env = f.env ?? process.env;
  const out = f.out_ ?? stdout;
  if (f.batch) return runBatchAttest(f, env, out);
  if (!f.skill)
    throw new UsageError('attest needs a skill folder, owner/slug@version, or --batch <file>');
  if (f.verify) {
    const a = JSON.parse(await readFile(resolve(f.verify), 'utf8')) as Attestation;
    const trusted = f.publicKey ? await readFile(resolve(f.publicKey), 'utf8') : undefined;
    const subj = await resolveSubject(f.skill, f, env);
    let c;
    try {
      if (subj.source && a.statement?.source?.ref !== subj.source.ref)
        c = {
          ok: false,
          verified: false,
          reason: `attestation is for ${a.statement?.source?.ref ?? 'a local folder'}, not ${subj.source.ref}`,
        };
      else
        c = await verifyAttestation(a, {
          dir: subj.dir,
          ...(trusted ? { trustedPublicKey: trusted } : {}),
          ...(f.now ? { now: f.now } : {}),
        });
    } finally {
      await subj.cleanup();
    }
    out(
      f.json
        ? JSON.stringify(c)
        : `${c.ok ? (c.verified ? 'VERIFIED' : 'SIGNED, NOT VERIFIED') : 'FAILED'}: ${c.reason}`,
    );
    if (!c.ok)
      await emitAlert(
        'verify-failed',
        `attestation failed verification: ${c.reason}`,
        { file: f.verify, reason: c.reason },
        { env },
      );
    return c.ok && c.verified ? 0 : 2;
  }
  const store = await RetentionStore.open(env, f.now ? () => f.now as Date : undefined);
  // Default next to the caller, never inside the skill: writing there would change its digest.
  const {
    attestation: a,
    file,
    badge,
  } = await attestOne(f.skill, f, env, store, (label) =>
    resolve(f.out ?? `${label}.attestation.json`),
  );
  if (f.json) out(JSON.stringify({ attestation: file, badge, ...a.statement }));
  else
    out(
      `${a.statement.verified ? 'verified' : `not verified (verdict ${a.statement.verdict})`}: ${a.statement.source?.ref ?? a.statement.subject.name} ${a.statement.subject.contentDigest.slice(0, 12)}\nattestation ${file}\nbadge ${badge}`,
    );
  return a.statement.verified ? 0 : 1;
}

export interface BatchItem {
  input: string;
  ref: string | null;
  name: string | null;
  publisher: string | null;
  verdict: string | null;
  verified: boolean;
  contentDigest: string | null;
  attestation: string | null;
  error: string | null;
}

export async function parseBatchFile(file: string): Promise<string[]> {
  const text = (await readFile(resolve(file), 'utf8')).trim();
  if (text.startsWith('[')) {
    const arr = JSON.parse(text) as unknown;
    if (!Array.isArray(arr) || !arr.every((x) => typeof x === 'string'))
      throw new UsageError('--batch JSON must be an array of strings');
    return arr as string[];
  }
  return text
    .split('\n')
    .map((l) => l.replace(/#.*$/, '').trim())
    .filter(Boolean);
}

async function runBatchAttest(f: AttestFlags, env: NodeJS.ProcessEnv, out: Out): Promise<number> {
  const inputs = await parseBatchFile(f.batch as string);
  if (!inputs.length) throw new UsageError('--batch file lists no skills');
  const outDir = resolve(f.outDir ?? 'attestations');
  const store = await RetentionStore.open(env, f.now ? () => f.now as Date : undefined);
  const items: BatchItem[] = [];
  for (const input of inputs) {
    try {
      const r = await attestOne(input, f, env, store, (label) =>
        join(outDir, `${label.replace(/[^A-Za-z0-9@._-]/g, '_')}.attestation.json`),
      );
      const s = r.attestation.statement;
      items.push({
        input,
        ref: s.source?.ref ?? null,
        name: s.subject.name,
        publisher: s.publisher ?? null,
        verdict: s.verdict,
        verified: s.verified,
        contentDigest: s.subject.contentDigest,
        attestation: r.file,
        error: null,
      });
    } catch (e) {
      // A skill that could not be fetched or scanned is listed as an error, never as verified.
      items.push({
        input,
        ref: null,
        name: null,
        publisher: null,
        verdict: null,
        verified: false,
        contentDigest: null,
        attestation: null,
        error: (e as Error).message,
      });
    }
  }
  const counts = {
    total: items.length,
    verified: items.filter((i) => i.verified).length,
    notVerified: items.filter((i) => !i.verified && !i.error).length,
    errors: items.filter((i) => i.error).length,
  };
  const summary = {
    format: 'ironheights-batch/1' as const,
    generatedAt: (f.now ?? new Date()).toISOString(),
    version: TOOL_VERSION,
    rulesetHash: rulesetHash(),
    counts,
    items,
  };
  const signed = {
    summary,
    keyId: store.key.keyId,
    publicKey: store.key.publicPem,
    signature: sign(null, Buffer.from(stable(summary)), store.key.privateKey).toString('base64'),
  };
  const summaryFile = join(outDir, 'batch-summary.json');
  await mkdir(outDir, { recursive: true });
  await writeFile(summaryFile, JSON.stringify(signed, null, 2) + '\n');
  if (f.json) out(JSON.stringify(signed, null, 2));
  else {
    for (const i of items)
      out(
        `${i.error ? 'ERROR' : i.verified ? 'verified' : `not verified (${i.verdict})`}  ${i.ref ?? i.input}${i.error ? `: ${i.error}` : ''}`,
      );
    out(
      `batch: ${counts.verified}/${counts.total} verified, ${counts.notVerified} not verified, ${counts.errors} error(s); summary ${summaryFile}`,
    );
  }
  return counts.verified === counts.total ? 0 : 1;
}

export function verifyBatchSummary(s: {
  summary: unknown;
  publicKey: string;
  signature: string;
}): boolean {
  try {
    return verify(
      null,
      Buffer.from(stable(s.summary)),
      createPublicKey(s.publicKey),
      Buffer.from(s.signature, 'base64'),
    );
  } catch {
    return false;
  }
}

/* ---------------- publisher reputation ---------------- */

export async function runPublisherReputation(f: {
  publisher?: string;
  out?: string;
  json?: boolean;
  minSkills?: number;
  env?: NodeJS.ProcessEnv;
  now?: Date;
  out_?: Out;
}): Promise<number> {
  const env = f.env ?? process.env;
  const out = f.out_ ?? stdout;
  const store = await RetentionStore.open(env, f.now ? () => f.now as Date : undefined);
  const v = await store.verify();
  if (!v.ok)
    throw new UsageError(
      `retained store failed verification, reputation not computed: ${v.problems.join('; ')}`,
    );
  const rep = computeReputation(await store.records(), {
    ...(f.publisher ? { publisher: f.publisher } : {}),
    ...(f.minSkills ? { minSkills: f.minSkills } : {}),
    now: f.now ?? new Date(),
  });
  const signed = signReputation(rep, store.key);
  if (f.out) await writeFile(resolve(f.out), JSON.stringify(signed, null, 2) + '\n');
  if (f.json) out(JSON.stringify(signed, null, 2));
  else if (!rep.publishers.length)
    out('no ClawHub attestations retained yet; run ironheights attest owner/slug@version first');
  else
    for (const p of rep.publishers)
      out(
        `${p.publisher.padEnd(20)} ${p.tier.padEnd(17)} ${p.verified}/${p.skills} verified, ${p.review} review, ${p.blocked} block, ${p.incomplete} incomplete (${p.attestations} attestation(s), last ${p.lastAttestedAt})`,
      );
  return 0;
}

/* ---------------- alerts ---------------- */

export async function runAlerts(f: {
  action: string;
  body?: string;
  signature?: string;
  publicKey?: string;
  env?: NodeJS.ProcessEnv;
  fetchImpl?: typeof fetch;
  out_?: Out;
}): Promise<number> {
  const env = f.env ?? process.env;
  const out = f.out_ ?? stdout;
  if (f.action === 'test') {
    const r = await emitAlert(
      'test',
      'ironheights alert test',
      {},
      {
        env,
        ...(f.fetchImpl ? { fetchImpl: f.fetchImpl } : {}),
      },
    );
    if (!r.sent) {
      out(
        'alerts are off: set IRONHEIGHTS_ALERT_WEBHOOK, IRONHEIGHTS_ALERT_COMMAND or IRONHEIGHTS_HOME/alerts.json',
      );
      return 1;
    }
    out(`alert sent: webhook ${r.webhook ?? 'not set'}, command ${r.command ?? 'not set'}`);
    return r.webhook === 'failed' || r.webhook === 'refused' || r.command === 'failed' ? 2 : 0;
  }
  if (f.action === 'verify') {
    if (!f.body || !f.signature)
      throw new UsageError('alerts verify needs --body <file> and --signature <base64>');
    const pem = await readFile(
      resolve(f.publicKey ?? join(ironheightsHome(env), 'watch-key.pub.pem')),
      'utf8',
    );
    const ok = verifyAlert(await readFile(resolve(f.body), 'utf8'), f.signature, pem);
    out(ok ? 'alert signature verified' : 'alert signature FAILED');
    return ok ? 0 : 2;
  }
  throw new UsageError(`alerts: unknown action ${f.action} (test, verify)`);
}

/* ---------------- policy init ---------------- */

export async function runPolicyInit(f: {
  template?: string;
  dir?: string;
  force?: boolean;
  list?: boolean;
  out_?: Out;
}): Promise<number> {
  const out = f.out_ ?? stdout;
  if (f.list || !f.template) {
    for (const t of Object.values(TEMPLATES)) out(`${t.name.padEnd(9)} ${t.description}`);
    return f.list ? 0 : 1;
  }
  const t = TEMPLATES[f.template];
  if (!t)
    throw new UsageError(`unknown template ${f.template} (${Object.keys(TEMPLATES).join(', ')})`);
  ConfigSchema.parse(t.config);
  GuardPolicySchema.parse(t.guard);
  const dir = resolve(f.dir ?? '.');
  const files: Record<string, string> = {
    'ironheights.config.json': JSON.stringify(t.config, null, 2) + '\n',
    [GUARD_POLICY_NAME]: JSON.stringify(t.guard, null, 2) + '\n',
    ...(t.extra ?? {}),
  };
  if (!f.force)
    for (const rel of Object.keys(files))
      if (
        await stat(join(dir, rel)).then(
          () => true,
          () => false,
        )
      )
        throw new UsageError(`${rel} exists; pass --force to overwrite`);
  for (const [rel, text] of Object.entries(files)) {
    await mkdir(dirname(join(dir, rel)), { recursive: true });
    await writeFile(join(dir, rel), text);
    out(`wrote ${rel}`);
  }
  out(`template ${t.name}: ${t.description}`);
  return 0;
}

/* ---------------- fleet inventory ---------------- */

export async function runFleetInventory(f: {
  targets: string[];
  out?: string;
  auditExport?: string;
  json?: boolean;
  trustKey?: string;
  config?: string;
  env?: NodeJS.ProcessEnv;
  now?: Date;
  out_?: Out;
}): Promise<number> {
  const env = f.env ?? process.env;
  const out = f.out_ ?? stdout;
  if (!f.targets.length)
    throw new UsageError('fleet inventory needs bot=dir targets or inventory .json files');
  const trusted = f.trustKey ? await readFile(resolve(f.trustKey), 'utf8') : undefined;
  const bots: FleetBot[] = [];
  for (const t of f.targets) {
    if (t.endsWith('.json')) {
      const s = JSON.parse(await readFile(resolve(t), 'utf8')) as SignedInventory;
      if (s?.inventory?.format !== 'ironheights-fleet/1' || !verifyInventory(s, trusted))
        throw new UsageError(
          `${t}: not a signed Ironheights fleet inventory, or the signature does not verify`,
        );
      bots.push(...s.inventory.bots);
      continue;
    }
    const { bot, dir } = parseTarget(t);
    bots.push(
      await inventoryBot(bot, resolve(dir), async (d) =>
        executeScan({
          paths: [d],
          stdout: () => undefined,
          quiet: true,
          json: false,
          allowSkipped: false,
          noColor: true,
          env,
          ...(f.config ? { config: f.config } : {}),
        }),
      ),
    );
  }
  const store = await RetentionStore.open(env, f.now ? () => f.now as Date : undefined);
  const now = f.now ?? new Date();
  const signed = signInventory(buildInventory(bots, now), store.key);
  if (f.out) await writeFile(resolve(f.out), JSON.stringify(signed, null, 2) + '\n');
  if (f.auditExport) {
    const audit = signInventory(buildInventory(bots, now, await store.exportBundle()), store.key);
    await writeFile(resolve(f.auditExport), JSON.stringify(audit, null, 2) + '\n');
  }
  const s = signed.inventory.summary;
  if (f.json) out(JSON.stringify(signed, null, 2));
  else {
    out(`fleet: ${s.bots} bot(s) on ${s.hosts} host(s), ${s.skills} skill(s)`);
    out(
      `verdicts: ${
        Object.entries(s.verdicts)
          .map(([k, v]) => `${k} ${v}`)
          .join(', ') || 'none'
      }`,
    );
    for (const b of s.blocked) out(`BLOCK ${b.bot}: ${b.skill}`);
    for (const d of s.divergent)
      out(`DIVERGENT ${d.name}: ${d.digests.length} versions across ${d.bots.join(', ')}`);
    if (f.out) out(`inventory ${f.out}`);
    if (f.auditExport) out(`audit export ${f.auditExport}`);
  }
  return s.blocked.length ? 1 : 0;
}
