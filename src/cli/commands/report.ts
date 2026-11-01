import { watchSummaryFor } from './runtime.ts';
import { applyCap } from '../../runtime/watcher.ts';
import { readFile, stat, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { contentDigest } from '../../mcp/receipts.ts';
import { readJsonl, type ArtifactRecord, type RefusalEvent } from '../../report/extras.ts';
import { TOOL_VERSION } from '../../version.ts';
import type { PostureReport } from '../../report/posture.ts';
import { loadConfig } from '../../core/config.ts';
import {
  appendHistory,
  buildReport,
  readHistory,
  renderPostureHtml,
} from '../../report/posture.ts';

export interface ReportFlags {
  targets: string[];
  title?: string;
  ledger?: string;
  history?: string;
  html?: string;
  json?: boolean;
  jsonFile?: string;
  failOnBlock?: boolean;
  /** Exit 2 when any loaded skill was not fully inspected (0.23.0). */
  failOnIncomplete?: boolean;
  validDays?: number;
  /** 0.24.0 */
  checkIntervalHours?: number;
  refusals?: string;
  /** 0.25.0: signed activity log from `watch --activity`. */
  fromWatch?: string;
  watchKey?: string;
  artifacts?: string;
  loaded?: string;
  fixes?: string;
  envId?: string;
  imageDigest?: string;
  receipts?: string;
  reversalWindow?: number;
  verifySlaDays?: number;
  /** Re-check a saved JSON report against the files on disk now. */
  verify?: string;
  config?: string;
  env?: NodeJS.ProcessEnv;
  now?: Date;
  out?: (line: string) => void;
  err?: (line: string) => void;
}

export async function runReport(flags: ReportFlags): Promise<number> {
  const out = flags.out ?? ((l: string) => process.stdout.write(l + '\n'));
  const env = flags.env ?? process.env;
  const config = await loadConfig({ ...(flags.config ? { explicitPath: flags.config } : {}), env });
  const err = flags.err ?? ((l: string) => process.stderr.write(l + '\n'));
  for (const t of flags.targets) {
    const ok = await stat(resolve(t)).then(
      (s) => s.isDirectory(),
      () => false,
    );
    if (!ok) {
      err(`ironheights report: target is not a directory: ${t}`);
      return 1;
    }
  }
  if (flags.verify) return verifySaved(resolve(flags.verify), flags, out);
  const readJson = async <T>(p?: string): Promise<T | undefined> => {
    if (!p) return undefined;
    try {
      return JSON.parse(await readFile(resolve(p), 'utf8')) as T;
    } catch {
      err(`ironheights report: cannot read JSON ${p}`);
      return undefined;
    }
  };
  const artifactsRaw = flags.artifacts
    ? flags.artifacts.endsWith('.jsonl')
      ? await readJsonl<ArtifactRecord>(resolve(flags.artifacts))
      : ((await readJson<ArtifactRecord[]>(flags.artifacts)) ?? [])
    : undefined;
  const loaded = await readJson<Record<string, string>>(flags.loaded);
  const fixes = await readJson<Record<string, string>>(flags.fixes);
  const history = flags.history ? await readHistory(resolve(flags.history)) : [];
  const report = await buildReport({
    targets: flags.targets.length ? flags.targets : ['.'],
    config,
    history,
    ...(flags.title ? { title: flags.title } : {}),
    ...(flags.ledger ? { ledger: flags.ledger } : {}),
    ...(flags.now ? { now: flags.now } : {}),
    ...(flags.validDays !== undefined ? { validDays: flags.validDays } : {}),
    ...(flags.checkIntervalHours ? { checkIntervalHours: flags.checkIntervalHours } : {}),
    ...(flags.refusals ? { refusals: await readJsonl<RefusalEvent>(resolve(flags.refusals)) } : {}),
    ...(artifactsRaw ? { artifacts: artifactsRaw } : {}),
    ...(loaded ? { loaded } : {}),
    ...(fixes ? { fixes } : {}),
    ...(flags.envId ? { envId: flags.envId } : {}),
    ...(flags.imageDigest ? { imageDigest: flags.imageDigest } : {}),
    ...(flags.receipts
      ? { receipts: await readJsonl<Record<string, unknown>>(resolve(flags.receipts)) }
      : {}),
    ...(flags.reversalWindow ? { reversalWindow: flags.reversalWindow } : {}),
    ...(flags.verifySlaDays !== undefined ? { verifySlaDays: flags.verifySlaDays } : {}),
    env,
  });
  if (flags.fromWatch) {
    const watch = await watchSummaryFor(flags.fromWatch, flags.watchKey, env);
    (report as typeof report & { watch?: unknown }).watch = watch;
    for (const sk of report.skills) {
      const capped = applyCap(sk.grade, sk.skill, watch);
      if (capped !== sk.grade) {
        (sk as typeof sk & { watchCap?: unknown }).watchCap = {
          from: sk.grade,
          to: capped,
          reasons: [...(watch.caps[sk.skill]?.reasons ?? []), ...(watch.caps['*']?.reasons ?? [])],
        };
        sk.grade = capped;
      }
    }
    if (!flags.json) {
      out(
        watch.verified
          ? `watch: ${watch.records} signed record(s) ${watch.from ?? ''} to ${watch.to ?? ''}`
          : `watch: activity log FAILED verification: ${watch.problem}`,
      );
      for (const h of watch.undeclaredHosts)
        out(`watch: ${h.skill ?? '?'} contacted undeclared ${h.host}`);
      for (const o of watch.staleObservers)
        out(`watch: observer ${o.observer} (${o.skill ?? '?'}) missed its heartbeat`);
      if (watch.stalls.hang || watch.stalls.busyQueue)
        out(`watch: stalls ${watch.stalls.hang} hang, ${watch.stalls.busyQueue} busy queue`);
      const ar = Object.entries(watch.afterRefusal);
      if (ar.length) out(`watch: after refusal ${ar.map(([k, v]) => `${k} ${v}`).join(', ')}`);
    }
    if (!watch.verified) {
      if (flags.json) out(JSON.stringify(report, null, 2));
      return 2;
    }
  }
  if (flags.history) await appendHistory(resolve(flags.history), report);
  if (flags.html) await writeFile(resolve(flags.html), renderPostureHtml(report));
  if (flags.jsonFile)
    await writeFile(resolve(flags.jsonFile), JSON.stringify(report, null, 2) + '\n');
  if (flags.json) out(JSON.stringify(report, null, 2));
  else {
    const t = report.totals;
    out(`${report.title}: ${t.repos} repo(s), ${t.skills} skill(s), ${t.findings} finding(s)`);
    if (report.lead) out(report.lead);
    out(t.result);
    for (const c of report.lanes?.containment ?? [])
      out(`containment: ${c.repo}/${c.skill} ${c.asset} via ${c.precondition}`);
    for (const v of report.lanes?.verification ?? [])
      out(
        `verify: ${v.repo}/${v.skill} ${v.asset}: ${v.checkNeeded}${v.status === 'contained-pending-check' ? ' (SLA lapsed: contain pending check)' : ''}`,
      );
    for (const l of report.leftovers ?? []) if (l.severity !== 'info') out(`leftover: ${l.detail}`);
    if (report.refusals)
      out(
        `refusals: ${report.refusals.denials} denial(s), route-around rate ${report.refusals.routeAroundRate ?? 'n/a'}`,
      );
    if (report.reversal) out(`reversal: ${report.reversal.label}`);
    for (const s of report.skills) {
      const cfg = s.configHash.slice(0, 8);
      out(
        `${s.worstReach.label}  grade ${s.grade} @ cfg ${cfg}  ${s.repo}/${s.skill}${s.worstReach.rule ? `  ${s.worstReach.rule}` : ''}`,
      );
      if (s.regraded) out('config changed since last report; grade recomputed');
      if (!s.coverage.complete) out(`  not fully inspected: ${s.coverage.reasons.join('; ')}`);
    }
    out(
      `verdicts: block ${t.verdicts.block ?? 0}, review ${t.verdicts.review ?? 0}, incomplete ${t.verdicts.incomplete ?? 0}, no findings ${t.verdicts['no-findings'] ?? 0}`,
    );
    out(
      `threat model: ${t.reposWithThreatModel}/${t.repos} repo(s), coverage ${t.threatModelCoverage === null ? 'n/a' : `${t.threatModelCoverage}%`}, ${report.violations.filter((v) => v.severity !== 'info').length} violation(s)`,
    );
    out(`drift: ${t.driftChanged} changed of ${t.driftApproved} approved`);
    const top = report.owaspLlm.filter((o) => o.findings > 0);
    if (top.length)
      out(`OWASP LLM: ${top.map((o) => `${o.id.split(':')[0]} ${o.findings}`).join(', ')}`);
    if (flags.html) out(`HTML report: ${resolve(flags.html)}`);
  }
  if (flags.failOnBlock && (report.totals.verdicts.block ?? 0) > 0) return 2;
  if (flags.failOnIncomplete && !report.totals.coverage.complete) return 2;
  return 0;
}

async function verifySaved(
  file: string,
  flags: ReportFlags,
  out: (l: string) => void,
): Promise<number> {
  let r: PostureReport;
  try {
    r = JSON.parse(await readFile(file, 'utf8')) as PostureReport;
  } catch {
    out(`ironheights report --verify: cannot read ${file}`);
    return 64;
  }
  const now = (flags.now ?? new Date()).getTime();
  const rows: Array<{ skill: string; status: string; reason: string }> = [];
  for (const s of r.skills) {
    const repo = r.repos.find((x) => x.repo === s.repo);
    const root = repo ? resolve(repo.path, s.path) : resolve(s.path);
    const id = `${s.repo}/${s.path}`;
    const d = await contentDigest(root).catch(() => ({ digest: null }));
    let status = 'fresh';
    let reason = `grade ${s.grade} still describes these bytes`;
    if (!d.digest) [status, reason] = ['missing', 'the graded files are gone'];
    else if (s.stamp?.contentHash && d.digest !== s.stamp.contentHash)
      [status, reason] = [
        'changed',
        'files changed since grading: the grade is greyed until re-graded',
      ];
    else if ((s.stamp?.gradedAgainstVersion ?? r.version) !== TOOL_VERSION)
      [status, reason] = [
        'version-mismatch',
        `graded with ${s.stamp?.gradedAgainstVersion ?? r.version}, running ${TOOL_VERSION}`,
      ];
    else if (s.stamp && Date.parse(s.stamp.validUntil) < now)
      [status, reason] = ['expired', `hard cutoff ${s.stamp.validUntil} passed`];
    rows.push({ skill: id, status, reason });
  }
  const stale = rows.filter((x) => x.status !== 'fresh').length;
  if (flags.json)
    out(JSON.stringify({ report: file, fingerprint: r.fingerprint, stale, skills: rows }, null, 2));
  else {
    out(`${file}: ${rows.length - stale} of ${rows.length} grade(s) still fresh`);
    for (const x of rows) out(`${x.status.padEnd(16)} ${x.skill}  ${x.reason}`);
  }
  return stale ? 2 : 0;
}
