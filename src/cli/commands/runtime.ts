/**
 * 0.25.0 commands that run or watch a skill: `sandbox run`, `watch --activity`, `install`.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import { ironheightsHome } from '../../core/config.ts';
import { UsageError } from '../../core/errors.ts';
import { parseSkillRef } from '../../net/clawhub.ts';
import { locateOpenClaw } from '../../openclaw/locate.ts';
import { loadModel, MODEL_FILE, modelDir } from '../../threatmodel/threatmodel.ts';
import { ActivityLog, loadOrCreateWatchKey, verifyActivityLog } from '../../runtime/activity.ts';
import {
  buildLock,
  checkAgainstLock,
  depsCommands,
  guardedInstall,
  stageLocal,
  type DepsExec,
  type SkillLock,
} from '../../runtime/install.ts';
import {
  compareTrace,
  findEntry,
  isDir,
  runInSandbox,
  SandboxUnavailable,
  type ExecImpl,
  type ExternalRecord,
  type SandboxTrace,
} from '../../runtime/sandbox.ts';
import { ActivityWatcher, summarizeWatch } from '../../runtime/watcher.ts';
import { stageSkill } from './fetch.ts';
import { executeScan } from './scan.ts';

type Out = (l: string) => void;
const stdout: Out = (l) => process.stdout.write(l + '\n');
const stderr: Out = (l) => process.stderr.write(l + '\n');

/* ---------------- sandbox run ---------------- */

export interface SandboxFlags {
  skill: string;
  entry: string[];
  model?: string;
  image?: string;
  timeout?: number;
  trace?: string;
  saveTrace?: string;
  external?: string;
  json?: boolean;
  failOnUnused?: boolean;
  env?: NodeJS.ProcessEnv;
  exec?: ExecImpl;
  out?: Out;
  err?: Out;
}

export async function runSandbox(f: SandboxFlags): Promise<number> {
  const out = f.out ?? stdout;
  const err = f.err ?? stderr;
  if (!(await isDir(f.skill))) throw new UsageError(`sandbox run: not a directory: ${f.skill}`);
  let trace: SandboxTrace;
  if (f.trace) trace = JSON.parse(await readFile(resolve(f.trace), 'utf8')) as SandboxTrace;
  else {
    if (!f.entry.length)
      throw new UsageError(
        'sandbox run: pass the command to run after --, for example: ironheights sandbox run ./skill -- node run.js',
      );
    try {
      trace = await runInSandbox({
        skillDir: f.skill,
        entry: f.entry,
        ...(f.image ? { image: f.image } : {}),
        ...(f.timeout ? { timeoutSeconds: f.timeout } : {}),
        ...(f.env ? { env: f.env } : {}),
        ...(f.exec ? { exec: f.exec } : {}),
      });
    } catch (e) {
      if (e instanceof SandboxUnavailable) {
        err(`ironheights sandbox: ${e.message}`);
        return 3;
      }
      throw e;
    }
  }
  if (f.saveTrace) await writeFile(resolve(f.saveTrace), JSON.stringify(trace, null, 2) + '\n');
  const modelPath = resolve(f.model ?? MODEL_FILE);
  let entry;
  let modelFound = false;
  try {
    const model = await loadModel(modelPath);
    modelFound = true;
    entry = findEntry(model, f.skill, modelDir(modelPath));
  } catch {
    /* no model: everything observed is undeclared */
  }
  const external = f.external
    ? (JSON.parse(await readFile(resolve(f.external), 'utf8')) as ExternalRecord[])
    : [];
  const findings = compareTrace(trace, entry, external);
  const failing = findings.filter(
    (x) => x.severity === 'error' || (f.failOnUnused && x.kind === 'sandbox-write-unused'),
  );
  const result = {
    skill: f.skill,
    model: modelFound ? modelPath : null,
    modelEntry: Boolean(entry),
    trace,
    findings,
    result: failing.length ? 'fail' : 'pass',
  };
  if (f.json) out(JSON.stringify(result, null, 2));
  else {
    out(
      `sandbox: ${trace.engine} ${trace.image}, exit ${trace.exitCode ?? '?'}, ${trace.durationMs} ms`,
    );
    out(
      `observed: ${trace.writes.length} write(s), ${trace.hosts.length} host attempt(s), ${trace.children.length} child process(es)`,
    );
    if (!modelFound) out(`no threat model at ${modelPath}: every observed reach is undeclared`);
    else if (!entry) out(`skill not in ${modelPath}: every observed reach is undeclared`);
    for (const x of findings) out(`${x.severity.padEnd(7)} ${x.kind}: ${x.detail}`);
    out(
      result.result === 'pass'
        ? 'sandbox: matches the threat model'
        : `sandbox: ${failing.length} finding(s) fail`,
    );
  }
  return failing.length ? 2 : 0;
}

/* ---------------- watch --activity ---------------- */

export interface ActivityFlags {
  paths: string[];
  log?: string;
  events?: string;
  model?: string;
  interval?: number;
  once?: boolean;
  maxRounds?: number;
  checkBudget?: number;
  env?: NodeJS.ProcessEnv;
  sleep?: (ms: number) => Promise<void>;
  clock?: () => Date;
  out?: Out;
}

export async function runActivityWatch(f: ActivityFlags): Promise<number> {
  const out = f.out ?? stdout;
  const env = f.env ?? process.env;
  const home = ironheightsHome(env);
  if (!f.paths.length) throw new UsageError('watch --activity requires a skills path');
  const key = await loadOrCreateWatchKey(home);
  const file = resolve(f.log ?? join(home, 'activity.jsonl'));
  const log = new ActivityLog(file, key, f.clock);
  await log.open();
  let model;
  if (f.model) model = await loadModel(resolve(f.model));
  const w = new ActivityWatcher({
    paths: f.paths,
    log,
    ...(f.events ? { events: resolve(f.events) } : {}),
    ...(model ? { model } : {}),
    ...(f.checkBudget ? { checkBudgetSeconds: f.checkBudget } : {}),
    ...(f.clock ? { clock: f.clock } : {}),
  });
  const sleep = f.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const rounds = f.once ? 1 : (f.maxRounds ?? Number.POSITIVE_INFINITY);
  const seconds = f.interval ?? 15;
  if (seconds < 1) throw new UsageError('--interval must be 1 second or more');
  out(
    `watch: signing activity to ${file} (key ${key.keyId}, public key ${join(home, 'watch-key.pub.pem')})`,
  );
  for (let i = 0; i < rounds; i += 1) {
    if (i > 0) await sleep(seconds * 1000);
    const recs = await w.round();
    for (const r of recs)
      if (r.kind !== 'heartbeat')
        out(`${r.at} ${r.kind}${r.skill ? ` ${r.skill}` : ''} ${JSON.stringify(r.data)}`);
  }
  return 0;
}

export async function runVerifyActivity(
  file: string,
  pub: string | undefined,
  env: NodeJS.ProcessEnv = process.env,
  out: Out = stdout,
): Promise<number> {
  const pem = await readFile(
    resolve(pub ?? join(ironheightsHome(env), 'watch-key.pub.pem')),
    'utf8',
  );
  const v = await verifyActivityLog(resolve(file), pem);
  out(
    v.ok
      ? `activity log verified: ${v.records.length} record(s)`
      : `activity log FAILED: ${v.problem}`,
  );
  return v.ok ? 0 : 2;
}

/** Used by `report --from-watch`. */
export async function watchSummaryFor(
  file: string,
  pub: string | undefined,
  env: NodeJS.ProcessEnv,
) {
  const pem = await readFile(
    resolve(pub ?? join(ironheightsHome(env), 'watch-key.pub.pem')),
    'utf8',
  );
  const v = await verifyActivityLog(resolve(file), pem);
  return summarizeWatch(v.records, v.ok, v.problem);
}

/* ---------------- install ---------------- */

export interface InstallFlags {
  skill: string;
  dir?: string;
  lock?: string;
  expectDigest?: string;
  writeLock?: string;
  withDeps?: boolean;
  acceptReview?: boolean;
  json?: boolean;
  config?: string;
  env?: NodeJS.ProcessEnv;
  fetchImpl?: typeof fetch;
  depsExec?: DepsExec;
  out?: Out;
  now?: Date;
}

export async function runInstall(f: InstallFlags): Promise<number> {
  const out = f.out ?? stdout;
  const env = f.env ?? process.env;
  const local = await isDir(f.skill);
  const staged = local
    ? await stageLocal(f.skill)
    : (
        await stageSkill({
          skill: f.skill,
          quiet: true,
          env,
          ...(f.fetchImpl ? { fetchImpl: f.fetchImpl } : {}),
        })
      ).dir;
  const slug = local ? basename(resolve(f.skill)).toLowerCase() : parseSkillRef(f.skill).slug;
  if (f.writeLock) {
    const lock = await buildLock(staged, slug, f.now);
    await writeFile(resolve(f.writeLock), JSON.stringify(lock, null, 2) + '\n');
    out(
      `lock written: ${f.writeLock} (${Object.keys(lock.files).length} files, digest ${lock.digest}, ${lock.closure.length} pinned dependencies)`,
    );
    return 0;
  }
  if (!f.lock && !f.expectDigest)
    throw new UsageError(
      'install needs --lock <file> or --expect-digest <sha256> (the contentDigest from check_skill); create a lock with --write-lock',
    );
  const lock = f.lock
    ? (JSON.parse(await readFile(resolve(f.lock), 'utf8')) as SkillLock)
    : undefined;
  const check = await checkAgainstLock(staged, lock, f.expectDigest);
  const scan = await executeScan({
    paths: [staged],
    stdout: () => undefined,
    quiet: true,
    json: false,
    allowSkipped: false,
    noColor: true,
    ...(f.config ? { config: f.config } : {}),
  });
  if (
    scan.verdict === 'block' ||
    scan.verdict === 'incomplete' ||
    (scan.verdict === 'review' && !f.acceptReview)
  )
    check.problems.push(
      `scan verdict ${scan.verdict}${scan.verdict === 'review' ? ' (pass --accept-review to accept)' : ''}`,
    );
  check.ok = check.problems.length === 0;
  const report = (extra: Record<string, unknown>) =>
    f.json &&
    out(
      JSON.stringify(
        {
          skill: f.skill,
          digest: check.digest,
          verdict: scan.verdict,
          problems: check.problems,
          ...extra,
        },
        null,
        2,
      ),
    );
  if (!check.ok) {
    if (!f.json) {
      out(`Refused: ${f.skill} does not match what was checked`);
      for (const p of check.problems) out(`  ${p}`);
    }
    report({ installed: false });
    return 2;
  }
  const parent =
    f.dir ??
    (await locateOpenClaw(env)).skillDirs.find((d) => d.source === 'workspace skills')?.path;
  if (!parent) throw new UsageError('pass --dir <skills-directory>');
  const res = await guardedInstall({
    staged,
    destParent: parent,
    slug,
    check,
    withDeps: Boolean(f.withDeps),
    home: ironheightsHome(env),
    ...(f.depsExec ? { exec: f.depsExec } : {}),
    ...(f.now ? { now: f.now } : {}),
  });
  if (!f.json) {
    out(`Installed ${res.files} verified file(s) to ${res.dest} (digest ${check.digest})`);
    for (const d of res.deps) out(`  deps: ${d}`);
    if (!f.withDeps)
      for (const [c, a] of depsCommands(Object.keys(check.files)))
        out(`  pinned deps not installed; run with --with-deps for: ${c} ${a.join(' ')}`);
  }
  report({ installed: true, dest: res.dest, deps: res.deps });
  return 0;
}
