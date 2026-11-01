/**
 * `ironheights sandbox run` (0.25.0): run a skill once in a throwaway container with no network
 * except a logging proxy, record what it wrote, which hosts it tried and which child processes
 * it started, then compare that trace against the threat model.
 *
 * The container is started with `--network none`; HTTP(S)_PROXY points at a proxy inside the
 * container that logs every request and refuses to forward it, so a host attempt is recorded
 * without any byte leaving the machine. File writes come from strace when the image has it and
 * from a before/after diff of the writable mounts always. Nothing is fetched or installed.
 */
import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import {
  hostAllowed,
  pathAllowed,
  type SkillEntryT,
  type ThreatModel,
} from '../threatmodel/threatmodel.ts';

export interface TraceWrite {
  path: string;
  /** pid that wrote it, when strace saw it. */
  pid?: number;
  /** true when a child process (not the entry process) wrote it. */
  byChild?: boolean;
}
export interface TraceHost {
  host: string;
  port?: number;
  via: 'proxy' | 'connect' | 'dns';
}
export interface TraceChild {
  pid: number;
  ppid?: number;
  argv: string[];
}
export interface SandboxTrace {
  engine: string;
  image: string;
  entry: string[];
  exitCode: number | null;
  startedAt: string;
  durationMs: number;
  writes: TraceWrite[];
  hosts: TraceHost[];
  children: TraceChild[];
  /** Which sources were measured. A missing strace leaves children `not-measured`. */
  measured: {
    writes: 'strace+diff' | 'diff';
    hosts: 'proxy' | 'proxy+strace';
    children: 'strace' | 'not-measured';
  };
}

export type SandboxFindingKind =
  | 'sandbox-write-undeclared'
  | 'sandbox-host-undeclared'
  | 'sandbox-child-undeclared'
  | 'sandbox-child-write'
  | 'sandbox-write-unused'
  | 'sandbox-record-mismatch'
  | 'sandbox-not-measured';

export interface SandboxFinding {
  kind: SandboxFindingKind;
  severity: 'error' | 'warning' | 'info';
  detail: string;
}

export interface ExternalRecord {
  kind: 'host' | 'write' | 'child';
  value: string;
  /** How many times the outside record saw it. Default 1. */
  count?: number;
}

/** Paths every process touches inside the container; never findings. */
const NOISE = [/^\/proc\//, /^\/dev\//, /^\/sys\//, /^\/tmp\//, /^\/trace\//, /^\/run\//];

export type ExecImpl = (
  cmd: string,
  args: string[],
  opts?: { timeoutMs?: number },
) => SpawnSyncReturns<string>;

const defaultExec: ExecImpl = (cmd, args, opts) =>
  spawnSync(cmd, args, { encoding: 'utf8', timeout: opts?.timeoutMs ?? 10_000 });

/** docker or podman, or null. `IRONHEIGHTS_CONTAINER` picks one explicitly. */
export function detectEngine(
  env: NodeJS.ProcessEnv = process.env,
  exec: ExecImpl = defaultExec,
): string | null {
  const wanted = env.IRONHEIGHTS_CONTAINER ? [env.IRONHEIGHTS_CONTAINER] : ['docker', 'podman'];
  for (const e of wanted) {
    try {
      const r = exec(e, ['version', '--format', '{{.Server.Version}}'], { timeoutMs: 8000 });
      if (r.status === 0) return e;
      const r2 = exec(e, ['--version'], { timeoutMs: 8000 });
      if (r2.status === 0 && e === 'podman') return e;
    } catch {
      /* not installed */
    }
  }
  return null;
}

/** Tiny logging proxy run inside the container. It records the target and refuses. */
export const PROXY_JS = `const http=require('http'),fs=require('fs');
const log=(h,p)=>fs.appendFileSync('/trace/proxy.log',JSON.stringify({host:h,port:p,at:new Date().toISOString()})+'\\n');
const s=http.createServer((q,r)=>{try{const u=new URL(q.url);log(u.hostname,Number(u.port)||80)}catch{log(String(q.headers.host||'').split(':')[0],80)}r.writeHead(403);r.end('ironheights sandbox: egress refused\\n')});
s.on('connect',(q,c)=>{const [h,p]=String(q.url).split(':');log(h,Number(p)||443);c.end('HTTP/1.1 403 Forbidden\\r\\n\\r\\n')});
s.listen(8899,'127.0.0.1');`;

export const ENTRY_SH = `set -u
node /trace/proxy.js & sleep 0.3
export HTTP_PROXY=http://127.0.0.1:8899 HTTPS_PROXY=http://127.0.0.1:8899 http_proxy=http://127.0.0.1:8899 https_proxy=http://127.0.0.1:8899
if command -v strace >/dev/null 2>&1; then
  strace -f -qq -s 256 -e trace=execve,openat,open,creat,rename,renameat,renameat2,unlink,unlinkat,mkdir,mkdirat,connect -o /trace/strace.log "$@"
else
  "$@"
fi
echo $? > /trace/exit`;

async function walk(root: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  const go = async (d: string): Promise<void> => {
    let ents;
    try {
      ents = await readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of ents) {
      const p = join(d, e.name);
      if (e.isDirectory()) await go(p);
      else if (e.isFile())
        out[relative(root, p)] = createHash('sha256')
          .update(await readFile(p))
          .digest('hex');
    }
  };
  await go(root);
  return out;
}

const WRITE_FLAGS = /O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND/;

/** Parse `strace -f` output into writes, connects and child processes. */
export function parseStrace(text: string): {
  writes: TraceWrite[];
  hosts: TraceHost[];
  children: TraceChild[];
} {
  const writes: TraceWrite[] = [];
  const hosts: TraceHost[] = [];
  const children: TraceChild[] = [];
  let rootPid: number | null = null;
  for (const line of text.split('\n')) {
    const m = /^(\d+)\s+(\w+)\((.*)\)\s+=\s+(-?\d+)/.exec(line.trim());
    if (!m) continue;
    const pid = Number(m[1]);
    const call = m[2] as string;
    const args = m[3] as string;
    const ok = Number(m[4]) >= 0;
    if (rootPid === null) rootPid = pid;
    if (!ok) continue;
    const strs = [...args.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((x) => x[1] as string);
    if (call === 'execve') {
      const argv =
        /\[(.*?)\]/
          .exec(args)?.[1]
          ?.match(/"((?:[^"\\]|\\.)*)"/g)
          ?.map((s) => s.slice(1, -1)) ?? [];
      if (pid !== rootPid) children.push({ pid, argv: argv.length ? argv : strs.slice(0, 1) });
    } else if (call === 'openat' || call === 'open' || call === 'creat') {
      if (call === 'creat' || WRITE_FLAGS.test(args)) {
        const p = strs[0];
        if (p) writes.push({ path: p, pid, byChild: pid !== rootPid });
      }
    } else if (/^(rename|renameat2?|mkdir|mkdirat|unlink|unlinkat)$/.test(call)) {
      const p = strs[strs.length - 1];
      if (p) writes.push({ path: p, pid, byChild: pid !== rootPid });
    } else if (call === 'connect') {
      const ip =
        /inet_addr\("([^"]+)"\)/.exec(args)?.[1] ??
        /inet_pton\(AF_INET6, "([^"]+)"/.exec(args)?.[1];
      const port = Number(/htons\((\d+)\)/.exec(args)?.[1] ?? 0);
      if (ip && ip !== '127.0.0.1' && ip !== '::1') hosts.push({ host: ip, port, via: 'connect' });
    }
  }
  return { writes, hosts, children };
}

export interface RunOptions {
  skillDir: string;
  entry: string[];
  image?: string;
  timeoutSeconds?: number;
  env?: NodeJS.ProcessEnv;
  exec?: ExecImpl;
  now?: () => number;
}

/** Run once in a container. Throws `SandboxUnavailable` when there is no docker or podman. */
export class SandboxUnavailable extends Error {}

export async function runInSandbox(opts: RunOptions): Promise<SandboxTrace> {
  const exec = opts.exec ?? defaultExec;
  const env = opts.env ?? process.env;
  const engine = detectEngine(env, exec);
  if (!engine)
    throw new SandboxUnavailable(
      'no container engine found: install docker or podman (or set IRONHEIGHTS_CONTAINER), or pass --trace <file> with a recorded trace',
    );
  const image = opts.image ?? env.IRONHEIGHTS_SANDBOX_IMAGE ?? 'node:20-bookworm-slim';
  const work = await mkdtemp(join(tmpdir(), 'ih-sandbox-'));
  const skill = join(work, 'skill');
  const home = join(work, 'home');
  const trace = join(work, 'trace');
  await mkdir(home, { recursive: true });
  await mkdir(trace, { recursive: true });
  await cp(resolve(opts.skillDir), skill, { recursive: true });
  await writeFile(join(trace, 'proxy.js'), PROXY_JS);
  await writeFile(join(trace, 'entry.sh'), ENTRY_SH);
  const before = { skill: await walk(skill), home: await walk(home) };
  const now = opts.now ?? Date.now;
  const started = now();
  const name = `ironheights-sandbox-${createHash('sha256').update(work).digest('hex').slice(0, 12)}`;
  const args = [
    'run',
    '--rm',
    '--name',
    name,
    '--network',
    'none',
    '--cap-drop',
    'ALL',
    '--cap-add',
    'SYS_PTRACE',
    '--security-opt',
    'no-new-privileges',
    '--pids-limit',
    '256',
    '--memory',
    '512m',
    '-e',
    'HOME=/home/sandbox',
    '-v',
    `${skill}:/skill`,
    '-v',
    `${home}:/home/sandbox`,
    '-v',
    `${trace}:/trace`,
    '-w',
    '/skill',
    image,
    'sh',
    '/trace/entry.sh',
    ...opts.entry,
  ];
  const r = exec(engine, args, { timeoutMs: (opts.timeoutSeconds ?? 120) * 1000 });
  if (r.error && (r.error as NodeJS.ErrnoException).code === 'ETIMEDOUT')
    exec(engine, ['rm', '-f', name]);
  const durationMs = now() - started;
  const read = (f: string) => readFile(join(trace, f), 'utf8').catch(() => '');
  const straceText = await read('strace.log');
  const proxyText = await read('proxy.log');
  const exitText = (await read('exit')).trim();
  const st = parseStrace(straceText);
  const after = { skill: await walk(skill), home: await walk(home) };
  const diffWrites: TraceWrite[] = [];
  for (const [area, mount] of [
    ['skill', '/skill'],
    ['home', '/home/sandbox'],
  ] as const) {
    for (const [p, h] of Object.entries(after[area]))
      if (before[area][p] !== h) diffWrites.push({ path: `${mount}/${p}` });
  }
  const proxyHosts: TraceHost[] = proxyText
    .split('\n')
    .filter(Boolean)
    .flatMap((l) => {
      try {
        const j = JSON.parse(l) as { host: string; port?: number };
        return [{ host: j.host, ...(j.port ? { port: j.port } : {}), via: 'proxy' as const }];
      } catch {
        return [];
      }
    });
  await rm(work, { recursive: true, force: true });
  return {
    engine,
    image,
    entry: opts.entry,
    exitCode: exitText ? Number(exitText) : (r.status ?? null),
    startedAt: new Date(started).toISOString(),
    durationMs,
    writes: dedupeWrites([...st.writes, ...diffWrites]),
    hosts: [...proxyHosts, ...st.hosts],
    children: st.children,
    measured: {
      writes: straceText ? 'strace+diff' : 'diff',
      hosts: straceText ? 'proxy+strace' : 'proxy',
      children: straceText ? 'strace' : 'not-measured',
    },
  };
}

function dedupeWrites(ws: TraceWrite[]): TraceWrite[] {
  const m = new Map<string, TraceWrite>();
  for (const w of ws) {
    const prev = m.get(w.path);
    if (!prev || (w.byChild && !prev.byChild)) m.set(w.path, { ...prev, ...w });
  }
  return [...m.values()];
}

/** Map a container path to the way threat models write paths (`~/...` or skill-relative). */
export function modelPath(p: string): string {
  if (p.startsWith('/home/sandbox/')) return '~/' + p.slice('/home/sandbox/'.length);
  if (p === '/home/sandbox') return '~';
  if (p.startsWith('/skill/')) return p.slice('/skill/'.length);
  return p;
}

function declaredWrites(e: SkillEntryT): string[] {
  if (e.writes === 'none' || !e.writes) return [];
  return e.writes.map((w) => (typeof w === 'string' ? w : (w as { path: string }).path));
}

/**
 * Compare a trace against one skill's model entry. Undeclared writes, hosts and children fail;
 * declared writes that never happened are reported as unused; outside records that disagree
 * with the trace are reported as mismatches.
 */
export function compareTrace(
  trace: SandboxTrace,
  entry: SkillEntryT | undefined,
  external: ExternalRecord[] = [],
): SandboxFinding[] {
  const f: SandboxFinding[] = [];
  const allowedWrites = entry ? [...declaredWrites(entry), ...entry.filesystem] : [];
  const allowedHosts = entry ? [...entry.network, ...(entry.egress ?? []).map((x) => x.host)] : [];
  const writes = trace.writes.filter((w) => !NOISE.some((n) => n.test(w.path)));
  const seen = new Set<string>();
  for (const w of writes) {
    const mp = modelPath(w.path);
    seen.add(mp);
    if (!pathAllowed(mp, allowedWrites))
      f.push({
        kind: 'sandbox-write-undeclared',
        severity: 'error',
        detail: `wrote ${mp}${w.byChild ? ' (from a child process)' : ''}, not in writes or filesystem`,
      });
    else if (w.byChild && entry && !entry.shell)
      f.push({
        kind: 'sandbox-child-write',
        severity: 'warning',
        detail: `child process wrote ${mp}; the model does not allow shell`,
      });
  }
  for (const h of trace.hosts) {
    if (!hostAllowed(h.host, allowedHosts))
      f.push({
        kind: 'sandbox-host-undeclared',
        severity: 'error',
        detail: `tried ${h.host}${h.port ? `:${h.port}` : ''} (${h.via}), not in network or egress`,
      });
  }
  if (trace.children.length && !(entry?.shell ?? false))
    for (const c of trace.children)
      f.push({
        kind: 'sandbox-child-undeclared',
        severity: 'error',
        detail: `started ${c.argv.join(' ') || `pid ${c.pid}`}; the model does not allow shell`,
      });
  for (const d of entry ? declaredWrites(entry) : [])
    if (![...seen].some((s) => pathAllowed(s, [d])))
      f.push({
        kind: 'sandbox-write-unused',
        severity: 'info',
        detail: `declared write ${d} never happened in this run`,
      });
  if (trace.measured.children === 'not-measured')
    f.push({
      kind: 'sandbox-not-measured',
      severity: 'warning',
      detail: 'image has no strace: child processes and per-process writes were not measured',
    });
  // Reconcile with an outside record (egress firewall, audit log, the skill's own log).
  const count = (kind: ExternalRecord['kind'], v: string): number =>
    kind === 'host'
      ? trace.hosts.filter((h) => h.host === v).length
      : kind === 'write'
        ? writes.filter((w) => modelPath(w.path) === v).length
        : trace.children.filter((c) => c.argv[0] === v || c.argv.join(' ') === v).length;
  for (const r of external) {
    const want = r.count ?? 1;
    const got = count(r.kind, r.value);
    if (got !== want)
      f.push({
        kind: 'sandbox-record-mismatch',
        severity: 'error',
        detail: `outside record has ${r.kind} ${r.value} x${want}; the sandbox saw x${got}`,
      });
  }
  const extHosts = new Set(external.filter((r) => r.kind === 'host').map((r) => r.value));
  if (external.length && extHosts.size)
    for (const h of new Set(trace.hosts.map((x) => x.host)))
      if (!extHosts.has(h))
        f.push({
          kind: 'sandbox-record-mismatch',
          severity: 'error',
          detail: `sandbox saw ${h}; the outside record does not`,
        });
  return f;
}

export function findEntry(
  model: ThreatModel,
  skillPath: string,
  modelDir: string,
): SkillEntryT | undefined {
  const abs = resolve(skillPath);
  return Object.values(model.skills).find((s) => resolve(modelDir, s.path) === abs);
}

export async function isDir(p: string): Promise<boolean> {
  return stat(p).then(
    (s) => s.isDirectory(),
    () => false,
  );
}
