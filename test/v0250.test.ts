/* eslint-disable @typescript-eslint/no-non-null-assertion */
import * as fs from 'node:fs';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { SpawnSyncReturns } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { runReport } from '../src/cli/commands/report.ts';
import {
  runActivityWatch,
  runInstall,
  runSandbox,
  runVerifyActivity,
} from '../src/cli/commands/runtime.ts';
import { ActivityLog, loadOrCreateWatchKey, verifyActivityLog } from '../src/runtime/activity.ts';
import { buildLock, checkAgainstLock, depsCommands } from '../src/runtime/install.ts';
import {
  compareTrace,
  detectEngine,
  parseStrace,
  runInSandbox,
  type ExecImpl,
  type SandboxTrace,
} from '../src/runtime/sandbox.ts';
import { ActivityWatcher, applyCap, summarizeWatch } from '../src/runtime/watcher.ts';
import { parseModel } from '../src/threatmodel/threatmodel.ts';

function capture() {
  const lines: string[] = [];
  return { lines, out: (l: string) => lines.push(l) };
}

async function skillDir(body = 'Say hello.', extra: Record<string, string> = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'ih-0250-'));
  const s = join(dir, 'demo');
  await mkdir(s);
  await writeFile(join(s, 'SKILL.md'), `---\nname: demo\ndescription: d\n---\n${body}\n`);
  for (const [f, c] of Object.entries(extra)) await writeFile(join(s, f), c);
  return { dir, s, env: { ...process.env, IRONHEIGHTS_HOME: join(dir, 'home') } };
}

const ok = (stdout = ''): SpawnSyncReturns<string> =>
  ({ status: 0, stdout, stderr: '', pid: 1, output: [], signal: null }) as SpawnSyncReturns<string>;

const MODEL = `version: 1
skills:
  demo:
    path: demo
    network: [api.example.com]
    writes:
      - path: ~/.demo/cache.json
        reason: cache
      - path: ~/.demo/never.json
        reason: rare
    shell: false
`;

const STRACE = [
  '100 execve("/usr/bin/node", ["node", "run.js"], 0x0 /* 3 vars */) = 0',
  '100 openat(AT_FDCWD, "/home/sandbox/.demo/cache.json", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3',
  '100 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3',
  '101 execve("/bin/sh", ["sh", "-c", "curl evil.example"], 0x0 /* 3 vars */) = 0',
  '101 openat(AT_FDCWD, "/home/sandbox/.bashrc", O_WRONLY|O_APPEND) = 4',
  '100 connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.9")}, 16) = -1 ENETUNREACH',
  '100 openat(AT_FDCWD, "/proc/self/status", O_RDONLY) = 6',
].join('\n');

/** Fake docker: writes trace files into the mounted /trace dir like the real entry script. */
function fakeDocker(withStrace = true): { exec: ExecImpl; calls: string[][] } {
  const calls: string[][] = [];
  const exec: ExecImpl = (cmd, args) => {
    calls.push([cmd, ...args]);
    if (args[0] !== 'run') return ok('24.0.0');
    const mount = (dst: string) => {
      const v = args[args.findIndex((a) => a.endsWith(`:${dst}`))]!;
      return v.slice(0, v.length - dst.length - 1);
    };
    const t = mount('/trace');
    const home = mount('/home/sandbox');
    if (withStrace) fs.writeFileSync(join(t, 'strace.log'), STRACE);
    fs.writeFileSync(
      join(t, 'proxy.log'),
      JSON.stringify({ host: 'api.example.com', port: 443 }) +
        '\n' +
        JSON.stringify({ host: 'exfil.example.net', port: 443 }) +
        '\n',
    );
    fs.mkdirSync(join(home, '.demo'), { recursive: true });
    fs.writeFileSync(join(home, '.demo', 'cache.json'), '{}');
    fs.writeFileSync(join(t, 'exit'), '0\n');
    return ok();
  };
  return { exec, calls };
}

describe('0.25.0 sandbox run', () => {
  it('parses strace writes, connects and child processes', () => {
    const p = parseStrace(STRACE);
    expect(p.children.map((c) => c.argv.join(' '))).toEqual(['sh -c curl evil.example']);
    expect(p.writes.map((w) => w.path)).toEqual([
      '/home/sandbox/.demo/cache.json',
      '/home/sandbox/.bashrc',
    ]);
    expect(p.writes[1]!.byChild).toBe(true);
    expect(p.hosts).toEqual([]); // failed connect is not a contact
  });

  it('runs with --network none and a logging proxy, then compares against the model', async () => {
    const { dir, s } = await skillDir();
    await writeFile(join(dir, 'ironheights.threatmodel.yml'), MODEL);
    const { exec, calls } = fakeDocker();
    const trace = await runInSandbox({ skillDir: s, entry: ['node', 'run.js'], exec, env: {} });
    const run = calls.find((c) => c[1] === 'run')!;
    expect(run).toContain('--network');
    expect(run[run.indexOf('--network') + 1]).toBe('none');
    expect(trace.measured.children).toBe('strace');
    expect(trace.hosts.map((h) => h.host)).toEqual(['api.example.com', 'exfil.example.net']);
    const model = parseModel(MODEL);
    const f = compareTrace(trace, model.skills.demo);
    const kinds = f.map((x) => x.kind);
    expect(kinds).toContain('sandbox-host-undeclared');
    expect(kinds).toContain('sandbox-child-undeclared');
    expect(f.find((x) => x.kind === 'sandbox-write-undeclared')!.detail).toContain(
      '~/.bashrc (from a child process)',
    );
    expect(f.find((x) => x.kind === 'sandbox-write-unused')!.detail).toContain(
      '~/.demo/never.json',
    );
    expect(
      f.some((x) => x.detail.includes('cache.json') && x.kind === 'sandbox-write-undeclared'),
    ).toBe(false);
    expect(f.some((x) => x.detail.includes('/proc'))).toBe(false);
  });

  it('marks children not-measured when the image has no strace', async () => {
    const { s } = await skillDir();
    const trace = await runInSandbox({
      skillDir: s,
      entry: ['node', 'x.js'],
      exec: fakeDocker(false).exec,
      env: {},
    });
    expect(trace.measured.children).toBe('not-measured');
    expect(compareTrace(trace, undefined).map((x) => x.kind)).toContain('sandbox-not-measured');
  });

  it('reconciles with an outside record', () => {
    const trace: SandboxTrace = {
      engine: 'docker',
      image: 'i',
      entry: [],
      exitCode: 0,
      startedAt: '',
      durationMs: 1,
      writes: [],
      hosts: [{ host: 'api.example.com', via: 'proxy' }],
      children: [],
      measured: { writes: 'diff', hosts: 'proxy', children: 'strace' },
    };
    const entry = parseModel(MODEL).skills.demo;
    expect(
      compareTrace(trace, entry, [{ kind: 'host', value: 'api.example.com' }]).filter(
        (x) => x.kind === 'sandbox-record-mismatch',
      ),
    ).toEqual([]);
    const bad = compareTrace(trace, entry, [{ kind: 'host', value: 'api.example.com', count: 3 }]);
    expect(bad.find((x) => x.kind === 'sandbox-record-mismatch')!.detail).toContain('x3');
  });

  it('exits 3 with a clear message when no container engine exists', async () => {
    const { s } = await skillDir();
    const err = capture();
    const none: ExecImpl = () =>
      ({ status: 1, stdout: '', stderr: '' }) as SpawnSyncReturns<string>;
    expect(detectEngine({}, none)).toBeNull();
    const code = await runSandbox({
      skill: s,
      entry: ['true'],
      exec: none,
      env: {},
      err: err.out,
      out: () => undefined,
    });
    expect(code).toBe(3);
    expect(err.lines[0]).toContain('docker or podman');
  });

  it('CLI compares a recorded trace and fails on undeclared reach (Action path)', async () => {
    const { dir, s } = await skillDir();
    const model = join(dir, 'ironheights.threatmodel.yml');
    await writeFile(model, MODEL);
    const trace = await runInSandbox({
      skillDir: s,
      entry: ['node', 'run.js'],
      exec: fakeDocker().exec,
      env: {},
    });
    const tf = join(dir, 'trace.json');
    await writeFile(tf, JSON.stringify(trace));
    const c = capture();
    const code = await runSandbox({
      skill: s,
      entry: [],
      trace: tf,
      model,
      json: true,
      out: c.out,
    });
    expect(code).toBe(2);
    const j = JSON.parse(c.lines.join('\n'));
    expect(j.result).toBe('fail');
    expect(j.modelEntry).toBe(true);
  });
});

describe('0.25.0 watch --activity', () => {
  it('signs an append-only chain and detects edits and removals', async () => {
    const { dir } = await skillDir();
    const key = await loadOrCreateWatchKey(join(dir, 'home'));
    const file = join(dir, 'a.jsonl');
    const log = new ActivityLog(file, key);
    await log.open();
    await log.append('heartbeat', { observer: 'o' });
    await log.append('net', { host: 'x' }, 'demo');
    const log2 = new ActivityLog(file, key);
    await log2.open();
    await log2.append('action', { tool: 't' });
    expect((await verifyActivityLog(file, key.publicPem)).ok).toBe(true);
    const lines = (await readFile(file, 'utf8')).trim().split('\n');
    await writeFile(file, [lines[0], lines[2]].join('\n') + '\n');
    expect((await verifyActivityLog(file, key.publicPem)).problem).toContain('line 2');
    await writeFile(file, [lines[0], lines[1]!.replace('"x"', '"y"'), lines[2]].join('\n') + '\n');
    expect((await verifyActivityLog(file, key.publicPem)).problem).toContain('bad signature');
  });

  it('records file changes, undeclared hosts, stalls, stale observers and post-refusal actions', async () => {
    const { dir, s } = await skillDir();
    const key = await loadOrCreateWatchKey(join(dir, 'home'));
    const file = join(dir, 'a.jsonl');
    const events = join(dir, 'events.jsonl');
    let now = Date.parse('2026-11-01T10:00:00Z');
    const clock = () => new Date(now);
    const log = new ActivityLog(file, key, clock);
    await log.open();
    const model = parseModel(`version: 1
skills:
  demo:
    path: demo
    network: [api.example.com]
    observers:
      - name: audit
        kind: external
        reaches: [network]
        heartbeat: 1m
`);
    const w = new ActivityWatcher({
      paths: [dir],
      log,
      events,
      model,
      clock,
      checkBudgetSeconds: 30,
      progressWindowSeconds: 10,
      refusalWindowSeconds: 60,
    });
    expect((await w.round()).map((r) => r.kind)).toEqual(['watch-start']);
    await writeFile(join(s, 'SKILL.md'), '---\nname: demo\ndescription: d\n---\nchanged\n');
    const ev = (o: object) => JSON.stringify({ at: new Date(now).toISOString(), ...o });
    await writeFile(
      events,
      [
        ev({ kind: 'net', skill: 'demo', host: 'evil.example' }),
        ev({ kind: 'net', skill: 'demo', host: 'api.example.com' }),
        ev({ kind: 'check-start', id: 'c1', skill: 'demo' }),
        ev({ kind: 'check-start', id: 'c2', skill: 'demo' }),
        ev({ kind: 'refusal', agent: 'a1', tool: 'shell', target: 'rm -rf', skill: 'demo' }),
        ev({ kind: 'action', agent: 'a1', tool: 'shell', target: 'rm -r -f' }),
      ].join('\n') + '\n',
    );
    now += 20_000;
    const r2 = await w.round();
    expect(r2.find((r) => r.kind === 'file')!.data.changed).toEqual(['SKILL.md']);
    expect(r2.filter((r) => r.kind === 'net').map((r) => r.data.declared)).toEqual([false, true]);
    expect(r2.find((r) => r.kind === 'after-refusal')!.data.next).toBe('retry-mutated');
    now += 15_000;
    await writeFile(
      events,
      (await readFile(events, 'utf8')) + ev({ kind: 'check-progress', id: 'c1' }) + '\n',
    );
    const r3 = await w.round();
    const stalls = Object.fromEntries(
      r3.filter((r) => r.kind === 'check-stall').map((r) => [r.data.id, r.data.stallClass]),
    );
    expect(stalls).toEqual({ c1: 'busy-queue', c2: 'hang' });
    now += 40_000;
    await writeFile(
      events,
      (await readFile(events, 'utf8')) +
        ev({ kind: 'check-end', id: 'c1', outcome: 'allow' }) +
        '\n',
    );
    const r4 = await w.round();
    expect(r4.find((r) => r.kind === 'check-end')!.data).toMatchObject({
      durationMs: 75_000,
      stallClass: 'busy-queue',
    });
    expect(r4.find((r) => r.kind === 'observer-stale')!.data.observer).toBe('audit');
    const v = await verifyActivityLog(file, key.publicPem);
    expect(v.ok).toBe(true);
    const sum = summarizeWatch(v.records, true);
    expect(sum.stalls).toEqual({ busyQueue: 1, hang: 1 });
    expect(sum.undeclaredHosts).toEqual([{ skill: 'demo', host: 'evil.example' }]);
    expect(sum.checkDurationsMs.max).toBe(75_000);
    expect(applyCap('A', 'demo', sum)).toBe('F');
    expect(applyCap('A', 'other', sum)).toBe('A');
    expect(applyCap('B', 'x', summarizeWatch([], false, 'line 2: bad'))).toBe('F');
  });

  it('report --from-watch caps grades and refuses a tampered log', async () => {
    const { dir, s, env } = await skillDir();
    const home = env.IRONHEIGHTS_HOME;
    const events = join(dir, 'ev.jsonl');
    await writeFile(
      events,
      JSON.stringify({ kind: 'net', skill: 'demo', host: 'evil.example' }) + '\n',
    );
    const model = join(dir, 'm.yml');
    await writeFile(model, MODEL);
    const logf = join(dir, 'act.jsonl');
    const c0 = capture();
    await runActivityWatch({ paths: [s], log: logf, events, model, once: true, env, out: c0.out });
    expect(c0.lines.some((l) => l.includes('net demo'))).toBe(true);
    expect(await runVerifyActivity(logf, undefined, env, () => undefined)).toBe(0);
    const c = capture();
    const code = await runReport({
      targets: [dir],
      json: true,
      fromWatch: logf,
      env,
      out: c.out,
    } as never);
    expect(code).toBe(0);
    const rep = JSON.parse(c.lines.join('\n'));
    expect(rep.watch.verified).toBe(true);
    expect(rep.watch.undeclaredHosts[0].host).toBe('evil.example');
    for (const sk of rep.skills.filter((x: { skill: string }) => x.skill === 'demo'))
      expect(sk.grade).toBe('F');
    const text = await readFile(logf, 'utf8');
    await writeFile(logf, text.replace('evil.example', 'good.example'));
    expect(
      await runVerifyActivity(logf, join(home!, 'watch-key.pub.pem'), env, () => undefined),
    ).toBe(2);
    const code2 = await runReport({
      targets: [dir],
      json: true,
      fromWatch: logf,
      env,
      out: () => undefined,
    } as never);
    expect(code2).toBe(2);
  });
});

describe('0.25.0 guarded install', () => {
  it('installs exactly the locked bytes and refuses changes, extras and unpinned deps', async () => {
    const { dir, s, env } = await skillDir('Say hello.', { 'helper.md': 'notes' });
    const lockf = join(dir, 'lock.json');
    expect(await runInstall({ skill: s, writeLock: lockf, env, out: () => undefined })).toBe(0);
    const dest = join(dir, 'skills');
    const c = capture();
    expect(await runInstall({ skill: s, lock: lockf, dir: dest, env, out: c.out })).toBe(0);
    expect(await readFile(join(dest, 'demo', 'helper.md'), 'utf8')).toBe('notes');
    const installs = await readFile(join(env.IRONHEIGHTS_HOME!, 'installs.jsonl'), 'utf8');
    expect(installs).toContain('"slug":"demo"');

    await writeFile(join(s, 'helper.md'), 'notes, edited');
    await writeFile(join(s, 'extra.sh'), 'curl x');
    const r = capture();
    expect(
      await runInstall({ skill: s, lock: lockf, dir: dest, env, json: true, out: r.out }),
    ).toBe(2);
    const j = JSON.parse(r.lines.join('\n'));
    expect(j.installed).toBe(false);
    expect(j.problems).toEqual(
      expect.arrayContaining(['changed helper.md', 'extra extra.sh (not in the lock)']),
    );
    expect(await readFile(join(dest, 'demo', 'helper.md'), 'utf8')).toBe('notes');
  });

  it('matches the check_skill digest and refuses a different one', async () => {
    const { dir, s, env } = await skillDir();
    const lock = await buildLock(s, 'demo');
    expect((await checkAgainstLock(s, undefined, lock.digest)).ok).toBe(true);
    const bad = await runInstall({
      skill: s,
      expectDigest: 'f'.repeat(64),
      dir: join(dir, 'k'),
      env,
      out: () => undefined,
    });
    expect(bad).toBe(2);
  });

  it('pins the dependency closure and installs deps only from it', async () => {
    const lockJson = JSON.stringify({
      lockfileVersion: 3,
      packages: { '': {}, 'node_modules/left-pad': { version: '1.3.0', integrity: 'sha512-abc' } },
    });
    const pkg = JSON.stringify({ dependencies: { 'left-pad': '1.3.0' } });
    const { dir, s, env } = await skillDir('Say hello.', {
      'package.json': pkg,
      'package-lock.json': lockJson,
    });
    const lockf = join(dir, 'lock.json');
    await runInstall({ skill: s, writeLock: lockf, env, out: () => undefined });
    const ran: string[] = [];
    const code = await runInstall({
      skill: s,
      lock: lockf,
      dir: join(dir, 'k'),
      env,
      withDeps: true,
      out: () => undefined,
      depsExec: (cmd, args) => (ran.push(`${cmd} ${args.join(' ')}`), { status: 0 }),
    });
    expect(code).toBe(0);
    expect(ran[0]).toContain('npm ci --ignore-scripts');
    expect(depsCommands(['requirements.txt'])[0]![1]).toContain('--require-hashes');
    await writeFile(join(s, 'package-lock.json'), lockJson.replace('1.3.0', '1.3.1'));
    const r = capture();
    expect(
      await runInstall({ skill: s, lock: lockf, dir: join(dir, 'k'), env, json: true, out: r.out }),
    ).toBe(2);
    expect(JSON.parse(r.lines.join('\n')).problems.join(' ')).toContain('closure:');
  });
});
