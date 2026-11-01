import { mkdtemp, mkdir, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { callTool, TOOLS } from '../src/mcp/server.ts';
import {
  checkCoverage,
  checkInvocation,
  expandArg,
  permHash,
  setHash,
} from '../src/mcp/invocation.ts';

type Sc = Record<string, unknown>;
const sc = (r: Record<string, unknown>): Sc => r.structuredContent as Sc;

async function ws() {
  const dir = await mkdtemp(join(tmpdir(), 'ih-0270-'));
  const s = join(dir, 'work', 'demo');
  await mkdir(s, { recursive: true });
  await writeFile(join(s, 'SKILL.md'), '---\nname: demo\ndescription: d\n---\nhi\n');
  return {
    dir,
    work: join(dir, 'work'),
    s,
    env: { ...process.env, IRONHEIGHTS_HOME: join(dir, 'home'), HOME: dir },
  };
}

describe('0.27.0 check_invocation: verdict bound to the exact invocation', () => {
  it('lists the new tools', () => {
    const names = TOOLS.map((t) => t.name);
    for (const n of [
      'check_invocation',
      'skill_copies',
      'load_binding',
      'session_lock',
      'check_coverage',
    ])
      expect(names).toContain(n);
  });

  it('expands ~ and $VAR before judging', () => {
    expect(expandArg('~/x', { HOME: '/h' })).toBe('/h/x');
    expect(expandArg('$A/${B}', { A: '1', B: '2' })).toBe('1/2');
  });

  it('binds a clean invocation and changes the hash when anything changes', async () => {
    const w = await ws();
    const base = {
      argv: ['node', './demo/run.js'],
      cwd: w.work,
      vettedScopes: ['read:workspace'],
      requestedScopes: ['read:workspace'],
      skillPath: 'demo',
      env: w.env,
    };
    const a = await checkInvocation(base);
    expect(a.verdict).toBe('bound');
    const b = await checkInvocation({ ...base, runtime: 'ssh' });
    expect(b.bindingHash).not.toBe(a.bindingHash);
    const c = await checkInvocation({ ...base, argv: ['node', './demo/run.js', '--all'] });
    expect(c.bindingHash).not.toBe(a.bindingHash);
  });

  it('wider scope than vetted is unanswered, not inherited', async () => {
    const w = await ws();
    const r = await checkInvocation({
      argv: ['x'],
      cwd: w.work,
      vettedScopes: ['read:workspace'],
      requestedScopes: ['read:workspace', 'write:$HOME'],
      env: w.env,
    });
    expect(r.verdict).toBe('unanswered');
    expect(r.findings.map((f) => f.code)).toContain('scope-wider-than-vetted');
  });

  it('a flag suggested by an error message cannot widen scope', async () => {
    const w = await ws();
    const r = await checkInvocation({
      argv: ['x', '--allow-all'],
      cwd: w.work,
      vettedScopes: [],
      flags: [{ flag: '--allow-all', source: 'error-output', grants: ['net:*'] }],
      env: w.env,
    });
    expect(r.verdict).toBe('refused');
    expect(r.findings.map((f) => f.code)).toContain('untrusted-widening');
  });

  it('refuses path escape after ~ expansion and symlinked install targets', async () => {
    const w = await ws();
    const esc = await checkInvocation({ argv: ['cat', '~/.ssh/id_rsa'], cwd: w.work, env: w.env });
    expect(esc.findings.map((f) => f.code)).toContain('path-escape');
    await symlink(w.dir, join(w.work, 'link'));
    const ln = await checkInvocation({
      argv: ['i'],
      cwd: w.work,
      target: 'link/skills/demo',
      env: w.env,
    });
    expect(ln.verdict).toBe('refused');
    expect(ln.findings.map((f) => f.code)).toContain('target-symlink');
  });

  it('fails when the fetched set differs from the checked resolved set (transitive deps)', async () => {
    const w = await ws();
    const set = [
      { name: 'demo', sha256: 'a'.repeat(64) },
      { name: 'dep', sha256: 'b'.repeat(64) },
    ];
    const ok = await checkInvocation({
      argv: ['i'],
      cwd: w.work,
      resolvedSet: set,
      fetchedSet: [...set].reverse(),
      env: w.env,
    });
    expect(ok.verdict).toBe('bound');
    const bad = await checkInvocation({
      argv: ['i'],
      cwd: w.work,
      resolvedSet: set,
      fetchedSet: [set[0]!, { name: 'dep', sha256: 'c'.repeat(64) }],
      env: w.env,
    });
    expect(bad.findings.map((f) => f.code)).toContain('fetched-not-checked');
    expect(setHash(set)).toBe(setHash([...set].reverse()));
  });

  it('caller permissions are self-reported unless an independent record agrees', async () => {
    const w = await ws();
    const perms = ['read:workspace'];
    const self = await checkInvocation({
      argv: ['x'],
      cwd: w.work,
      callerPermissions: perms,
      env: w.env,
    });
    expect(self.callerPermissions).toBe('self-reported');
    const rec = join(w.dir, 'perm.json');
    await writeFile(rec, JSON.stringify({ permissionsSha256: permHash(perms) }));
    expect(
      (
        await checkInvocation({
          argv: ['x'],
          cwd: w.work,
          callerPermissions: perms,
          permissionRecord: rec,
          env: w.env,
        })
      ).callerPermissions,
    ).toBe('verified');
    const lie = await checkInvocation({
      argv: ['x'],
      cwd: w.work,
      callerPermissions: ['write:*'],
      permissionRecord: rec,
      env: w.env,
    });
    expect(lie.verdict).toBe('refused');
  });

  it('MCP: logs the call, refuses duplicate copies, double-hashes and locks the session', async () => {
    const w = await ws();
    const r = sc(await callTool('check_invocation', { argv: ['x'], cwd: w.work }, { env: w.env }));
    expect(r.verdict).toBe('bound');
    const other = join(w.dir, 'other');
    await mkdir(join(other, 'demo'), { recursive: true });
    await writeFile(join(other, 'demo', 'SKILL.md'), 'different');
    const copies = sc(
      await callTool('skill_copies', { name: 'demo', roots: [w.work, other] }, { env: w.env }),
    );
    expect(copies.state).toBe('refused');
    expect((copies.copies as unknown[]).length).toBe(2);
    const lock = sc(await callTool('session_lock', { path: w.s }, { env: w.env }));
    const live = sc(
      await callTool(
        'load_binding',
        { checkedPath: w.s, checkedHash: lock.digest, loadedPath: w.s },
        { env: w.env },
      ),
    );
    expect(live.match).toBe(true);
    expect(
      sc(
        await callTool(
          'load_binding',
          { checkedPath: w.s, checkedHash: lock.digest, loadedPath: join(other, 'demo') },
          { env: w.env },
        ),
      ).match,
    ).toBe(false);
    expect(sc(await callTool('session_lock', { lock }, { env: w.env })).state).toBe('locked');
    await writeFile(join(w.s, 'SKILL.md'), 'changed mid-session');
    expect(sc(await callTool('session_lock', { lock }, { env: w.env })).state).toBe('changed');
  });

  it('check coverage keys on exact hash and tells no-check from ran-and-passed', () => {
    const res = checkCoverage(
      [
        { name: 'a', sha256: 'h1', at: '2026-11-01T10:00:00Z', session: 's' },
        { name: 'a', sha256: 'h2', at: '2026-11-01T10:05:00Z', session: 's' },
      ],
      [
        {
          sha256: 'h1',
          at: '2026-11-01T09:59:00Z',
          status: 'passed',
          callerPermissionsSha256: 'p1',
        },
        {
          sha256: 'h1',
          at: '2026-11-01T10:01:00Z',
          status: 'passed',
          cacheHit: true,
          callerPermissionsSha256: 'p2',
        },
      ],
    );
    expect(res.installs.map((i) => i.check)).toEqual(['ran-and-passed', 'no-check-ran']);
    expect(res.skipRate).toBe(0.5);
    expect(res.reachDifferedCacheHits).toBe(1);
    expect(res.ok).toBe(false);
  });
});
