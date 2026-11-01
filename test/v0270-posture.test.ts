import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { accessRows, coverageReport, driftState } from '../src/report/coverage.ts';
import {
  approvalCovers,
  diffAuthority,
  removalLeftovers,
  sharedPathReaders,
  unreachedKnobs,
} from '../src/threatmodel/authority.ts';
import { appendRecord, auditRecords, recordDir } from '../src/premium/installrecord.ts';
import { runAuthority, runCoverage, runRecord } from '../src/cli/commands/v027.ts';

const H = 'a'.repeat(64);
const run = (night: string, grades?: Record<string, string>, rulesetHash = 'r1') =>
  grades ? { night, ran: true, grades, rulesetHash } : { night, ran: false };

describe('0.27.0 gap-aware posture report', () => {
  it('coverage first, unknown count in the headline, grade when whole', () => {
    const r = coverageReport({
      runs: [run('2026-10-30', { a: 'A', b: 'B' }), run('2026-10-31', { a: 'A', b: 'A' })],
      inventory: ['a', 'b', 'c'],
    });
    expect(r.headline).toBe('checked 2 of 3, 1 unknown');
    expect(r.graded).toBe(true);
    expect(r.grade).toBe('A');
    expect(r.rulesetHash).toBe('r1');
  });
  it('refuses to grade over more than one empty night or a gap right after an update', () => {
    const many = coverageReport({
      runs: [run('2026-10-28'), run('2026-10-29'), run('2026-10-30', { a: 'A' })],
      inventory: ['a'],
    });
    expect(many.graded).toBe(false);
    expect(many.grade).toBeUndefined();
    const upd = coverageReport({
      runs: [run('2026-10-29', { a: 'A' }), run('2026-10-30'), run('2026-10-31', { a: 'A' })],
      inventory: ['a'],
      skillChanges: ['2026-10-29T22:00:00Z'],
    });
    expect(upd.refusal).toMatch(/update window/);
  });
  it('marks a grade stale when the rule set changed, keeps a fixed cohort and names skills that left scanning', () => {
    const r = coverageReport({
      runs: [run('2026-10-30', { a: 'A', b: 'F' }), run('2026-10-31', { a: 'B' })],
      inventory: ['a', 'b'],
      previousSkills: ['a', 'b'],
      currentRulesetHash: 'r2',
    });
    expect(r.rulesetStale).toBe(true);
    expect(r.cohort).toEqual(['a']);
    expect(r.leftScanning).toEqual(['b']);
    expect(r.cohortTrend.map((t) => t.grade)).toEqual(['A', 'B']);
  });
  it('declared vs granted vs used, ambient access and unmodelled actors', () => {
    const [row] = accessRows([
      {
        skill: 's',
        declared: ['read:docs'],
        granted: ['read:docs', 'env:GH_TOKEN'],
        used: ['read:docs', 'net:x'],
        consumers: ['git-credential-helper'],
        dependencyGraph: ['node'],
      },
    ]);
    expect(row?.ambient).toEqual(['env:GH_TOKEN']);
    expect(row?.usedNotDeclared).toEqual(['net:x']);
    expect(row?.unmodelledActors).toEqual(['git-credential-helper']);
  });
  it('explained is not resolved; self-resolution is rejected', () => {
    const base = {
      id: 'd',
      causedBy: 'agent',
      driftedSha256: H,
      detectedAt: '2026-11-01T10:00:00Z',
    };
    expect(driftState(base)).toBe('open');
    expect(driftState({ ...base, explanation: { by: 'agent' } })).toBe('rejected');
    expect(
      driftState({
        ...base,
        explanation: {
          by: 'agent',
          artifact: { path: 'install.log', sha256: H, writtenAt: '2026-11-01T09:00:00Z' },
        },
      }),
    ).toBe('explained');
    expect(driftState({ ...base, resolution: { by: 'agent' } })).toBe('rejected');
    expect(driftState({ ...base, resolution: { by: 'reviewer' } })).toBe('resolved');
  });
  it('CLI exits 2 when not graded', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-cov-'));
    const f = join(dir, 'in.json');
    await writeFile(
      f,
      JSON.stringify({ runs: [run('2026-10-29'), run('2026-10-30')], inventory: ['a'] }),
    );
    const lines: string[] = [];
    expect(await runCoverage({ input: f, out: (l) => lines.push(l) })).toBe(2);
    expect(lines[1]).toMatch(/not graded/);
  });
});

describe('0.27.0 runner authority and removal leftovers', () => {
  const base = [
    {
      runner: 'gh',
      secrets: ['NPM_TOKEN'],
      tokens: [],
      permissions: ['contents:read'],
      steps: { test: [] },
    },
  ];
  it('fails (not warns) when ambient authority or a step reach grows, and on a new runner', () => {
    const f = diffAuthority(base, [
      {
        runner: 'gh',
        secrets: ['NPM_TOKEN', 'AWS_KEY'],
        tokens: [],
        permissions: ['contents:read'],
        steps: { test: ['NPM_TOKEN'] },
      },
      { runner: 'self-hosted', secrets: [], tokens: [], permissions: [] },
    ]);
    expect(f.map((x) => x.code).sort()).toEqual([
      'ambient-authority-grew',
      'new-runner',
      'step-reach-grew',
    ]);
    expect(f.every((x) => x.severity === 'fail')).toBe(true);
  });
  it('skill+machine approval, knobs without reach lines, DNS leftovers and shared-path readers', () => {
    expect(
      approvalCovers(
        [{ skill: 's', sha256: H, runner: 'gh', authoritySha256: 'x' }],
        's',
        H,
        'other',
        'x',
      ),
    ).toBe(false);
    expect(
      unreachedKnobs(['A'], ['A', '--debug', 'B_URL'], { B_URL: 'net: b.example' }).map(
        (x) => x.message,
      ),
    ).toEqual([expect.stringContaining('--debug')]);
    const left = removalLeftovers(
      [
        { kind: 'dns', id: 'hook.example.com' },
        { kind: 'cron', id: 'nightly' },
      ],
      [{ kind: 'cron', id: 'nightly' }],
    );
    expect(left).toHaveLength(1);
    expect(left[0]?.message).toMatch(/re-registration/);
    const w = [{ skill: 'mail', path: '/cache', private: true }];
    expect(sharedPathReaders(w, [{ skill: 'sum', path: '/cache' }])).toHaveLength(1);
    expect(
      sharedPathReaders(
        w,
        [{ skill: 'sum', path: '/cache' }],
        [{ skill: 'sum', path: '/cache', by: 'kaleb', reason: 'reviewed' }],
      ),
    ).toHaveLength(0);
  });
  it('CLI exits 2 on growth', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-auth-'));
    const f = join(dir, 'a.json');
    await writeFile(
      f,
      JSON.stringify({ baseline: base, current: [{ ...base[0], secrets: ['NPM_TOKEN', 'X'] }] }),
    );
    expect(await runAuthority({ input: f, out: () => undefined })).toBe(2);
  });
});

describe('0.27.0 auditor-accepted install record', () => {
  const rec = {
    skill: 's',
    version: '1.2.0',
    sha256: H,
    approver: 'kaleb',
    approverSawSha256: H,
    scope: { skill: 's', versionRange: '1.2.x', scopeVersion: 1 },
  };
  it('appends signed records, marks inherited and hash-mismatched approvals not accepted', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-rec-'));
    const env = {
      ...process.env,
      IRONHEIGHTS_HOME: join(dir, 'home'),
      IRONHEIGHTS_RECORD_DIR: join(dir, 'worm'),
    };
    expect(recordDir(env)).toBe(join(dir, 'worm'));
    await appendRecord(rec, env);
    await appendRecord(
      { ...rec, version: '1.2.1', inherited: { from: 's@1.2.0', via: 'auto-update' } },
      env,
    );
    await appendRecord({ ...rec, version: '1.2.2', approverSawSha256: 'b'.repeat(64) }, env);
    const a = await auditRecords(env);
    expect(a.chain.ok).toBe(true);
    expect(a.rows.map((r) => r.accepted)).toEqual([true, false, false]);
    expect(await runRecord({ action: 'audit', env, out: () => undefined })).toBe(2);
  });
  it('detects an edited record', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-rec-'));
    const env = {
      ...process.env,
      IRONHEIGHTS_HOME: join(dir, 'home'),
      IRONHEIGHTS_RECORD_DIR: join(dir, 'worm'),
    };
    await appendRecord(rec, env);
    const file = join(dir, 'worm', 'install-records.jsonl');
    await writeFile(file, (await readFile(file, 'utf8')).replace('kaleb', 'mallory'));
    expect((await auditRecords(env)).chain.ok).toBe(false);
  });
  it('refuses a record without an approver or a real hash', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-rec-'));
    const env = { ...process.env, IRONHEIGHTS_HOME: join(dir, 'home') };
    await expect(appendRecord({ ...rec, approver: '' }, env)).rejects.toThrow(/approver/);
    await expect(appendRecord({ ...rec, sha256: 'x' }, env)).rejects.toThrow(/sha256/);
  });
});
