import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  budgetFindings,
  concurrencyFindings,
  deriveSurfaces,
  reconcileSurfaces,
  surfaceChanges,
} from '../src/threatmodel/surfaces.ts';
import {
  checkSessionBinding,
  gate,
  lookupVerdict,
  sessionDigest,
  typeVerdict,
} from '../src/mcp/verdicts.ts';
import { ignoreDebt, machineRows } from '../src/report/fleetposture.ts';
import { auditRunReceipts, writeRunReceipt } from '../src/premium/runreceipt.ts';
import { runFleetPosture, runRunReceipt, runSurfaces } from '../src/cli/commands/v028.ts';

const H = 'a'.repeat(64);
const H2 = 'b'.repeat(64);

describe('0.28.0 execution surfaces', () => {
  const base = [{ id: 'w', credential: 'TOKEN_A', schedule: '0 2 * * *', location: 'ubuntu' }];
  it('fails when credential, frequency or location changes without a threat-model edit', () => {
    const f = surfaceChanges(
      base,
      [{ id: 'w', credential: 'TOKEN_B', schedule: '*/5 * * * *', location: 'self-hosted' }],
      false,
    );
    expect(f.map((x) => x.code).sort()).toEqual([
      'surface-credential-changed',
      'surface-location-changed',
      'surface-schedule-changed',
    ]);
    expect(f.every((x) => x.severity === 'fail')).toBe(true);
    expect(surfaceChanges(base, [{ ...base[0], id: 'w', credential: 'X' }], true)).toEqual([]);
    expect(surfaceChanges(base, [...base, { id: 'new' }], false)[0]?.code).toBe('surface-added');
  });
  it('derives surfaces from the repo and fails when the model omits one', async () => {
    const d = await mkdtemp(join(tmpdir(), 'ih28-'));
    await mkdir(join(d, '.github', 'workflows'), { recursive: true });
    await writeFile(
      join(d, '.github', 'workflows', 'nightly.yml'),
      "on:\n  schedule:\n    - cron: '0 3 * * *'\njobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n      T: ${{ secrets.SKILL_TOKEN }}\n",
    );
    await writeFile(join(d, 'Dockerfile'), 'FROM node\n');
    await writeFile(join(d, 'jobs.cron'), '*/10 * * * * run-skill\n');
    const s = await deriveSurfaces(d);
    const wf = s.find((x) => x.id === 'workflow:.github/workflows/nightly.yml');
    expect(wf).toMatchObject({
      credential: 'SKILL_TOKEN',
      schedule: '0 3 * * *',
      location: 'ubuntu-latest',
    });
    expect(s.some((x) => x.id === 'container:Dockerfile')).toBe(true);
    expect(s.some((x) => x.id === 'cron:jobs.cron#1')).toBe(true);
    const f = reconcileSurfaces(s, [
      { id: 'container:Dockerfile' },
      { id: 'old' },
      { id: 'external:mac' },
    ]);
    expect(f.filter((x) => x.code === 'surface-missing-from-model')).toHaveLength(2);
    expect(f.filter((x) => x.code === 'surface-stale-in-model')).toHaveLength(1);
  });
  it('declared max concurrency is compared against the scheduler ledger', () => {
    const model = [
      { id: 'a', writes: ['cache/'] },
      { id: 'b', writes: ['cache/'], maxConcurrent: 2 },
      { id: 'c', maxConcurrent: 1 },
    ];
    const f = concurrencyFindings(model, [
      { surface: 'b', maxConcurrentObserved: 3, window: '7d' },
    ]);
    const codes = f.map((x) => x.code);
    expect(codes).toContain('concurrency-undeclared');
    expect(codes).toContain('shared-write-unlocked');
    expect(codes).toContain('concurrency-exceeded');
    expect(f.find((x) => x.code === 'shared-write-unlocked')?.severity).toBe('warn');
    expect(f.find((x) => x.code === 'concurrency-unobserved')?.severity).toBe('warn');
  });
  it('contract budgets fail on measured numbers, guidelines warn, removed caps fail', () => {
    const m = [{ surface: 's', host: 'api', callsPerTask: 40, largestPayloadBytes: 9000 }];
    const c = budgetFindings(
      [{ surface: 's', host: 'api', kind: 'contract', maxCallsPerTask: 10 }],
      m,
    );
    expect(c[0]).toMatchObject({ code: 'budget-calls-exceeded', severity: 'fail' });
    const g = budgetFindings(
      [{ surface: 's', host: 'api', kind: 'guideline', maxPayloadBytes: 100 }],
      m,
    );
    expect(g[0]).toMatchObject({ code: 'budget-payload-exceeded', severity: 'warn' });
    const r = budgetFindings([{ surface: 's', host: 'api', kind: 'guideline' }], m, [
      { surface: 's', host: 'api', kind: 'guideline', retryCap: 3 },
      { surface: 's', host: 'x', kind: 'contract' },
    ]);
    expect(r.map((x) => x.code).sort()).toEqual(['budget-cap-removed', 'budget-contract-removed']);
  });
  it('CLI exits 2 on a failing surface change', async () => {
    const d = await mkdtemp(join(tmpdir(), 'ih28c-'));
    const p = join(d, 'i.json');
    await writeFile(p, JSON.stringify({ base, head: [{ ...base[0], credential: 'Z' }] }));
    const lines: string[] = [];
    expect(await runSurfaces({ input: p, out: (l) => lines.push(l) })).toBe(2);
    expect(lines[0]).toContain('surface-credential-changed');
  });
});

describe('0.28.0 MCP verdict typing', () => {
  it('a check after load never returns allow', () => {
    const v = typeVerdict({
      decision: 'allow',
      checkedAt: '2026-11-02T10:00:00Z',
      loadedAt: '2026-11-02T09:00:00Z',
      checkedSha256: H,
      loadedSha256: H,
    });
    expect(v.verdict).toBe('post-load-unchanged');
    expect(v.loadedAt).toBe('2026-11-02T09:00:00Z');
    expect(
      typeVerdict({
        decision: 'allow',
        checkedAt: '2026-11-02T10:00:00Z',
        loadedAt: '2026-11-02T09:00:00Z',
        checkedSha256: H,
        loadedSha256: H2,
      }).verdict,
    ).toBe('post-load-drifted');
    expect(typeVerdict({ decision: 'allow', checkedAt: '2026-11-02T10:00:00Z' }).verdict).toBe(
      'allow',
    );
    expect(gate(v).proceed).toBe(false);
  });
  it('gate fails closed on unknown, truthy or missing verdicts', () => {
    expect(gate('allow').proceed).toBe(true);
    expect(gate({ verdict: 'allow' }).proceed).toBe(true);
    for (const x of ['pass', true, 1, undefined, null, 'ALLOW', { verdict: 'ok' }, 'block'])
      expect(gate(x).proceed).toBe(false);
  });
  it('lookup refuses bare names and unverified publishers, finds by hash + publisher', () => {
    const store = [
      {
        name: 'foo',
        publisher: 'acme',
        sha256: H,
        verdict: { verdict: 'allow' as const, checkedAt: 'x' },
      },
    ];
    expect(lookupVerdict(store, { name: 'foo' }).status).toBe('refused');
    expect(lookupVerdict(store, { sha256: H, publisher: 'acme' }).status).toBe('refused');
    expect(
      lookupVerdict(store, { sha256: H, publisher: 'acme', publisherVerified: true }).status,
    ).toBe('found');
    expect(
      lookupVerdict(store, { sha256: H, publisher: 'evil', publisherVerified: true }).status,
    ).toBe('no-verdict');
    expect(
      lookupVerdict(store, { name: 'bar', sha256: H, publisher: 'acme', publisherVerified: true })
        .status,
    ).toBe('refused');
  });
  it('session binding expires when env names change, never sees values', () => {
    const d = sessionDigest('s1', ['B', 'A']);
    expect(checkSessionBinding(d, 's1', ['A', 'B']).status).toBe('current');
    expect(checkSessionBinding(d, 's1', ['A', 'B', 'AWS_SECRET']).status).toBe('expired');
    expect(checkSessionBinding(d, 's2', ['A', 'B']).status).toBe('expired');
  });
});

describe('0.28.0 fleet posture', () => {
  const now = new Date('2026-11-02T00:00:00Z');
  const findings = [
    { id: 'f1', sha256: H, severity: 'high' as const },
    { id: 'f2', sha256: H2, severity: 'low' as const },
  ];
  it('ignore debt sits next to the grade; ignores die when the finding changes or expires', () => {
    const r = ignoreDebt(
      findings,
      [
        { findingId: 'f1', findingSha256: H, createdAt: '2026-10-01T00:00:00Z' },
        { findingId: 'f2', findingSha256: 'c'.repeat(64), createdAt: '2026-10-20T00:00:00Z' },
        {
          findingId: 'f3',
          findingSha256: H,
          createdAt: '2026-10-20T00:00:00Z',
          expiresAt: '2026-10-25T00:00:00Z',
        },
      ],
      now,
    );
    expect(r.grade).toBe('B');
    expect(r.gradeWithoutIgnores).toBe('D');
    expect(r.ignoreDebtDays).toBe(32);
    expect(r.notify).toBe(true);
    expect(r.deadIgnores.map((d) => d.reason).sort()).toEqual(['expired', 'finding changed']);
    expect(r.headline).toContain('ignore debt 32d');
  });
  it('fleet is clean only when every running copy was checked on its host with matching hash', () => {
    const ok = machineRows([
      { machine: 'm1', skill: 's', checkedSha256: H, executedSha256: H, checkedOnHost: true },
    ]);
    expect(ok.fleetClean).toBe(true);
    const bad = machineRows(
      [
        { machine: 'm1', skill: 's', checkedSha256: H, executedSha256: H, checkedOnHost: true },
        { machine: 'm2', skill: 's', checkedSha256: H, executedSha256: H2, checkedOnHost: true },
        { machine: 'm3', skill: 's' },
      ],
      ['m4'],
    );
    expect(bad.fleetClean).toBe(false);
    expect(bad.rows.find((r) => r.machine === 'm2')?.hashMismatch).toEqual(['s']);
    expect(bad.rows.find((r) => r.machine === 'm3')?.unchecked).toEqual(['s']);
    expect(bad.unscannedMachines).toEqual(['m4']);
  });
  it('CLI exits 2 when the fleet is not clean', async () => {
    const d = await mkdtemp(join(tmpdir(), 'ih28f-'));
    const p = join(d, 'f.json');
    await writeFile(p, JSON.stringify({ findings: [], copies: [{ machine: 'm', skill: 's' }] }));
    const lines: string[] = [];
    expect(await runFleetPosture({ input: p, now, out: (l) => lines.push(l) })).toBe(2);
    expect(lines.join('\n')).toContain('NOT clean');
  });
});

describe('0.28.0 per-run receipts', () => {
  it('loader writes one signed line per running copy with approver of the exact hash', async () => {
    const home = await mkdtemp(join(tmpdir(), 'ih28r-'));
    const env = { IRONHEIGHTS_HOME: home, IRONHEIGHTS_RECEIPT_DIR: join(home, 'r') };
    const base = {
      runId: 'r1',
      machine: 'm1',
      skill: 's',
      loadedSha256: H,
      writer: 'loader' as const,
      trigger: 'cron',
      loadedAt: 'x',
    };
    await writeRunReceipt({ ...base, copyId: 'c1', approver: 'kaleb', approvedSha256: H }, env);
    await writeRunReceipt({ ...base, copyId: 'c2', approver: 'kaleb', approvedSha256: H2 }, env);
    await expect(
      writeRunReceipt({ ...base, copyId: 'c3', writer: 'job' as never }, env),
    ).rejects.toThrow(/loader/);
    await expect(writeRunReceipt({ ...base, copyId: 'c3', trigger: '' }, env)).rejects.toThrow(
      /trigger/,
    );
    const a = await auditRunReceipts(env);
    expect(a.chain.ok).toBe(true);
    expect(a.copies).toBe(2);
    expect(a.unapproved).toBe(1);
    const lines: string[] = [];
    expect(await runRunReceipt({ action: 'audit', env, out: (l) => lines.push(l) })).toBe(2);
    expect(lines[0]).toContain('2 receipt(s)');
  });
});
