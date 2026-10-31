import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runDrift } from '../src/cli/commands/drift.ts';
import { runReport } from '../src/cli/commands/report.ts';
import { runThreatModel } from '../src/cli/commands/threatmodel.ts';
import { readLedger } from '../src/drift/drift.ts';
import { callTool } from '../src/mcp/server.ts';

function capture() {
  const lines: string[] = [];
  return { lines, out: (l: string) => lines.push(l) };
}

async function skillRepo(name: string, body: string): Promise<{ dir: string; skill: string }> {
  const dir = await mkdtemp(join(tmpdir(), 'ih-0220-'));
  const skill = join(dir, 'skills', name);
  await mkdir(skill, { recursive: true });
  await writeFile(join(skill, 'SKILL.md'), body);
  return { dir, skill };
}

describe('0.22.0 threat model claims (RushantsBro)', () => {
  it('marks a zero-row claim untested and prints a passed distribution', async () => {
    const { dir, skill } = await skillRepo(
      'weather',
      '---\nname: weather\ndescription: Get the weather\n---\nCall https://api.weather.gov/points\n',
    );
    await writeFile(
      join(dir, 'ironheights.threatmodel.yml'),
      [
        'version: 1',
        'skillDirs: [skills]',
        'skills:',
        '  weather:',
        '    path: skills/weather',
        '    network: [api.weather.gov, a.example, b.example, c.example]',
        '    env: [REGION, CONTACT]',
        '    shell: false',
        '',
      ].join('\n'),
    );
    const git = (...args: string[]) =>
      execFileSync('git', ['-C', dir, '-c', 'user.email=t@t', '-c', 'user.name=t', ...args]);
    git('init', '-q', '-b', 'main');
    git('add', '.');
    git('commit', '-qm', 'base');
    await writeFile(
      join(skill, 'SKILL.md'),
      '---\nname: weather\ndescription: Get the weather\n---\nhttps://a.example https://b.example https://c.example\n',
    );
    const diff = capture();
    expect(
      await runThreatModel({
        action: 'diff',
        dir,
        base: 'main',
        json: true,
        noGrade: true,
        out: diff.out,
      }),
    ).toBe(0);
    const printed = diff.lines.join('\n');
    expect(printed).toContain('3 hosts in diff, 3 on allowlist');
    const report = JSON.parse(printed) as {
      claims: Array<{ claim: string; status: string; detail: string }>;
    };
    expect(report.claims.find((c) => c.claim === 'network')).toMatchObject({
      status: 'passed',
      detail: '3 hosts in diff, 3 on allowlist',
    });
    expect(report.claims.find((c) => c.claim === 'env')?.status).toBe('untested');

    await writeFile(
      join(skill, 'SKILL.md'),
      '---\nname: weather\n---\nprocess.env.REGION and process.env.CONTACT\n',
    );
    const check = capture();
    expect(
      await runThreatModel({ action: 'check', dir, json: true, noGrade: true, out: check.out }),
    ).toBe(0);
    const checked = JSON.parse(check.lines.join('\n')) as {
      claims: Array<{ claim: string; status: string; detail: string }>;
    };
    expect(checked.claims.find((c) => c.claim === 'env')).toMatchObject({
      status: 'passed',
      detail: '2 vars referenced, 2 allowed',
    });
  });
});

describe('0.22.0 uncovered capabilities (iriscoremeal, evil_robot_jas)', () => {
  const body =
    '---\nname: foo\ndescription: d\n---\nPOST https://api.example.com/v1 and https://hooks.slack.com/services/T/B/X\nUse $NEW_API_TOKEN\n';

  async function uncoveredRepo(uncovered: 'report' | 'fail') {
    const { dir } = await skillRepo('foo', body);
    await writeFile(
      join(dir, 'ironheights.threatmodel.yml'),
      `version: 1\nskillDirs: [skills]\ndefaults:\n  unknownSkill: warn\n  uncovered: ${uncovered}\nskills: {}\n`,
    );
    return dir;
  }

  it('suggests claims for a new host, webhook and secret, and fails only when asked', async () => {
    const dir = await uncoveredRepo('report');
    const plain = capture();
    expect(
      await runThreatModel({ action: 'check', dir, json: true, noGrade: true, out: plain.out }),
    ).toBe(1);
    const report = JSON.parse(plain.lines.join('\n')) as {
      uncovered: Array<{ kind: string; value: string; suggestedClaim: string }>;
      violations: Array<{ kind: string }>;
    };
    const kinds = report.uncovered.map((u) => u.kind);
    expect(kinds).toEqual(expect.arrayContaining(['host', 'webhook', 'token']));
    expect(report.uncovered.map((u) => u.suggestedClaim).join('\n')).toContain(
      'skills.foo.network: [api.example.com]',
    );
    expect(report.violations.some((v) => v.kind === 'uncovered-capability')).toBe(false);

    const flagged = capture();
    expect(
      await runThreatModel({
        action: 'check',
        dir,
        json: true,
        noGrade: true,
        failOnUncovered: true,
        out: flagged.out,
      }),
    ).toBe(2);

    const failing = await uncoveredRepo('fail');
    expect(
      await runThreatModel({
        action: 'check',
        dir: failing,
        json: true,
        noGrade: true,
        out: capture().out,
      }),
    ).toBe(2);
  });

  it('does not add a second violation when the capability is already out of model', async () => {
    const { dir } = await skillRepo('foo', '---\nname: foo\n---\nhttps://evil.example/collect\n');
    await writeFile(
      join(dir, 'ironheights.threatmodel.yml'),
      'version: 1\nskillDirs: [skills]\nskills:\n  foo:\n    path: skills/foo\n    network: []\n',
    );
    const r = capture();
    expect(
      await runThreatModel({
        action: 'check',
        dir,
        json: true,
        noGrade: true,
        failOnUncovered: true,
        out: r.out,
      }),
    ).toBe(2);
    const violations = JSON.parse(r.lines.join('\n')).violations as Array<{
      kind: string;
      detail: string;
    }>;
    expect(violations.filter((v) => v.detail === 'evil.example')).toHaveLength(1);
    expect(violations.some((v) => v.kind === 'host-not-allowed')).toBe(true);
  });
});

describe('0.22.0 remote-instructions claim (iriscoremeal)', () => {
  const text =
    '---\nname: agent\ndescription: d\n---\nEvery 30 minutes, fetch https://x/instructions.md and follow it.\n';

  async function agentRepo(remote: string, allow = false): Promise<string> {
    const { dir } = await skillRepo('agent', text);
    await writeFile(
      join(dir, 'ironheights.threatmodel.yml'),
      [
        'version: 1',
        'skillDirs: [skills]',
        'defaults:',
        `  remoteInstructions: ${remote}`,
        'skills:',
        '  agent:',
        '    path: skills/agent',
        '    network: [x]',
        '    shell: false',
        ...(allow ? ['    remoteInstructions: true'] : []),
        '',
      ].join('\n'),
    );
    return dir;
  }

  it('lists a violated claim without changing the exit code, unless the model denies it', async () => {
    const reportDir = await agentRepo('report');
    const report = capture();
    expect(
      await runThreatModel({
        action: 'check',
        dir: reportDir,
        json: true,
        noGrade: true,
        out: report.out,
      }),
    ).toBe(0);
    const body = JSON.parse(report.lines.join('\n')) as {
      claims: Array<{ claim: string; status: string }>;
      violations: Array<{ kind: string; severity: string }>;
    };
    expect(body.claims.find((c) => c.claim === 'remote-instructions')?.status).toBe('violated');
    expect(body.violations.find((v) => v.kind === 'remote-instructions')?.severity).toBe('info');

    const denyDir = await agentRepo('deny');
    expect(
      await runThreatModel({
        action: 'check',
        dir: denyDir,
        noGrade: true,
        out: capture().out,
      }),
    ).toBe(2);

    const allowed = await agentRepo('deny', true);
    const ok = capture();
    expect(
      await runThreatModel({
        action: 'check',
        dir: allowed,
        json: true,
        noGrade: true,
        out: ok.out,
      }),
    ).toBe(0);
    const allowedBody = JSON.parse(ok.lines.join('\n')) as {
      claims: Array<{ claim: string; status: string }>;
    };
    expect(allowedBody.claims.find((c) => c.claim === 'remote-instructions')?.status).toBe(
      'passed',
    );
  });
});

describe('0.22.0 unenforced claims (muse_bryce)', () => {
  it('flags a dataBoundaries claim as unenforced', async () => {
    const { dir } = await skillRepo('weather', '---\nname: weather\n---\nSay hello.\n');
    await writeFile(
      join(dir, 'ironheights.threatmodel.yml'),
      [
        'version: 1',
        'skillDirs: [skills]',
        'skills:',
        '  weather:',
        '    path: skills/weather',
        '    dataBoundaries: [no-user-data]',
        '    purpose: Read-only notes.',
        '',
      ].join('\n'),
    );
    const c = capture();
    expect(
      await runThreatModel({ action: 'check', dir, json: true, noGrade: true, out: c.out }),
    ).toBe(0);
    const claims = (
      JSON.parse(c.lines.join('\n')) as {
        claims: Array<{ claim: string; unenforced?: boolean; enforcement: string }>;
      }
    ).claims;
    expect(claims.find((claim) => claim.claim === 'dataBoundaries')).toMatchObject({
      unenforced: true,
      enforcement: 'unenforced',
    });
    expect(claims.find((claim) => claim.claim === 'network')?.enforcement).toBe(
      'egress/allowlist in diff',
    );
  });
});

describe('0.22.0 config-key drift (fromthebot)', () => {
  async function approved(config: unknown) {
    const dir = await mkdtemp(join(tmpdir(), 'ih-keys-'));
    const skill = join(dir, 'demo');
    await mkdir(skill);
    await writeFile(join(skill, 'SKILL.md'), '---\nname: demo\ndescription: d\n---\nSay hello.\n');
    await writeFile(join(skill, 'config.json'), JSON.stringify(config));
    const ledger = join(dir, 'approvals.json');
    await runDrift({ action: 'approve', paths: [skill], ledger, out: () => undefined });
    return { skill, ledger };
  }

  async function check(skill: string, ledger: string, config: unknown) {
    await writeFile(join(skill, 'config.json'), JSON.stringify(config));
    const c = capture();
    const code = await runDrift({
      action: 'check',
      paths: [skill],
      ledger,
      json: true,
      out: c.out,
    });
    const body = JSON.parse(c.lines.join('\n')) as {
      decision: string;
      configKeys: Array<{
        key: string;
        change: string;
        severity: string;
        before?: string;
        after?: string;
        reason: string;
      }>;
      changes: Array<{ kind: string }>;
    };
    return { code, body, text: c.lines.join('\n') };
  }

  function key(
    body: {
      configKeys: Array<{
        key: string;
        change: string;
        severity: string;
        before?: string;
        after?: string;
      }>;
    },
    suffix: string,
    change: string,
  ) {
    return body.configKeys.find((item) => item.key.endsWith(suffix) && item.change === change);
  }

  it('warns on a new key and blocks a new allowedHosts key', async () => {
    const added = await approved({ timeout: 30 });
    const warn = await check(added.skill, added.ledger, { timeout: 30, notes: 1 });
    expect(key(warn.body, 'notes', 'config-key-added')).toMatchObject({ severity: 'warn' });
    expect(warn.body.decision).toBe('warn');
    expect(warn.code).toBe(1);
    expect(warn.body.changes.some((c) => c.kind === 'file-changed')).toBe(true);

    const hosts = await approved({ timeout: 30 });
    const block = await check(hosts.skill, hosts.ledger, { timeout: 30, allowedHosts: ['x'] });
    expect(key(block.body, 'allowedHosts', 'config-key-added')).toMatchObject({
      severity: 'block',
    });
    expect(block.body.decision).toBe('block');
    expect(block.code).toBe(2);
  });

  it('reports removed and loosened restrictions, and blocks a wildcard allowlist', async () => {
    const removed = await approved({ timeout: 30, notes: 1 });
    const gone = await check(removed.skill, removed.ledger, { notes: 1 });
    expect(key(gone.body, 'timeout', 'restriction-removed')).toMatchObject({ severity: 'warn' });

    const zero = await approved({ timeout: 30 });
    const loosened = await check(zero.skill, zero.ledger, { timeout: 0 });
    expect(key(loosened.body, 'timeout', 'restriction-loosened')).toMatchObject({
      severity: 'warn',
      before: '30',
      after: '0',
    });

    const list = await approved({ allowlist: ['a'] });
    const wild = await check(list.skill, list.ledger, { allowlist: ['*'] });
    expect(key(wild.body, 'allowlist', 'restriction-loosened')).toMatchObject({
      severity: 'block',
    });
    expect(wild.code).toBe(2);

    const calls = await approved({ maxCalls: 10 });
    const raised = await check(calls.skill, calls.ledger, { maxCalls: 1000 });
    expect(key(raised.body, 'maxCalls', 'restriction-loosened')).toMatchObject({
      severity: 'warn',
      before: '10',
      after: '1000',
    });
    expect(raised.body.decision).toBe('warn');
  });

  it('loads a ledger with no key baseline and never prints a secret value', async () => {
    const { skill, ledger } = await approved({ timeout: 30 });
    const saved = JSON.parse(await readFile(ledger, 'utf8')) as {
      skills: Record<string, { configKeys?: unknown }>;
    };
    for (const rec of Object.values(saved.skills)) delete rec.configKeys;
    await writeFile(ledger, JSON.stringify(saved));
    expect((await readLedger(ledger)).skills[skill]?.configKeys).toBeUndefined();
    const old = await check(skill, ledger, { timeout: 30 });
    expect(old.code).toBe(0);
    expect(old.body.decision).toBe('ok');
    expect(old.body.configKeys.map((item) => item.change)).toContain('config-keys-unrecorded');

    const secret = 'ghp_abcdefghijklmnopqrstuvwxyz123456';
    const leaked = await approved({ timeout: 30 });
    const hidden = await check(leaked.skill, leaked.ledger, { timeout: 30, apiToken: secret });
    expect(hidden.text).not.toContain(secret);
    expect(hidden.text).toContain('<redacted>');
    expect(key(hidden.body, 'apiToken', 'config-key-added')?.severity).toBe('block');

    const mcp = capture();
    const status = await callTool('drift_status', { paths: [skill], ledger });
    const structured = status.structuredContent as { decision: string; configKeys: unknown[] };
    expect(structured.decision).toBe('ok');
    expect(Array.isArray(structured.configKeys)).toBe(true);
    expect(mcp.lines).toEqual([]);
  });
});

describe('0.22.0 posture report (fromthebot, evil_robot_jas)', () => {
  async function repo() {
    const dir = await mkdtemp(join(tmpdir(), 'ih-post-'));
    const quiet = join(dir, 'skills', 'quiet');
    const cred = join(dir, 'skills', 'cred');
    await mkdir(quiet, { recursive: true });
    await mkdir(cred, { recursive: true });
    await writeFile(
      join(quiet, 'SKILL.md'),
      '---\nname: quiet\ndescription: hi\n---\nSay hello.\n',
    );
    await writeFile(
      join(cred, 'SKILL.md'),
      '---\nname: cred\ndescription: d\n---\nRead ~/.ssh/id_rsa\n',
    );
    await writeFile(join(quiet, 'config.json'), JSON.stringify({ timeout: 30 }));
    return { dir, quiet };
  }

  it('leads with worst reach and sorts the inventory by it', async () => {
    const { dir } = await repo();
    const c = capture();
    const html = join(dir, 'posture.html');
    const jsonFile = join(dir, 'posture.json');
    expect(await runReport({ targets: [dir], html, jsonFile, out: c.out })).toBe(0);
    const text = c.lines.join('\n');
    const rows = c.lines.filter((l) => l.includes('@ cfg'));
    expect(rows[0]).toMatch(/^exec or credential read {2}grade \S+ @ cfg [a-f0-9]{8} {2}.+\/cred/);
    expect(rows[1]).toMatch(/^read-only {2}grade \S+ @ cfg [a-f0-9]{8} {2}.+\/quiet/);
    const body = JSON.parse(await readFile(jsonFile, 'utf8')) as {
      skills: Array<{
        skill: string;
        worstReach: { level: string; label: string };
        grade: string;
        configHash: string;
      }>;
      repos: Array<{ configHash: string }>;
    };
    expect(body.skills[0]?.worstReach.level).toBe('exec');
    expect(body.skills[0]?.grade).toBeTruthy();
    expect(body.skills[1]?.worstReach.level).toBe('read-only');
    expect(body.skills[0]?.configHash).toMatch(/^[a-f0-9]{64}$/);
    expect(body.repos[0]?.configHash).toMatch(/^[a-f0-9]{64}$/);
    const page = await readFile(html, 'utf8');
    expect(page).toContain('Worst reach');
    expect(page.indexOf('exec or credential read')).toBeLessThan(page.indexOf('read-only'));
    expect(page).toContain('@ cfg');
    expect(text).toContain('grade');
  });

  it('changes configHash when config changes and flags regraded from --history', async () => {
    const { dir, quiet } = await repo();
    const hist = join(dir, 'hist.jsonl');
    await runReport({ targets: [dir], history: hist, json: true, out: capture().out });
    const first = JSON.parse(await readFile(hist, 'utf8')) as {
      configHashes?: Record<string, string>;
    };
    const quietKey = Object.keys(first.configHashes ?? {}).find((k) => k.endsWith('skills/quiet'));
    const before = quietKey ? first.configHashes?.[quietKey] : undefined;
    expect(before).toMatch(/^[a-f0-9]{64}$/);
    await writeFile(join(quiet, 'config.json'), JSON.stringify({ timeout: 5 }));
    const c = capture();
    const jsonFile = join(dir, 'after.json');
    await runReport({ targets: [dir], history: hist, jsonFile, out: c.out });
    const after = JSON.parse(await readFile(jsonFile, 'utf8')) as {
      skills: Array<{ skill: string; configHash: string; regraded?: boolean }>;
    };
    const quietRow = after.skills.find((s) => s.skill === 'quiet');
    expect(quietRow?.configHash).not.toBe(before);
    expect(quietRow?.regraded).toBe(true);
    expect(c.lines.join('\n')).toContain('config changed since last report; grade recomputed');
  });
});
