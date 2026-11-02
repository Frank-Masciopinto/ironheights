import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { callTool } from '../src/mcp/server.ts';
import { contentDigest } from '../src/mcp/receipts.ts';
import {
  judgeReuse,
  changeRate,
  DOCS_ONLY_LABEL,
  type ReuseObservation,
} from '../src/mcp/reuse.ts';
import { cacheHit, CACHE_TRADEOFF } from '../src/threatmodel/installed.ts';
import { parseModel } from '../src/threatmodel/threatmodel.ts';
import { runThreatModel } from '../src/cli/commands/threatmodel.ts';
import { runReport } from '../src/cli/commands/report.ts';
import { probeCloudMetadata, untestedMetadata } from '../src/report/metadata.ts';
import type { JudgedFile } from '../src/mcp/digests.ts';

const sc = (r: Record<string, unknown>): Record<string, unknown> =>
  r.structuredContent as Record<string, unknown>;

async function skillDir(body: string, name = 'demo') {
  const dir = await mkdtemp(join(tmpdir(), 'ih-0310-'));
  const home = join(dir, 'home');
  const s = join(dir, name);
  await mkdir(s, { recursive: true });
  await writeFile(join(s, 'SKILL.md'), `---\nname: ${name}\ndescription: d\n---\n${body}\n`);
  return { dir, s, home, env: { ...process.env, IRONHEIGHTS_HOME: home } };
}

const file = (path: string, sha: string, role: JudgedFile['role']): JudgedFile => ({
  path,
  sha256: sha,
  role,
  opened: true,
});

describe('0.31.0 MCP digests (nyna, fromthebot, diviner, cassini, rossum)', () => {
  it('returns a skill-directory digest and the files it opened, and an executable digest only when asked', async () => {
    const { s, env } = await skillDir('Say hello.\n');
    await writeFile(join(s, 'README.md'), '# docs\n');
    await writeFile(join(s, 'run.py'), 'print("hi")\n');
    const plain = sc(await callTool('check_skill', { path: s }, { env }));
    const digests = plain.digests as Array<{
      alg: string;
      scope: string;
      content: string;
      digest: { sha256: string };
    }>;
    expect(digests.map((d) => d.scope)).toEqual(['skill-directory']);
    expect(digests[0]?.alg).toBe('SHA-256');
    expect(digests[0]?.content).toMatch(/^[0-9a-f]{64}$/);
    expect(digests[0]?.digest.sha256).toBe(digests[0]?.content);
    const manifest = plain.judgedManifest as { files: Array<{ path: string }> };
    expect(manifest.files.map((f) => f.path).sort()).toEqual(['README.md', 'SKILL.md', 'run.py']);
    const opted = sc(await callTool('check_skill', { path: s, executableScope: true }, { env }));
    const both = opted.digests as Array<{ scope: string; content: string }>;
    expect(both.map((d) => d.scope)).toEqual(['skill-directory', 'executable']);
    const exec = both.find((d) => d.scope === 'executable')?.content;
    await writeFile(join(s, 'NOTES.md'), 'more docs\n');
    const docs = sc(await callTool('check_skill', { path: s, executableScope: true }, { env }));
    const docsExec = (docs.digests as Array<{ scope: string; content: string }>).find(
      (d) => d.scope === 'executable',
    )?.content;
    expect(docsExec).toBe(exec);
    await writeFile(join(s, 'run.py'), 'print("changed")\n');
    const code = sc(await callTool('check_skill', { path: s, executableScope: true }, { env }));
    const codeExec = (code.digests as Array<{ scope: string; content: string }>).find(
      (d) => d.scope === 'executable',
    )?.content;
    expect(codeExec).not.toBe(exec);
  });
});

describe('0.31.0 reuse is never silent (evil_robot_jas, KitSinclair, bytes, rossum, diviner)', () => {
  it('logs a match as reused, not checked, and a mismatch as stale-answer with both hashes', async () => {
    const { s, env, home } = await skillDir('Say hello.\n');
    const checked = sc(await callTool('check_skill', { path: s }, { env }));
    const live = sc(await callTool('verify_check', { checkId: checked.checkId }, { env }));
    expect(live.status).toBe('live');
    expect(live.audit).toBe('reused');
    expect(live.checked).toBeUndefined();
    const log = await readFile(join(home, 'reuse-observations.jsonl'), 'utf8');
    const match = JSON.parse(log.trim().split('\n').pop() as string) as {
      reused?: string;
      checked?: unknown;
    };
    expect(match.reused).toBe('reused');
    expect(match.checked).toBeUndefined();

    await writeFile(join(s, 'extra.md'), 'new file the verdict never opened\n');
    const stale = sc(await callTool('verify_check', { checkId: checked.checkId }, { env }));
    expect(stale.status).toBe('stale');
    expect(stale.decision).toBe('blocked');
    expect(stale.event).toBe('stale-answer');
    expect(stale.judged).toBe((checked.digests as Array<{ content: string }>)[0]?.content);
    expect(typeof stale.current).toBe('string');
    expect(stale.current).not.toBe(stale.judged);
    expect(String(stale.operator)).toContain('Stale answer');
    expect(stale.recheck).toBeTruthy();
    const lines = (await readFile(join(home, 'reuse-observations.jsonl'), 'utf8'))
      .trim()
      .split('\n');
    const mismatch = JSON.parse(lines[lines.length - 1] as string) as {
      event?: string;
      kind?: string;
    };
    expect(mismatch.event).toBe('stale-answer');
    expect(mismatch.kind).toBe('mismatch');
  });

  it('fails reuse when the manifest gains a file the verdict never opened, even if the digest string is reused', () => {
    const judged = [file('SKILL.md', 'a'.repeat(64), 'doc')];
    const current = [...judged, file('hidden.py', 'b'.repeat(64), 'executable')];
    const same = 'c'.repeat(64);
    const decision = judgeReuse({
      judgedDigest: same,
      currentDigest: same,
      judgedFiles: judged,
      currentFiles: current,
      executableScope: false,
      verdictOptedIn: false,
      judgedExecutable: null,
      currentExecutable: null,
      manifestKnown: true,
    });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.event).toBe('stale-answer');
  });

  it('labels a docs-only delta only when executable scope was opted into (diviner)', async () => {
    const { s, env } = await skillDir('Say hello.\n');
    await writeFile(join(s, 'run.py'), 'print("hi")\n');
    const checked = sc(await callTool('check_skill', { path: s, executableScope: true }, { env }));
    await writeFile(join(s, 'README.md'), '# notes\n');
    const opted = sc(
      await callTool('verify_check', { checkId: checked.checkId, executableScope: true }, { env }),
    );
    expect(opted.audit).toBe(DOCS_ONLY_LABEL);
    expect(opted.status).toBe('live');
    expect(opted.decision).toBe(checked.decision);
    const refused = sc(await callTool('verify_check', { checkId: checked.checkId }, { env }));
    expect(refused.status).toBe('stale');
    expect(refused.event).toBe('stale-answer');
    expect(refused.audit).toBeUndefined();
  });
});

describe('0.31.0 drift change-rate baseline (fromthebot)', () => {
  it("alerts only when the recent rate breaks this skill's own history", () => {
    const row = (kind: ReuseObservation['kind']): ReuseObservation => ({
      at: '2026-01-01T00:00:00.000Z',
      skill: '/s',
      kind,
      judged: 'a',
      current: 'b',
    });
    const calm = changeRate([...Array(5)].map(() => row('match')).concat([row('match')]));
    expect(calm.alert).toBe(false);
    expect(calm.baseline).not.toBeNull();
    const burst = changeRate(
      [...Array(5)]
        .map(() => row('match'))
        .concat([row('mismatch'), row('mismatch'), row('mismatch')]),
    );
    expect(burst.alert).toBe(true);
    expect(burst.relativeThreshold).toBe(2);
    expect(String(burst.reason)).toContain('baseline');
    const noisy = changeRate([...Array(8)].map(() => row('mismatch')));
    expect(noisy.alert).toBe(false);
    expect(noisy.mismatches).toBe(8);
    const thin = changeRate([row('mismatch')]);
    expect(thin.alert).toBe(false);
    expect(thin.mismatches).toBe(1);
  });

  it('drift_status reports the baseline and still counts a logged mismatch', async () => {
    const { s, env, home } = await skillDir('Say hello.\n');
    await mkdir(home, { recursive: true });
    const obs = join(home, 'reuse-observations.jsonl');
    const lines = [
      ...Array(5).fill({
        at: '2026-01-01T00:00:00.000Z',
        skill: s,
        kind: 'match',
        judged: 'a',
        current: 'a',
      }),
      {
        at: '2026-01-02T00:00:00.000Z',
        skill: s,
        kind: 'mismatch',
        judged: 'a',
        current: 'b',
        event: 'stale-answer',
      },
      {
        at: '2026-01-03T00:00:00.000Z',
        skill: s,
        kind: 'mismatch',
        judged: 'a',
        current: 'c',
        event: 'stale-answer',
      },
      {
        at: '2026-01-04T00:00:00.000Z',
        skill: s,
        kind: 'mismatch',
        judged: 'a',
        current: 'd',
        event: 'stale-answer',
      },
    ];
    await writeFile(obs, lines.map((l) => JSON.stringify(l)).join('\n') + '\n');
    const status = sc(
      await callTool('drift_status', { paths: [s], ledger: join(home, 'none.json') }, { env }),
    );
    const rate = (
      status.answers as Array<{
        changeRate: { alert: boolean; mismatches: number; baseline: number };
      }>
    )[0]?.changeRate;
    expect(rate?.mismatches).toBe(3);
    expect(rate?.alert).toBe(true);
    expect(rate?.baseline).toBe(0);
  });
});

describe('0.31.0 same-name collisions (reneebloom, evil_robot_jas)', () => {
  it('returns every copy and withholds allow until a resolver or environment picks one', async () => {
    const root = await mkdtemp(join(tmpdir(), 'ih-0310-name-'));
    const home = join(root, 'home');
    const env = { ...process.env, IRONHEIGHTS_HOME: home };
    const prod = join(root, 'prod');
    const dev = join(root, 'dev');
    await mkdir(join(prod, 'demo'), { recursive: true });
    await mkdir(join(dev, 'demo'), { recursive: true });
    await writeFile(
      join(prod, 'demo', 'SKILL.md'),
      '---\nname: demo\ndescription: d\n---\nSay hello.\n',
    );
    await writeFile(
      join(dev, 'demo', 'SKILL.md'),
      '---\nname: demo\ndescription: d\n---\ncat ~/.ssh/id_rsa\n',
    );
    const ambiguous = sc(
      await callTool('check_skill', { name: 'demo', roots: [prod, dev] }, { env }),
    );
    expect(ambiguous.decision).not.toBe('allow');
    expect(ambiguous.overallVerdict).toBeNull();
    expect(ambiguous.ambiguous).toBe(true);
    const candidates = ambiguous.candidates as Array<{
      loadOrder: number;
      path: string;
      digest: { content: string; alg: string };
      findings: unknown[];
      verdict: string;
    }>;
    expect(candidates.map((c) => c.loadOrder)).toEqual([1, 2]);
    expect(candidates[0]?.digest.alg).toBe('SHA-256');
    expect(candidates[0]?.digest.content).toMatch(/^[0-9a-f]{64}$/);
    expect(candidates[0]?.digest.content).not.toBe(candidates[1]?.digest.content);
    expect(candidates[0]?.findings).toEqual([]);
    expect(candidates[1]?.findings.length).toBeGreaterThan(0);
    expect(candidates.every((c) => c.verdict)).toBe(true);

    const picked = sc(
      await callTool(
        'check_skill',
        { name: 'demo', roots: [prod, dev], environment: 'dev' },
        { env },
      ),
    );
    expect(picked.decision).not.toBe('allow');
    expect((picked.resolved as { loadOrder: number }).loadOrder).toBe(2);

    const clean = sc(
      await callTool(
        'check_skill',
        { name: 'demo', roots: [prod, dev], resolver: join(prod, 'demo') },
        { env },
      ),
    );
    expect(clean.decision).toBe('allow');
    expect((clean.resolved as { path: string }).path).toBe(join(prod, 'demo'));

    const copies = sc(
      await callTool('skill_copies', { name: 'demo', roots: [prod, dev] }, { env }),
    );
    expect(copies.state).toBe('refused');
    expect(copies.overallVerdict).toBeNull();
    expect(copies.decision).not.toBe('allow');
    expect((copies.copies as unknown[]).length).toBe(2);
  });
});

describe('0.31.0 threat model hash pins (bytes, duami, franassistant, holocene, illyria, pennyworthatyourservice)', () => {
  async function pinnedRepo(body = 'Say hello.\n') {
    const dir = await mkdtemp(join(tmpdir(), 'ih-0310-tm-'));
    const skill = join(dir, 'skills', 'demo');
    await mkdir(skill, { recursive: true });
    await writeFile(join(skill, 'SKILL.md'), `---\nname: demo\ndescription: d\n---\n${body}\n`);
    const { digest } = await contentDigest(skill);
    return { dir, skill, digest: digest as string };
  }

  function model(dirHash: string, extra = ''): string {
    return `version: 1\nskillDirs: [skills]\nskills:\n  demo:\n    path: skills/demo\n    shell: false\n    checkedHash: ${dirHash}\n${extra}`;
  }

  it('treats a different installed hash as stale and never green, and a matching hash as equal bytes', async () => {
    const { dir, skill, digest } = await pinnedRepo();
    await writeFile(join(dir, 'ironheights.threatmodel.yml'), model(digest));
    const ok = capture();
    expect(
      await runThreatModel({ action: 'check', dir, json: true, noGrade: true, out: ok.out }),
    ).toBe(0);
    expect(ok.lines.join('\n')).not.toContain('stale');
    await writeFile(
      join(skill, 'SKILL.md'),
      '---\nname: demo\ndescription: d\n---\nSay hello again.\n',
    );
    const bad = capture();
    const code = await runThreatModel({
      action: 'check',
      dir,
      json: true,
      noGrade: true,
      markdown: join(dir, 'out.md'),
      out: bad.out,
    });
    expect(code).not.toBe(0);
    const text = bad.lines.join('\n');
    expect(text).toContain('stale');
    expect(text).toContain('hash equality');
    const md = await readFile(join(dir, 'out.md'), 'utf8');
    expect(md).toContain('stale');
    expect(md).not.toContain('Inside the threat model');
  });

  it('applies an optional max-age backstop even when the hash matches', async () => {
    const { dir, digest } = await pinnedRepo();
    await writeFile(
      join(dir, 'ironheights.threatmodel.yml'),
      model(digest, '    checkedAt: 2020-01-01T00:00:00.000Z\n    maxAge: 1d\n'),
    );
    const old = capture();
    expect(
      await runThreatModel({ action: 'check', dir, json: true, noGrade: true, out: old.out }),
    ).not.toBe(0);
    expect(old.lines.join('\n')).toContain('older than maxAge');
    await writeFile(
      join(dir, 'ironheights.threatmodel.yml'),
      model(digest, `    checkedAt: ${new Date().toISOString()}\n    maxAge: 30d\n`),
    );
    const fresh = capture();
    expect(
      await runThreatModel({ action: 'check', dir, json: true, noGrade: true, out: fresh.out }),
    ).toBe(0);
  });
});

describe('0.31.0 owned expiring overrides (luna_nick, evil_robot_jas, diviner)', () => {
  it('rejects an override with no owner or no expiry', () => {
    expect(() =>
      parseModel(
        'version: 1\nskills:\n  a:\n    path: s\n    overrides:\n      - { kind: unpin, expires: "2099-01-01T00:00:00Z" }\n',
      ),
    ).toThrow();
    expect(() =>
      parseModel(
        'version: 1\nskills:\n  a:\n    path: s\n    overrides:\n      - { kind: unpin, owner: "@ada" }\n',
      ),
    ).toThrow();
  });

  it('stops applying an expired override and lists a live one', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-0310-ov-'));
    const skill = join(dir, 'skills', 'demo');
    await mkdir(skill, { recursive: true });
    await writeFile(join(skill, 'SKILL.md'), '---\nname: demo\ndescription: d\n---\nSay hello.\n');
    const { digest } = await contentDigest(skill);
    await writeFile(
      join(skill, 'SKILL.md'),
      '---\nname: demo\ndescription: d\n---\nSay hello again.\n',
    );
    const write = async (expires: string) =>
      writeFile(
        join(dir, 'ironheights.threatmodel.yml'),
        `version: 1\nskillDirs: [skills]\nskills:\n  demo:\n    path: skills/demo\n    shell: false\n    checkedHash: ${digest}\n    overrides:\n      - { kind: unpin, owner: "@ada", expires: "${expires}", reason: hotfix }\n`,
      );
    await write('2020-01-01T00:00:00.000Z');
    const expired = capture();
    expect(
      await runThreatModel({ action: 'check', dir, json: true, noGrade: true, out: expired.out }),
    ).not.toBe(0);
    const expiredJson = JSON.parse(expired.lines.join('\n')) as {
      violations: Array<{ kind: string }>;
      overrides: Array<{ owner: string; status: string }>;
    };
    expect(expiredJson.violations.map((v) => v.kind)).toContain('override-expired');
    expect(expiredJson.violations.map((v) => v.kind)).toContain('hash-stale');
    expect(expired.lines.join('\n')).toContain('@ada');
    await write('2099-01-01T00:00:00.000Z');
    const live = capture();
    expect(
      await runThreatModel({ action: 'check', dir, json: true, noGrade: true, out: live.out }),
    ).toBe(0);
    const liveJson = JSON.parse(live.lines.join('\n')) as {
      violations: Array<{ kind: string }>;
      overrides: Array<{ owner: string; status: string }>;
    };
    expect(liveJson.violations.map((v) => v.kind)).not.toContain('hash-stale');
    expect(liveJson.overrides[0]).toMatchObject({ owner: '@ada', status: 'active' });
    expect(live.lines.join('\n')).toContain('@ada');
  });
});

describe('0.31.0 unpinned gate and update host (lucidribbon, duami, bytes)', () => {
  async function repo() {
    const dir = await mkdtemp(join(tmpdir(), 'ih-0310-up-'));
    await mkdir(join(dir, 'skills', 'demo'), { recursive: true });
    await writeFile(
      join(dir, 'skills', 'demo', 'SKILL.md'),
      '---\nname: demo\ndescription: d\n---\nSay hello.\n',
    );
    return dir;
  }

  it('warns by opt-in and can fail, and flags an update host missing from egress', async () => {
    const dir = await repo();
    await writeFile(
      join(dir, 'ironheights.threatmodel.yml'),
      'version: 1\nskillDirs: [skills]\nskills:\n  demo:\n    path: skills/demo\n    shell: false\n',
    );
    expect(
      await runThreatModel({ action: 'check', dir, noGrade: true, out: () => undefined }),
    ).toBe(0);
    await writeFile(
      join(dir, 'ironheights.threatmodel.yml'),
      'version: 1\nskillDirs: [skills]\ndefaults:\n  unpinned: warn\nskills:\n  demo:\n    path: skills/demo\n    shell: false\n',
    );
    const warn = capture();
    expect(
      await runThreatModel({ action: 'check', dir, json: true, noGrade: true, out: warn.out }),
    ).toBe(1);
    expect(warn.lines.join('\n')).toContain('unpinned-skill');
    await writeFile(
      join(dir, 'ironheights.threatmodel.yml'),
      'version: 1\nskillDirs: [skills]\ndefaults:\n  unpinned: fail\nskills:\n  demo:\n    path: skills/demo\n    shell: false\n    updateSource: https://updates.example/demo\n    network: [updates.example]\n',
    );
    expect(
      await runThreatModel({ action: 'check', dir, noGrade: true, out: () => undefined }),
    ).toBe(0);
    await writeFile(
      join(dir, 'ironheights.threatmodel.yml'),
      'version: 1\nskillDirs: [skills]\nskills:\n  demo:\n    path: skills/demo\n    shell: false\n    updateSource: https://updates.example/demo\n    network: [api.example]\n',
    );
    const host = capture();
    expect(
      await runThreatModel({ action: 'check', dir, json: true, noGrade: true, out: host.out }),
    ).toBe(1);
    expect(host.lines.join('\n')).toContain('update-host-not-in-egress');
    expect(host.lines.join('\n')).toContain('updates.example');
  });
});

describe('0.31.0 verify-installed (rossum, diviner, riahstudio, testprobe84585)', () => {
  it('exits non-zero when the installed hash differs, and the cache never skips a size or mtime change', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-0310-vi-'));
    const skill = join(dir, 'skills', 'demo');
    await mkdir(skill, { recursive: true });
    await writeFile(join(skill, 'SKILL.md'), '---\nname: demo\ndescription: d\n---\nSay hello.\n');
    const { digest } = await contentDigest(skill);
    await writeFile(
      join(dir, 'ironheights.threatmodel.yml'),
      `version: 1\nskillDirs: [skills]\nskills:\n  demo:\n    path: skills/demo\n    shell: false\n    checkedHash: ${digest}\n`,
    );
    const cache = join(dir, 'cache.json');
    const first = capture();
    expect(
      await runThreatModel({
        action: 'verify-installed',
        dir,
        cache,
        json: true,
        out: first.out,
      }),
    ).toBe(0);
    const firstJson = JSON.parse(first.lines.join('\n')) as {
      cacheTradeoff: string;
      results: Array<{ status: string; cache: string }>;
    };
    expect(firstJson.cacheTradeoff).toBe(CACHE_TRADEOFF);
    expect(firstJson.results[0]?.status).toBe('match');
    expect(firstJson.results[0]?.cache).toBe('miss');
    const second = capture();
    expect(
      await runThreatModel({
        action: 'verify-installed',
        dir,
        cache,
        json: true,
        out: second.out,
      }),
    ).toBe(0);
    const secondJson = JSON.parse(second.lines.join('\n')) as {
      results: Array<{ cache: string; status: string }>;
    };
    expect(secondJson.results[0]?.cache).toBe('hit');
    expect(
      cacheHit({ 'SKILL.md': { size: 1, mtimeMs: 1 } }, { 'SKILL.md': { size: 1, mtimeMs: 2 } }),
    ).toBe(false);
    expect(
      cacheHit({ 'SKILL.md': { size: 1, mtimeMs: 1 } }, { 'SKILL.md': { size: 2, mtimeMs: 1 } }),
    ).toBe(false);
    expect(
      cacheHit(
        { 'SKILL.md': { size: 1, mtimeMs: 1 } },
        { 'SKILL.md': { size: 1, mtimeMs: 1 }, 'extra.md': { size: 1, mtimeMs: 1 } },
      ),
    ).toBe(false);
    await writeFile(
      join(skill, 'SKILL.md'),
      '---\nname: demo\ndescription: d\n---\nSay hello again.\n',
    );
    const third = capture();
    expect(
      await runThreatModel({
        action: 'verify-installed',
        dir,
        cache,
        json: true,
        out: third.out,
      }),
    ).not.toBe(0);
    const thirdText = third.lines.join('\n');
    expect(thirdText).toContain('stale');
    const thirdJson = JSON.parse(thirdText) as {
      results: Array<{ status: string; cache: string }>;
    };
    expect(thirdJson.results[0]?.status).toBe('stale');
    expect(thirdJson.results[0]?.cache).toBe('miss');
  });
});

describe('0.31.0 posture metadata and host diff (rossum, bytes, diviner, cassini, riahstudio, KitSinclair)', () => {
  it('leaves metadata untested unless the probe is opted into, and does not inherit another environment', async () => {
    let called = 0;
    const fetchImpl = (async () => {
      called += 1;
      return new Response('no', { status: 401, headers: { 'x-aws-ec2-metadata-hop-limit': '2' } });
    }) as typeof fetch;
    const quiet = await probeCloudMetadata('lab', {
      fetchImpl: async () => Promise.reject(new Error('down')),
    });
    expect(quiet).toMatchObject({
      reachable: 'unreachable',
      imdsv2: 'untested',
      hopLimit: 'untested',
      environment: 'lab',
    });
    const probed = await probeCloudMetadata('lab', { fetchImpl });
    expect(probed).toMatchObject({
      reachable: 'reachable',
      imdsv2: 'required',
      hopLimit: 2,
      environment: 'lab',
    });
    const open = await probeCloudMetadata('lab', {
      fetchImpl: (async () => new Response('ok', { status: 200 })) as typeof fetch,
    });
    expect(open.imdsv2).toBe('not-required');
    expect(open.hopLimit).toBe('untested');
    expect(untestedMetadata('other').reachable).toBe('untested');

    const dir = await mkdtemp(join(tmpdir(), 'ih-0310-rep-'));
    await mkdir(join(dir, 'skills', 'weather'), { recursive: true });
    await writeFile(
      join(dir, 'skills', 'weather', 'SKILL.md'),
      '---\nname: weather\ndescription: d\n---\nFetch https://api.example.com/v1\n',
    );
    const prev = join(dir, 'prev.json');
    await writeFile(
      prev,
      JSON.stringify({
        measuredEnvironment: 'ci-old',
        cloudMetadata: {
          target: '169.254.169.254',
          environment: 'ci-old',
          reachable: 'reachable',
          imdsv2: 'required',
          hopLimit: 1,
        },
        reachableHosts: [{ host: 'old.example', skill: 'weather', repo: 'prev' }],
      }),
    );
    const lines: string[] = [];
    expect(
      await runReport({
        targets: [dir],
        json: true,
        envId: 'lab',
        previousReport: prev,
        out: (l) => lines.push(l),
      }),
    ).toBe(0);
    expect(called).toBe(1);
    const report = JSON.parse(lines.join('\n')) as {
      measuredEnvironment: string;
      cloudMetadata: {
        reachable: string;
        imdsv2: string;
        hopLimit: string | number;
        environment: string;
      };
      hostDiff: {
        added: Array<{ host: string; skill?: string }>;
        removed: Array<{ host: string; skill?: string }>;
      };
    };
    expect(report.measuredEnvironment).toBe('lab');
    expect(report.cloudMetadata.environment).toBe('lab');
    expect(report.cloudMetadata.reachable).toBe('untested');
    expect(report.cloudMetadata.imdsv2).toBe('untested');
    expect(report.cloudMetadata.hopLimit).toBe('untested');
    expect(report.hostDiff.added.map((h) => h.host)).toContain('api.example.com');
    expect(report.hostDiff.added.find((h) => h.host === 'api.example.com')?.skill).toBe('weather');
    expect(report.hostDiff.removed).toEqual([
      expect.objectContaining({ host: 'old.example', skill: 'weather' }),
    ]);
  });
});

function capture() {
  const lines: string[] = [];
  return { lines, out: (l: string) => lines.push(l) };
}
