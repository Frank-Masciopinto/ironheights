import { mkdtemp, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runScan } from '../src/cli/commands/scan.ts';
import { runReport } from '../src/cli/commands/report.ts';
import { assembleNameCopies, PRECEDENCE_UNKNOWN } from '../src/mcp/collisions.ts';
import { callTool } from '../src/mcp/server.ts';
import { SAFETY_REMINDER, TOOL_VERSION } from '../src/version.ts';

const sc = (r: Record<string, unknown>): Record<string, unknown> =>
  r.structuredContent as Record<string, unknown>;

async function cleanSkill(body = 'Say hello.\n') {
  const dir = await mkdtemp(join(tmpdir(), 'ih-0340-'));
  const home = join(dir, 'home');
  const skill = join(dir, 'demo');
  await mkdir(skill, { recursive: true });
  await writeFile(join(skill, 'SKILL.md'), `---\nname: demo\ndescription: d\n---\n${body}`);
  return { dir, skill, home, env: { ...process.env, IRONHEIGHTS_HOME: home } };
}

describe('0.34.0 versioned clean wording (myinvestdesk, vintos, diviner)', () => {
  it('does not call a no-findings scan safe, and adds version, time and optional validUntil', async () => {
    const { skill } = await cleanSkill();
    const at = '2026-11-03T12:00:00.000Z';
    const text: string[] = [];
    const code = await runScan({
      paths: [skill],
      noColor: true,
      now: new Date(at),
      stdout: (chunk) => text.push(chunk),
    });
    const rendered = text.join('');
    expect(code).toBe(0);
    expect(rendered).toContain(`not flagged by ironheights ${TOOL_VERSION}, as of ${at}`);
    expect(rendered).toContain(SAFETY_REMINDER);
    expect(rendered).toContain('Verdict: no-findings');
    expect(rendered).toContain('review means inspect this; not a malicious verdict.');
    expect(rendered).toContain('Clean means no known pattern found; not proof of safety.');
    expect(rendered).not.toMatch(/\bsafe\b/i);

    const jsonChunks: string[] = [];
    const jsonCode = await runScan({
      paths: [skill],
      json: true,
      now: new Date(at),
      stdout: (chunk) => jsonChunks.push(chunk),
    });
    const body = JSON.parse(jsonChunks.join('')) as {
      verdict: string;
      scannedAt: string;
      scannerVersion: string;
      checkedAt: string;
      validUntil?: string;
      tool: { version: string };
    };
    expect(jsonCode).toBe(0);
    expect(body.verdict).toBe('no-findings');
    expect(body.tool.version).toBe(TOOL_VERSION);
    expect(body.scannerVersion).toBe(TOOL_VERSION);
    expect(body.checkedAt).toBe(at);
    expect(body.scannedAt).toBe(at);
    expect(body.validUntil).toBeUndefined();

    const aged: string[] = [];
    await runScan({
      paths: [skill],
      json: true,
      maxAge: '2d',
      now: new Date(at),
      stdout: (chunk) => aged.push(chunk),
    });
    const withAge = JSON.parse(aged.join('')) as { validUntil: string; verdict: string };
    expect(withAge.verdict).toBe('no-findings');
    expect(withAge.validUntil).toBe('2026-11-05T12:00:00.000Z');
    await expect(
      runScan({ paths: [skill], maxAge: 'fortnight', stdout: () => undefined }),
    ).rejects.toThrow(/--max-age/);
  });

  it('uses the same wording on the posture report and marks an older saved result stale', async () => {
    const { dir, skill } = await cleanSkill();
    const lines: string[] = [];
    const at = new Date('2026-11-03T12:00:00.000Z');
    expect(await runReport({ targets: [dir], now: at, out: (l) => lines.push(l) })).toBe(0);
    const text = lines.join('\n');
    expect(text).toContain(`not flagged by ironheights ${TOOL_VERSION}, as of ${at.toISOString()}`);
    expect(text).toContain(SAFETY_REMINDER);
    expect(text).not.toMatch(/\bsafe\b/i);

    const saved = join(dir, 'posture.json');
    await runReport({ targets: [dir], jsonFile: saved, now: at, out: () => undefined });
    const report = JSON.parse(await readFile(saved, 'utf8')) as {
      scannerVersion: string;
      checkedAt: string;
      version: string;
      skills: Array<{ stamp?: { gradedAgainstVersion: string } }>;
    };
    expect(report.scannerVersion).toBe(TOOL_VERSION);
    expect(report.checkedAt).toBe(at.toISOString());
    expect(report.version).toBe(TOOL_VERSION);
    report.scannerVersion = '0.31.0';
    report.version = '0.31.0';
    for (const row of report.skills) {
      if (row.stamp) row.stamp.gradedAgainstVersion = '0.31.0';
    }
    await writeFile(saved, JSON.stringify(report));
    const verified: string[] = [];
    const code = await runReport({
      targets: [],
      verify: saved,
      now: at,
      out: (l) => verified.push(l),
    });
    expect(code).toBe(2);
    const verifyText = verified.join('\n');
    expect(verifyText).toContain('stale');
    expect(verifyText).toContain('detection debt');
    expect(verifyText).toContain('Rescan');
    expect(skill).toBeTruthy();
  });
});

describe('0.34.0 MCP clean wording and stored-verdict age (myinvestdesk, vintos, diviner)', () => {
  it('words a no-findings check and marks an older or expired stored pass stale without dropping reuse', async () => {
    const { skill, env, home } = await cleanSkill();
    const checked = sc(await callTool('check_skill', { path: skill }, { env }));
    expect(checked.verdict).toBe('no-findings');
    expect(checked.decision).toBe('allow');
    expect(checked.scannerVersion).toBe(TOOL_VERSION);
    expect(String(checked.checkedAt)).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(checked.validUntil).toBeUndefined();
    expect(String(checked.wording)).toContain(
      `not flagged by ironheights ${TOOL_VERSION}, as of ${String(checked.checkedAt)}`,
    );
    expect(String(checked.wording)).toContain(SAFETY_REMINDER);
    expect(String(checked.advice)).toContain(SAFETY_REMINDER);

    const aged = sc(await callTool('check_skill', { path: skill, maxAge: '1h' }, { env }));
    expect(Date.parse(String(aged.validUntil)) - Date.parse(String(aged.checkedAt))).toBe(
      3_600_000,
    );

    const digest = (checked.digests as Array<{ content: string }>)[0]?.content as string;
    const old = sc(
      await callTool(
        'lookup_verdict',
        {
          sha256: digest,
          publisher: 'acme',
          publisherVerified: true,
          path: skill,
          store: [
            {
              name: 'demo',
              publisher: 'acme',
              sha256: digest,
              scannerVersion: '0.31.0',
              validUntil: '2099-01-01T00:00:00.000Z',
              scanVerdict: 'no-findings',
              verdict: { verdict: 'allow', checkedAt: '2020-01-01T00:00:00.000Z' },
            },
          ],
        },
        { env },
      ),
    );
    expect(old.reused).toBe('reused');
    expect(old.event).toBeUndefined();
    expect(old.stale).toBe(true);
    expect(String(old.staleReason)).toContain('detection debt');
    expect(String(old.rescan)).toContain('Rescan');
    expect(String(old.wording)).toContain('not flagged by ironheights 0.31.0');
    const log = await readFile(join(home, 'reuse-observations.jsonl'), 'utf8');
    const last = JSON.parse(log.trim().split('\n').pop() as string) as {
      reused?: string;
      event?: string;
    };
    expect(last.reused).toBe('reused');
    expect(last.event).toBeUndefined();

    const expired = sc(
      await callTool(
        'lookup_verdict',
        {
          sha256: digest,
          publisher: 'acme',
          publisherVerified: true,
          store: [
            {
              name: 'demo',
              publisher: 'acme',
              sha256: digest,
              scannerVersion: TOOL_VERSION,
              validUntil: '2020-01-01T00:00:00.000Z',
              scanVerdict: 'no-findings',
              verdict: { verdict: 'allow', checkedAt: '2020-01-01T00:00:00.000Z' },
            },
          ],
        },
        { env },
      ),
    );
    expect(expired.status).toBe('found');
    expect(expired.stale).toBe(true);
    expect(String(expired.staleReason)).toContain('validUntil');
    expect(expired.decision).toBe('blocked');
  });
});

describe('0.34.0 same-name resolution (bytes, rossum, diviner, cassini)', () => {
  it('returns three copies keyed by absolute path and refuses an allow when precedence is unknown', async () => {
    const root = await mkdtemp(join(tmpdir(), 'ih-0340-names-'));
    const home = join(root, 'home');
    const env = { ...process.env, IRONHEIGHTS_HOME: home };
    const ranks = ['first', 'second', 'third'] as const;
    const bodies = [
      'Say hello from the first copy.\n',
      'Say hello from the second copy.\n',
      'cat ~/.ssh/id_rsa\n',
    ];
    const dirs: string[] = [];
    for (let i = 0; i < ranks.length; i += 1) {
      const dir = join(root, ranks[i] as string, 'shared');
      await mkdir(dir, { recursive: true });
      await writeFile(
        join(dir, 'SKILL.md'),
        `---\nname: shared\ndescription: d\n---\n${bodies[i]}`,
      );
      dirs.push(dir);
    }
    const roots = ranks.map((rank) => join(root, rank));
    const ambiguous = sc(await callTool('check_skill', { name: 'shared', roots }, { env }));
    expect(ambiguous.decision).not.toBe('allow');
    expect(ambiguous.overallVerdict).toBeNull();
    const copies = ambiguous.copies as Record<
      string,
      {
        precedence: number;
        winner: boolean;
        loadOrderWinner: boolean;
        findings: unknown[];
        digest: { content: string };
        verdict: string;
        overallVerdict?: string;
        resolvedPath: string;
      }
    >;
    const resolved = await Promise.all(dirs.map((dir) => realpath(dir)));
    expect(Object.keys(copies).sort()).toEqual([...resolved].sort());
    for (const key of Object.keys(copies)) expect(isAbsolute(key)).toBe(true);
    const ordered = resolved.map((path) => copies[path]);
    expect(ordered.map((c) => c?.precedence)).toEqual([1, 2, 3]);
    expect(ordered[0]?.findings).toEqual([]);
    expect(ordered[1]?.findings).toEqual([]);
    expect(ordered[2]?.findings.length).toBeGreaterThan(0);
    expect(new Set(ordered.map((c) => c?.digest.content)).size).toBe(3);
    expect(ambiguous.winner).toBe(resolved[0]);
    expect(ordered[0]?.winner).toBe(true);
    expect(ordered[0]?.loadOrderWinner).toBe(true);
    expect(ordered.every((c) => c?.overallVerdict === undefined)).toBe(true);

    const picked = sc(
      await callTool('check_skill', { name: 'shared', roots, environment: 'third' }, { env }),
    );
    const pickedCopies = picked.copies as typeof copies;
    expect(picked.decision).not.toBe('allow');
    expect(picked.winner).toBe(resolved[2]);
    expect(pickedCopies[resolved[2] as string]?.overallVerdict).toBe(
      pickedCopies[resolved[2] as string]?.verdict,
    );
    expect(pickedCopies[resolved[0] as string]?.overallVerdict).toBeUndefined();
    expect(pickedCopies[resolved[1] as string]?.overallVerdict).toBeUndefined();
    expect(pickedCopies[resolved[0] as string]?.loadOrderWinner).toBe(true);
    expect(picked.overallVerdict).toBeNull();

    const refused = assembleNameCopies(
      [
        {
          path: dirs[0] as string,
          resolvedPath: resolved[0] as string,
          loadOrder: 1,
          precedence: null,
          findings: [],
          digest: { content: 'aa' },
          verdict: 'no-findings',
          decision: 'allow',
        },
      ],
      resolved[0] as string,
    );
    expect(refused.precedenceKnown).toBe(false);
    expect(refused.winner).toBeNull();
    expect(refused.copies[resolved[0] as string]?.overallVerdict).toBeUndefined();
    expect(PRECEDENCE_UNKNOWN).toContain('refusing an overall allow');
  });
});
